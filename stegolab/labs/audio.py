"""Bounded FFT/STFT analysis; audio decoding runs only inside the worker."""
import io
import shutil
import wave

import numpy as np
from PIL import Image

from ..analysis.tools import run_command

SAMPLE_RATE = 22050
MAX_SECONDS = 30


def read_pcm(path):
    with wave.open(str(path), 'rb') as stream:
        rate, channels, width = stream.getframerate(), stream.getnchannels(), stream.getsampwidth()
        if stream.getcomptype() != 'NONE' or width not in {1, 2, 3, 4} or channels not in {1, 2}:
            raise ValueError('Native WAV analysis supports uncompressed mono/stereo PCM with 8/16/24/32-bit samples')
        raw = stream.readframes(min(stream.getnframes(), rate * MAX_SECONDS))
        if width == 1: samples = (np.frombuffer(raw, np.uint8).astype(np.float32) - 128) / 128
        elif width == 2: samples = np.frombuffer(raw, '<i2').astype(np.float32) / 32768
        elif width == 4: samples = np.frombuffer(raw, '<i4').astype(np.float32) / 2147483648
        else:
            octets = np.frombuffer(raw, np.uint8).reshape(-1, 3).astype(np.int32)
            values = octets[:, 0] | octets[:, 1] << 8 | octets[:, 2] << 16
            values = (values ^ 0x800000) - 0x800000
            samples = values.astype(np.float32) / 8388608
        samples = samples.reshape(-1, channels)
        if rate > SAMPLE_RATE:
            # Deterministic linear resampling for inspection previews only.
            count = round(len(samples) * SAMPLE_RATE / rate)
            positions = np.arange(count) * rate / SAMPLE_RATE
            samples = np.stack([np.interp(positions, np.arange(len(samples)), samples[:, c]) for c in range(channels)], axis=1).astype(np.float32)
            rate = SAMPLE_RATE
        return samples, rate


def wav_bytes(samples, rate):
    buffer = io.BytesIO()
    with wave.open(buffer, 'wb') as stream:
        stream.setnchannels(1 if samples.ndim == 1 else samples.shape[1])
        stream.setsampwidth(2)
        stream.setframerate(rate)
        stream.writeframes((np.clip(samples, -1, 1) * 32767).astype('<i2').tobytes())
    return buffer.getvalue()


def analyze_audio(analysis):
    from ..analysis.engine import stage, finding
    kind = analysis.report['file']['format']
    if kind not in {'wav', 'mp3', 'ogg', 'flac', 'mp4', 'webm', 'avi', 'matroska', 'au'}:
        return stage('audio_lab', status='skipped', reason='Not a supported audio/media container')
    decoder = shutil.which('ffmpeg')
    temporary = analysis.root / 'audio-decoded.wav'
    errors = []
    if decoder:
        result = run_command([decoder, '-v', 'error', '-nostdin', '-threads', '1', '-protocol_whitelist', 'file,pipe',
                              '-i', str(analysis.original), '-vn', '-t', str(MAX_SECONDS), '-ac', '2', '-ar', str(SAMPLE_RATE),
                              '-c:a', 'pcm_s16le', '-y', str(temporary)], analysis.root, max_output=4*1024**2)
        if result['status'] != 'completed':
            temporary.unlink(missing_ok=True)
            return stage('audio_lab', errors=[result['stderr'][:2000] or 'FFmpeg could not decode audio'], status=result['status'])
        path = temporary
    elif kind == 'wav': path = analysis.original
    else: return stage('audio_lab', errors=['FFmpeg is unavailable'], status='unavailable')
    try: samples, rate = read_pcm(path)
    finally: temporary.unlink(missing_ok=True)
    if len(samples) < 32: raise ValueError('Audio contains too few decoded samples')
    playback = analysis.artifact('audio-preview.wav', wav_bytes(samples, rate), 'audio/wav', 'preview', max_bytes=4*1024**2)
    playback.update(preview=True, preview_type='audio', method=f'Normalized PCM preview; first {MAX_SECONDS}s maximum')
    data = {'sample_rate': rate, 'channels': samples.shape[1], 'duration': round(len(samples)/rate, 6),
            'preview_artifact_id': playback['id'], 'max_seconds': MAX_SECONDS, 'channel_data': [],
            'window': 1024, 'hop': 256, 'dynamic_range_db': [-90, 0],
            'explanation': 'Spectrogram uses a Hann-window STFT; frequency axis is linear. Preview audio may be resampled.'}
    artifacts = [playback]
    for channel in range(samples.shape[1]):
        signal = samples[:, channel]
        segment = analysis.artifact(f'channel-{channel+1}.wav', wav_bytes(signal, rate), 'audio/wav', 'preview', max_bytes=2*1024**2)
        segment.update(preview=True, preview_type='audio')
        artifacts.append(segment)
        chunks = np.array_split(signal, min(1200, len(signal)))
        waveform = [[round(float(chunk.min()), 5), round(float(chunk.max()), 5)] for chunk in chunks]
        padded = np.pad(signal, (0, max(0, 1024-len(signal))))
        windows = np.lib.stride_tricks.sliding_window_view(padded, 1024)[::256]
        if len(windows) > 1200: windows = windows[np.linspace(0, len(windows)-1, 1200, dtype=int)]
        spectrum = np.abs(np.fft.rfft(windows * np.hanning(1024), axis=1)) / 512
        db = np.maximum(-90, 20*np.log10(np.maximum(spectrum, 1e-8)))
        normalized = np.clip((db + 90) / 90, 0, 1)
        pixels = np.stack([normalized**.7 * 255, normalized**1.8 * 240, normalized**3 * 180], axis=-1).astype(np.uint8)
        picture = Image.fromarray(pixels.transpose(1, 0, 2)[::-1])
        encoded = io.BytesIO(); picture.save(encoded, 'PNG')
        spectrogram = analysis.artifact(f'spectrogram-channel-{channel+1}.png', encoded.getvalue(), 'image/png', 'spectrogram', max_bytes=4*1024**2)
        spectrogram.update(preview=True, preview_type='image')
        artifacts.append(spectrogram)
        average = spectrum.mean(axis=0)
        peak = int(np.argmax(average))
        data['channel_data'].append({'channel': channel + 1, 'waveform': waveform,
                                     'playback_artifact_id': segment['id'], 'spectrogram_artifact_id': spectrogram['id'],
                                     'peak_frequency_hz': round(peak*rate/1024, 2),
                                     'frequencies_hz': np.round(np.fft.rfftfreq(1024, 1/rate), 2).tolist(),
                                     'mean_magnitude': np.round(average, 6).tolist(),
                                     'rms': round(float(np.sqrt(np.mean(signal**2))), 6)})
    sox = shutil.which('sox')
    if sox:
        temp = analysis.root / 'sox-input.wav'; temp.write_bytes(wav_bytes(samples, rate))
        try:
            result = run_command([sox, str(temp), '-n', 'stat'], analysis.root)
            data['sox_statistics'] = result['stderr'][:8192]
        finally: temp.unlink(missing_ok=True)
    else: errors.append('SoX unavailable; native FFT/waveform analysis still completed')
    return stage('audio_lab', [finding('audio', 'Audio inspection preview', f'{data["duration"]} seconds, {rate} Hz, {samples.shape[1]} channels', confidence=1)], errors, artifacts,
                 status='partial' if errors else 'completed', data=data)
