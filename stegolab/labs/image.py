"""Lossless pixel inspection and bounded GIF/LSB extraction using Pillow/NumPy."""
import hashlib
import io
import warnings

import numpy as np
from PIL import Image

Image.MAX_IMAGE_PIXELS = 32_000_000


def load_image(path, frame=0, lsb=False):
    with warnings.catch_warnings():
        warnings.simplefilter('error', Image.DecompressionBombWarning)
        image = Image.open(path)
        if frame < 0 or frame >= min(getattr(image, 'n_frames', 1), 256):
            image.close()
            raise ValueError('Frame is outside the first 256 frames')
        if lsb and image.width * image.height > 8_000_000:
            image.close()
            raise ValueError('LSB extraction is limited to 8 million pixels')
        image.seek(frame)
        rgba = image.convert('RGBA')
        info = {'format': image.format, 'width': image.width, 'height': image.height,
                'mode': image.mode, 'frame_count': getattr(image, 'n_frames', 1),
                'metadata': {str(k): str(v)[:4096] for k, v in list(image.info.items())[:100]}}
        image.close()
        return rgba, info


def png_bytes(image):
    output = io.BytesIO()
    image.save(output, format='PNG')
    return output.getvalue()


def extract_lsb(path, channels='RGB', bits=None, bit_order='msb', direction='row', reverse=False,
                frame=0, max_bytes=65536, skip_bits=0):
    bits = [0] if bits is None else bits
    if not channels or len(channels) > 4 or len(set(channels)) != len(channels) or any(c not in 'RGBA' for c in channels):
        raise ValueError('Channels must be an ordered subset of RGBA, e.g. RGB, BGR or A')
    if not bits or len(set(bits)) != len(bits) or any(type(b) is not int or b < 0 or b > 7 for b in bits):
        raise ValueError('Select unique bit planes from 0 through 7')
    if bit_order not in {'msb', 'lsb'} or direction not in {'row', 'column'}:
        raise ValueError('Bit order must be msb/lsb; direction must be row/column')
    if not 1 <= max_bytes <= 1048576 or not 0 <= skip_bits <= 8_000_000:
        raise ValueError('Extraction limit: 1 MiB output; skip at most 8 million bits')
    image, info = load_image(path, frame, lsb=True)
    pixels = np.asarray(image)
    if direction == 'column': pixels = pixels.transpose(1, 0, 2)
    pixels = pixels.reshape(-1, 4)
    if reverse: pixels = pixels[::-1]
    indices = ['RGBA'.index(c) for c in channels]
    samples_per_pixel = len(indices) * len(bits)
    needed_pixels = min(len(pixels), (skip_bits + max_bytes * 8 + samples_per_pixel - 1) // samples_per_pixel)
    selected = pixels[:needed_pixels, indices]
    values = np.stack([(selected >> bit) & 1 for bit in bits], axis=-1).reshape(-1)
    values = values[skip_bits:skip_bits + max_bytes * 8]
    usable = len(values) // 8 * 8
    output = np.packbits(values[:usable], bitorder='big' if bit_order == 'msb' else 'little').tobytes()
    return output, {'channels': channels, 'bits': bits, 'bit_order': bit_order, 'direction': direction,
                    'reverse_pixels': reverse, 'frame': frame, 'skip_bits': skip_bits,
                    'size': len(output), 'truncated': image.width * image.height * samples_per_pixel - skip_bits > max_bytes * 8,
                    'pixel_offset_mapping': 'Extracted offsets refer to packed output, not original compressed-image bytes',
                    'source_dimensions': [info['width'], info['height']]}


def analyze_image(analysis):
    from ..analysis.engine import stage, finding
    kind = analysis.report['file']['format']
    if kind not in {'png', 'bmp', 'jpeg', 'gif', 'tiff', 'webp'}:
        return stage('image_lab', status='skipped', reason='Not a supported raster image')
    image, info = load_image(analysis.original)
    preview = image.copy()
    preview.thumbnail((1024, 1024))
    artifact = analysis.artifact('image-preview.png', png_bytes(preview.convert('RGB')), 'image/png', 'preview', max_bytes=8*1024**2)
    artifact.update(preview=True, preview_type='image', method='Pillow sanitized RGBA preview')
    values = np.asarray(preview)
    channels = {name: {'min': int(values[:, :, i].min()), 'max': int(values[:, :, i].max()),
                       'mean': round(float(values[:, :, i].mean()), 3),
                       'histogram': np.bincount(values[:, :, i].reshape(-1), minlength=256).tolist()}
                for i, name in enumerate('RGBA')}
    data = {**info, 'preview_artifact_id': artifact['id'], 'preview_dimensions': list(preview.size),
            'preview_resized': preview.size != image.size, 'channels': channels, 'frames': [],
            'limits': {'preview_side': 1024, 'gif_frames': 16, 'gif_total_pixels': 16_000_000, 'lsb_pixels': 8_000_000}}
    alpha = analysis.artifact('image-alpha.png',png_bytes(preview.getchannel('A').convert('RGB')),'image/png','preview',max_bytes=4*1024**2)
    alpha.update(preview=True,preview_type='image')
    data['alpha_artifact_id'] = alpha['id']
    findings, artifacts, errors = [], [artifact,alpha], []
    for key, value in info['metadata'].items():
        if len(value) > 512 or any(term in key.lower() for term in ['comment', 'description', 'user', 'software', 'xmp']):
            findings.append(finding('unusual_metadata', 'Image metadata worth inspecting', f'{key}: {value[:2048]}', confidence=.6,
                                    evidence='Long/free-text application metadata can carry clues; presence alone is not evidence of steganography'))
    if channels['A']['min'] != 255:
        findings.append(finding('image_alpha', 'Image has transparency', 'Inspect alpha channel and its bit planes', confidence=1))
    if kind == 'gif':
        total, previous = 0, None
        with Image.open(analysis.original) as gif:
            for index in range(min(info['frame_count'], 16)):
                gif.seek(index)
                if total + gif.width * gif.height > 16_000_000: break
                total += gif.width * gif.height
                frame = gif.convert('RGBA')
                encoded = png_bytes(frame)
                record = analysis.artifact(f'gif-frame-{index:03d}.png', encoded, 'image/png', 'gif_frame', max_bytes=8*1024**2)
                record.update(preview=True, preview_type='image', frame=index)
                artifacts.append(record)
                array = np.asarray(frame)
                difference = float(np.mean(np.any(array != previous, axis=2))) if previous is not None else None
                data['frames'].append({'index': index, 'duration_ms': gif.info.get('duration', 0),
                                       'disposal': getattr(gif, 'disposal_method', None), 'artifact_id': record['id'],
                                       'sha256': hashlib.sha256(encoded).hexdigest(), 'changed_pixel_fraction': difference})
                previous = array.copy()
        data['frames_truncated'] = len(data['frames']) < info['frame_count']
        if data['frames_truncated']: errors.append('GIF extraction reached frame/pixel limits; remaining frames were not extracted')
    if analysis.mode == 'deep' and kind in {'png', 'bmp'} and image.width * image.height <= 8_000_000:
        from .flags import FlagFinder
        finder = FlagFinder(maximum=50)
        for order in ['RGB', 'BGR', 'R', 'G', 'B', 'A']:
            output, options = extract_lsb(analysis.original, channels=order)
            detected = finder.scan_decoded(output, source=analysis.report['file']['filename'], history=[f'LSB {order} bit0 row/MSB'])
            if detected:
                record = analysis.artifact(f'lsb-{order}.bin', output, 'application/octet-stream', 'lsb')
                record.update(method=f'LSB {order} bit0 row/MSB', extraction=options)
                artifacts.append(record)
                for candidate in detected:
                    candidate['source'] = record['id']
                    candidate['source_file'] = record['name']
                    candidate['offset_scope'] = 'extracted pixel bitstream'
                    candidate['artifact_id'] = record['id']
                findings.extend(detected)
    return stage('image_lab', findings, errors, artifacts, status='partial' if errors else 'completed', data=data)
