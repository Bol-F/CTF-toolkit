"""Known-answer, benign CTF lab samples generated without network access."""
import base64
import io
import json
import math
from pathlib import Path
import struct
import wave

import numpy as np
from PIL import Image, ImageDraw, PngImagePlugin
import qrcode


def make_advanced(root):
    root = Path(root); root.mkdir(parents=True,exist_ok=True)
    expected = {}
    secret = b'flag{native_lsb_known_answer}\0'
    pixels = np.full((64,64,4),128,dtype=np.uint8); pixels[:,:,3]=255
    # Conventional RGB row-major bit0, first emitted bit is the MSB of a byte.
    for index,bit in enumerate(''.join(f'{byte:08b}' for byte in secret)):
        pixel,channel = divmod(index,3); row,column=divmod(pixel,64)
        pixels[row,column,channel]=(int(pixels[row,column,channel])&254)|int(bit)
    Image.fromarray(pixels,'RGBA').save(root/'lsb.png')
    Image.fromarray(pixels[:,:,:3],'RGB').save(root/'lsb.bmp')
    expected['lsb.png']={'flag':secret[:-1].decode(),'channels':'RGB','bits':[0],'bit_order':'msb','direction':'row'}
    metadata=PngImagePlugin.PngInfo();metadata.add_text('Comment','flag{unusual_metadata_answer}')
    Image.new('RGBA',(80,50),(18,42,90,127)).save(root/'metadata.png',pnginfo=metadata)
    expected['metadata.png']={'flag':'flag{unusual_metadata_answer}'}
    qrcode.make('CTF{qr_only_known_answer}').save(root/'qr.png')
    expected['qr.png']={'flag':'CTF{qr_only_known_answer}'}
    from PIL import ImageFont
    try:font=ImageFont.truetype('DejaVuSansMono.ttf',32)
    except OSError:font=ImageFont.load_default(size=32)
    ocr=Image.new('RGB',(650,110),'white');ImageDraw.Draw(ocr).text((20,30),'CTF{OCR_KNOWN_ANSWER}',font=font,fill='black')
    ocr.save(root/'ocr.png')
    expected['ocr.png']={'flag':'CTF{OCR_KNOWN_ANSWER}'}
    value=base64.b64encode(base64.b32encode(b'picoCTF{two_stage_decode}'))
    (root/'encoded.txt').write_bytes(value)
    expected['encoded.txt']={'flag':'picoCTF{two_stage_decode}','recipe':['base64_decode','base32_decode']}
    frames=[Image.new('RGB',(32,20),color) for color in ['red','green','blue']]
    frames[0].save(root/'frames.gif',save_all=True,append_images=frames[1:],duration=[80,160,240],loop=0)
    expected['frames.gif']={'frames':3,'durations':[80,160,240]}
    rate=22050
    with wave.open(str(root/'stereo.wav'),'wb') as stream:
        stream.setnchannels(2);stream.setsampwidth(2);stream.setframerate(rate)
        content=b''.join(struct.pack('<hh',round(12000*math.sin(2*math.pi*440*i/rate)),round(9000*math.sin(2*math.pi*880*i/rate))) for i in range(rate*2))
        stream.writeframes(content)
    expected['stereo.wav']={'left_peak_hz':440,'right_peak_hz':880}
    glyph=Image.new('L',(32,12),0);ImageDraw.Draw(glyph).text((0,0),'CTF',fill=255)
    mask=np.asarray(glyph)>0
    duration=.05;count=int(rate*duration);t=np.arange(count)/rate
    segments=[]
    for column in range(mask.shape[1]):
        rows=np.flatnonzero(mask[:,column]); signal=np.zeros(count)
        for row in rows: signal+=np.sin(2*np.pi*(600+(11-row)*250)*t)
        if len(rows): signal/=len(rows)
        signal*=np.hanning(count)
        segments.append(signal)
    signal=np.concatenate(segments)
    with wave.open(str(root/'spectrogram-ctf.wav'),'wb') as stream:
        stream.setnchannels(1);stream.setsampwidth(2);stream.setframerate(rate)
        stream.writeframes((signal*24000).astype('<i2').tobytes())
    expected['spectrogram-ctf.wav']={'visual':'CTF frequency glyph, 600–3350 Hz'}
    from .corpus import nested_image
    (root/'appended.png').write_bytes(nested_image())
    (root/'expected.json').write_text(json.dumps(expected,indent=2),encoding='utf-8')
    return {path.name:path for path in root.iterdir()}


if __name__=='__main__':
    import sys
    make_advanced(sys.argv[1] if len(sys.argv)>1 else 'sample-evidence/advanced')
