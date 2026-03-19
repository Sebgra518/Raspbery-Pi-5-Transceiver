import math
import struct
import pyaudio

RATE = 48000
p = pyaudio.PyAudio()

for i in range(p.get_device_count()):
    info = p.get_device_info_by_index(i)
    print(i, info['name'], info['maxOutputChannels'], info['defaultSampleRate'])

stream = p.open(
    format=pyaudio.paInt16,
    channels=1,
    rate=RATE,
    output=True,
    output_device_index=22,   # set this to your real output device
)

freq = 440.0
duration = 2.0
samples = []

for n in range(int(RATE * duration)):
    v = int(12000 * math.sin(2 * math.pi * freq * n / RATE))
    samples.append(struct.pack('<h', v))

stream.write(b''.join(samples))
stream.stop_stream()
stream.close()
p.terminate()