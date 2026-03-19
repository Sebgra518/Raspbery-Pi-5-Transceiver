import pyaudio

p = pyaudio.PyAudio()

print("=== Devices ===")
for i in range(p.get_device_count()):
    info = p.get_device_info_by_index(i)
    print(f"Index {i}: {info['name']}")
    print(f"  maxInputChannels={info['maxInputChannels']}")
    print(f"  maxOutputChannels={info['maxOutputChannels']}")
    print(f"  defaultSampleRate={info['defaultSampleRate']}")
    print()

p.terminate()