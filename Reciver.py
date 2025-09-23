import socket
import struct
import numpy as np
import cv2
import threading
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import pyaudio
import time

UDP_IP = "0.0.0.0"
UDP_PORT_VIDEO = 5005
UDP_PORT_AUDIO = 5004

# Global video variables
video_key = None
video_iv = None
video_frame_size = None
video_buffer = b""

# Set up video socket
sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_video.bind((UDP_IP, UDP_PORT_VIDEO))

# Set up audio socket
sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock_audio.bind((UDP_IP, UDP_PORT_AUDIO))

# Set up audio stream
p = pyaudio.PyAudio()
FORMAT = pyaudio.paInt16
CHANNELS = 2
RATE = 48000
CHUNK = 16384

#PRINT DEVICE AND SUPPORTED SAMPLE RATE
for i in range(p.get_device_count()):
    info = p.get_device_info_by_index(i)
    if info['maxInputChannels'] > 0:
        print(f"Input Device ID {i} - {info['name']}")
        print(f"\tDefault Sample Rate: {info['defaultSampleRate']}")

stream = p.open(format=FORMAT,
                channels=CHANNELS,
                rate=RATE,
                output=True,
                frames_per_buffer=CHUNK)

def receive_video():
    global video_buffer, video_frame_size, video_key, video_iv
    while True:
        try:
            data, _ = sock_video.recvfrom(65536)

            if len(data) == 32:
                video_key = data
                video_buffer = b""
                video_frame_size = None
                continue

            if len(data) == 16:
                video_iv = data
                video_buffer = b""
                video_frame_size = None
                continue

            if len(data) == 4:
                video_frame_size = struct.unpack("!I", data)[0]
                video_buffer = b""
                continue

            video_buffer += data

            if video_frame_size and len(video_buffer) >= video_frame_size and video_key and video_iv:
                encrypted_bytes = video_buffer[:video_frame_size]
                try:
                    encrypted_array = np.frombuffer(encrypted_bytes, dtype=np.uint8)
                    side_length = int(np.sqrt(len(encrypted_array) / 3))
                    if side_length > 0:
                        encrypted_array = encrypted_array[:side_length * side_length * 3]
                        encrypted_image = encrypted_array.reshape((side_length, side_length, 3))
                        cv2.imshow('Encrypted Stream', encrypted_image)
                except Exception as e:
                    print(f"Encrypted image error: {e}")

                try:
                    start = time.time()
                    cipher = AES.new(video_key, AES.MODE_CBC, video_iv)
                    decrypted_data = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)

                    eoi_index = decrypted_data.find(b'\xFF\xD9')
                    if eoi_index != -1:
                        jpeg_data = decrypted_data[:eoi_index + 2]
                        img_array = np.frombuffer(jpeg_data, dtype=np.uint8)
                        frame = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
                        
                        video_encrypt_duration = time.time() - start
        
                        #append to "video Encryption Time"
                        with open("Video Decryption Time.txt", "a") as f:
                            f.write(f"{video_encrypt_duration:.6f}\n")

                        if frame is not None:
                            cv2.imshow("Received Frame", frame)
                            if cv2.waitKey(1) & 0xFF == ord('q'):
                                break
                except Exception as e:
                    print(f"Decryption/display error: {e}")

                video_buffer = b""
                video_frame_size = None

        except Exception as e:
            print(f"Video thread error: {e}")
            video_buffer = b""
            video_frame_size = None

def receive_audio():
    audio_key = None
    audio_iv = None
    audio_size = None
    audio_buffer = b""

    while True:
        try:
            data, _ = sock_audio.recvfrom(65536)

            if len(data) == 32:
                audio_key = data
                audio_buffer = b""
                continue

            if len(data) == 16:
                audio_iv = data
                audio_buffer = b""
                continue

            if len(data) == 4:
                audio_size = struct.unpack("!I", data)[0]
                audio_buffer = b""
                continue

            audio_buffer += data

            if audio_key and audio_iv and audio_size and len(audio_buffer) >= audio_size:
                encrypted_audio = audio_buffer[:audio_size]
                try:
                    start = time.time()
                    cipher = AES.new(audio_key, AES.MODE_CBC, audio_iv)
                    decrypted_audio = unpad(cipher.decrypt(encrypted_audio), AES.block_size)

                    audio_encrypt_duration = time.time() - start
        
                    #append to "audio Encryption Time"
                    with open("Audio Decryption Time.txt", "a") as f:
                        f.write(f"{audio_encrypt_duration:.6f}\n")

                    # Convert decrypted audio to int16 numpy array
                    audio_np = np.frombuffer(decrypted_audio, dtype=np.int16)

                    # Apply gain
                    gain = 2.0  # Increase as needed, e.g., 2.0 = double volume
                    amplified_np = np.clip(audio_np * gain, -32768, 32767).astype(np.int16)

                    # Convert back to bytes
                    amplified_audio = amplified_np.tobytes()

                    # Interleave: Left = encrypted, Right = decrypted (amplified)
                    stereo_audio = b''.join([
                        encrypted_audio[i:i+2] + amplified_audio[i:i+2]
                        for i in range(0, min(len(encrypted_audio), len(amplified_audio)), 2)
                    ])

                    stream.write(stereo_audio)
                except Exception as e:
                    print(f"Audio decryption error: {e}")

                audio_key = None
                audio_iv = None
                audio_size = None
                audio_buffer = b""

        except Exception as e:
            print(f"Audio thread error: {e}")

# Start threads
video_thread = threading.Thread(target=receive_video, daemon=True)
audio_thread = threading.Thread(target=receive_audio, daemon=True)

video_thread.start()
audio_thread.start()

# Keep main thread alive
video_thread.join()
