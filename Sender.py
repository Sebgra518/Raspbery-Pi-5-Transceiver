import cv2
import subprocess
import time
import socket
import struct
from picamera2 import Picamera2
import base64
import json
import os
import pyaudio
import threading

# Audio sending thread
def audio_sender(sock_audio, ip, port, stream, chunk, proc):
    while True:
        try:
            audio_data = stream.read(chunk, exception_on_overflow=False)
        except IOError:
            print("Audio buffer overflowed, sending silence")
            audio_data = b'\x00' * chunk  # Silence

        try:
            # Encrypt audio data using same subprocess
            start = time.time()
            length = struct.pack(">I", len(audio_data))
            proc.stdin.write(length + audio_data)
            proc.stdin.flush()
            audio_encrypt_duration = time.time() - start
        
            #append to "video Encryption Time"
            with open("Audio Encryption Time.txt", "a") as f:
                f.write(f"{audio_encrypt_duration:.6f}\n")

            output = json.loads(proc.stdout.readline())
            encrypted_audio = base64.b64decode(output["data"])

            # Optional: send key + iv if needed by receiver
            key = base64.b64decode(output["key"])
            iv = base64.b64decode(output["iv"])

            sock_audio.sendto(key, (ip, port))
            sock_audio.sendto(iv, (ip, port))
            sock_audio.sendto(struct.pack("!I", len(encrypted_audio)), (ip, port))
            sock_audio.sendto(encrypted_audio, (ip, port))

        except Exception as e:
            print(f"Audio encryption/send error: {e}")

def main():
    #UDP_IP = "192.168.254.82"  # Home PC IP
    #UDP_IP = "192.168.254.160"  # Laptop Home IP
    #UDP_IP = "172.20.10.2"  # Laptop Out IP
    #UDP_IP = "172.20.10.6"  # Chris TEMP IP
    UDP_IP = "192.168.254.165"  # Home self IP
    UDP_PORT_VIDEO = 5005
    UDP_PORT_AUDIO = 5004

    sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    CHUNK = 16384  # 4096 samples * 2 bytes/sample = 8192 bytes
    CHUNK_SIZE = 64000 - 16  # For video encryption chunks

    #Open audio Stream
    p = pyaudio.PyAudio()

    #PRINT DEVICE AND SUPPORTED SAMPLE RATE
    for i in range(p.get_device_count()):
        info = p.get_device_info_by_index(i)
        if info['maxInputChannels'] > 0:
            print(f"Input Device ID {i} - {info['name']}")
            print(f"\tDefault Sample Rate: {info['defaultSampleRate']}")

    stream = p.open(format=pyaudio.paInt16,
                    channels=1,
                    rate=48000,
                    input=True,
                    input_device_index=1,
                    frames_per_buffer=CHUNK)

    #Turn crypto engine on/off (0 = on | 1 = off)
    env = os.environ.copy()
    env["OPENSSL_armcap"] = "1"

    #Open Rust Subprocess and pip I/O
    proc = subprocess.Popen(
        ["./target/release/ECE4301Final"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )

    # Start audio thread
    audio_thread = threading.Thread(
        target=audio_sender,
        args=(sock_audio, UDP_IP, UDP_PORT_AUDIO, stream, CHUNK, proc),
        daemon=True
    )
    audio_thread.start()

    # Start camera
    picam2 = Picamera2()
    picam2.preview_configuration.main.size = (584, 480)
    picam2.preview_configuration.main.format = "RGB888"
    picam2.start()

    print("Sending video and audio...")

    while True:
        frame = picam2.capture_array()
        ret, frame_bytes = cv2.imencode('.jpg', frame)
        if not ret:
            continue

        frame_data = frame_bytes.tobytes()
        length = struct.pack(">I", len(frame_data))

        #Encrypt
        startTime = time.time()
        proc.stdin.write(length + frame_data)
        proc.stdin.flush()
        output = json.loads(proc.stdout.readline())
        video_encrypt_duration = time.time() - startTime

        #append to "video Encryption Time"
        with open("Video Encryption Time.txt", "a") as f:
            f.write(f"{video_encrypt_duration:.6f}\n")

        key = base64.b64decode(output["key"])
        iv = base64.b64decode(output["iv"])
        encrypted_frame = base64.b64decode(output["data"])
        frame_size = len(encrypted_frame)

        sock_video.sendto(key, (UDP_IP, UDP_PORT_VIDEO))
        sock_video.sendto(iv, (UDP_IP, UDP_PORT_VIDEO))
        sock_video.sendto(struct.pack("!I", frame_size), (UDP_IP, UDP_PORT_VIDEO))

        for i in range(0, frame_size, CHUNK_SIZE):
            chunk = encrypted_frame[i:i + CHUNK_SIZE]
            sock_video.sendto(chunk, (UDP_IP, UDP_PORT_VIDEO))

if __name__ == "__main__":
    main()
