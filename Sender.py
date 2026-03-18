import socket
import threading
import cv2
import pyaudio
from picamera2 import Picamera2

from rust_crypto import RustCryptoWorker

DEST_IP = "192.168.254.165"
VIDEO_PORT = 5005
AUDIO_PORT = 5004
KEY_HEX = "3031323334353637383941424344454630313233343536373839414243444546"

RUST_EXE = "./target/release/crypto_worker"

USE_HW_CRYPTO = True

# Leave None to let OpenSSL auto-detect.
# For experiments, you can set a string here.
OPENSSL_ARMCAP = None

def make_backend():
    return "openssl" if USE_HW_CRYPTO else "rustcrypto"

def make_armcap():
    # Only pass through if you really want to override OpenSSL behavior.
    return OPENSSL_ARMCAP if USE_HW_CRYPTO else None

def audio_sender(sock_audio, worker, stop_event):
    p = pyaudio.PyAudio()

    stream = p.open(
        format=pyaudio.paInt16,
        channels=1,
        rate=48000,
        input=True,
        frames_per_buffer=1024,
    )

    frame_id = 0
    try:
        while not stop_event.is_set():
            audio_data = stream.read(1024, exception_on_overflow=False)
            packets = worker.encrypt_to_packets(frame_id, audio_data)
            for pkt in packets:
                sock_audio.sendto(pkt, (DEST_IP, AUDIO_PORT))
            frame_id = (frame_id + 1) & 0xFFFFFFFF
    finally:
        stream.stop_stream()
        stream.close()
        p.terminate()

def main():
    sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    video_worker = RustCryptoWorker(
        exe_path=RUST_EXE,
        stream="video",
        backend=make_backend(),
        key_hex=KEY_HEX,
        armcap=make_armcap(),
    )

    audio_worker = RustCryptoWorker(
        exe_path=RUST_EXE,
        stream="audio",
        backend=make_backend(),
        key_hex=KEY_HEX,
        armcap=make_armcap(),
    )

    stop_event = threading.Event()
    t = threading.Thread(
        target=audio_sender,
        args=(sock_audio, audio_worker, stop_event),
        daemon=True,
    )
    t.start()

    picam2 = Picamera2()
    cfg = picam2.create_video_configuration(
        main={"size": (640, 480), "format": "RGB888"}
    )
    picam2.configure(cfg)
    picam2.start()

    frame_id = 0
    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), 70]

    try:
        while True:
            frame = picam2.capture_array()
            ok, jpg = cv2.imencode(".jpg", frame, encode_params)
            if not ok:
                continue

            packets = video_worker.encrypt_to_packets(frame_id, jpg.tobytes())
            for pkt in packets:
                sock_video.sendto(pkt, (DEST_IP, VIDEO_PORT))

            frame_id = (frame_id + 1) & 0xFFFFFFFF

    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        picam2.stop()
        video_worker.close()
        audio_worker.close()
        sock_video.close()
        sock_audio.close()

if __name__ == "__main__":
    main()