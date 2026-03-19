import cv2
import os
import socket
import struct
import subprocess
import threading
import time
from picamera2 import Picamera2
import pyaudio

DEST_IP = "192.168.254.82"
VIDEO_PORT = 5005
AUDIO_PORT = 5004

MAGIC = b"AV01"
STREAM_VIDEO = 0
STREAM_AUDIO = 1

VIDEO_W = 640
VIDEO_H = 480
JPEG_QUALITY = 80

AUDIO_RATE = 44100
AUDIO_CH = 1
AUDIO_CHUNK = 1024  # samples\

def now_ms() -> int:
    return int(time.monotonic_ns() // 1_000_000)

def build_header(stream_type: int, seq: int, ts_ms: int, nonce: bytes, ct_len: int) -> bytes:
    return (
        MAGIC +
        struct.pack("!BBIQ", stream_type, 0, seq, ts_ms) +
        nonce +
        struct.pack("!I", ct_len)
    )

class RustEncryptor:
    def __init__(self, exe_path: str):
        self.proc = subprocess.Popen(
            [exe_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.lock = threading.Lock()

    def _read_exact(self, n: int) -> bytes:
        chunks = []
        total = 0
        while total < n:
            chunk = self.proc.stdout.read(n - total)
            if not chunk:
                rc = self.proc.poll()
                err = b""
                try:
                    err = self.proc.stderr.read()
                except Exception:
                    pass
                raise RuntimeError(
                    f"encryptor stdout closed early "
                    f"(wanted {n}, got {total}, returncode={rc}, stderr={err.decode(errors='replace')})"
                )
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def encrypt(self, stream_type: int, aad: bytes, payload: bytes):
        with self.lock:
            self.proc.stdin.write(struct.pack("!B", stream_type))
            self.proc.stdin.write(struct.pack("!I", len(payload)))
            self.proc.stdin.write(struct.pack("!I", len(aad)))
            self.proc.stdin.write(aad)
            self.proc.stdin.write(payload)
            self.proc.stdin.flush()

            nonce = self._read_exact(12)
            ct_len = struct.unpack("!I", self._read_exact(4))[0]
            ciphertext = self._read_exact(ct_len)

            return nonce, ciphertext

def audio_thread_fn(sock: socket.socket, encryptor: RustEncryptor):
    pa = pyaudio.PyAudio()
    
    stream = pa.open(
        format=pyaudio.paInt16,
        channels=AUDIO_CH,
        rate=AUDIO_RATE,
        input=True,
        input_device_index=0,
        frames_per_buffer=AUDIO_CHUNK,
    )   

    seq = 0
    while True:
        pcm = stream.read(AUDIO_CHUNK, exception_on_overflow=False)
        ts = now_ms()

        tmp_header = build_header(STREAM_AUDIO, seq, ts, b"\x00" * 12, 0)
        aad = tmp_header[:4 + 1 + 1 + 4 + 8]  # header without nonce/len is enough as AAD

        nonce, ciphertext = encryptor.encrypt(STREAM_AUDIO, aad, pcm)
        pkt = build_header(STREAM_AUDIO, seq, ts, nonce, len(ciphertext)) + ciphertext
        sock.sendto(pkt, (DEST_IP, AUDIO_PORT))
        seq = (seq + 1) & 0xFFFFFFFF

def main():
    sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    enc_video = RustEncryptor("./target/release/udp_av_encryptor")
    enc_audio = RustEncryptor("./target/release/udp_av_encryptor")

    th = threading.Thread(target=audio_thread_fn, args=(sock_audio, enc_audio), daemon=True)
    th.start()

    picam2 = Picamera2()
    cfg = picam2.create_video_configuration(
        main={"size": (VIDEO_W, VIDEO_H), "format": "RGB888"}
    )
    picam2.configure(cfg)
    picam2.start()

    seq = 0
    encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY]

    while True:
        frame = picam2.capture_array()
        ok, enc = cv2.imencode(".jpg", frame, encode_param)
        if not ok:
            continue

        jpeg = enc.tobytes()
        ts = now_ms()

        tmp_header = build_header(STREAM_VIDEO, seq, ts, b"\x00" * 12, 0)
        aad = tmp_header[:4 + 1 + 1 + 4 + 8]

        nonce, ciphertext = enc_video.encrypt(STREAM_VIDEO, aad, jpeg)
        pkt = build_header(STREAM_VIDEO, seq, ts, nonce, len(ciphertext)) + ciphertext

        # Keep one frame per datagram only if small enough.
        # For larger frames, either lower JPEG quality or fragment explicitly.
        if len(pkt) <= 65000:
            sock_video.sendto(pkt, (DEST_IP, VIDEO_PORT))

        seq = (seq + 1) & 0xFFFFFFFF

if __name__ == "__main__":
    main()