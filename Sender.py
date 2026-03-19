import cv2
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
JPEG_QUALITY = 70
VIDEO_FPS = 15
MAX_UDP_PACKET = 65000

AUDIO_RATE = 44100
AUDIO_CH = 1
AUDIO_CHUNK = 1024
AUDIO_INPUT_DEVICE_INDEX = 0

SOCKET_BUFFER_SIZE = 1024 * 1024


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
        self.exe_path = exe_path
        self.lock = threading.Lock()
        self.proc = self._start_proc()

    def _start_proc(self):
        return subprocess.Popen(
            [self.exe_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

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
                    f"(wanted {n}, got {total}, returncode={rc}, "
                    f"stderr={err.decode(errors='replace')})"
                )
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def encrypt(self, stream_type: int, aad: bytes, payload: bytes):
        with self.lock:
            if self.proc.poll() is not None:
                raise RuntimeError("encryptor process exited unexpectedly")

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

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            if self.proc.stdout:
                self.proc.stdout.close()
        except Exception:
            pass
        try:
            if self.proc.stderr:
                self.proc.stderr.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass


def audio_thread_fn(sock: socket.socket, encryptor: RustEncryptor):
    pa = pyaudio.PyAudio()

    print("=== Sender Input Devices ===")
    for i in range(pa.get_device_count()):
        info = pa.get_device_info_by_index(i)
        if info["maxInputChannels"] > 0:
            print(
                f"Index {i}: {info['name']} | "
                f"in={info['maxInputChannels']} | "
                f"defaultRate={info['defaultSampleRate']}"
            )

    stream = pa.open(
        format=pyaudio.paInt16,
        channels=AUDIO_CH,
        rate=AUDIO_RATE,
        input=True,
        input_device_index=AUDIO_INPUT_DEVICE_INDEX,
        frames_per_buffer=AUDIO_CHUNK,
    )

    seq = 0
    frame_duration = AUDIO_CHUNK / AUDIO_RATE

    print(f"Audio sender started: chunk={AUDIO_CHUNK}, rate={AUDIO_RATE}, packet every {frame_duration:.4f}s")

    try:
        while True:
            loop_start = time.monotonic()

            pcm = stream.read(AUDIO_CHUNK, exception_on_overflow=False)
            ts = now_ms()

            tmp_header = build_header(STREAM_AUDIO, seq, ts, b"\x00" * 12, 0)
            aad = tmp_header[:18]

            nonce, ciphertext = encryptor.encrypt(STREAM_AUDIO, aad, pcm)
            pkt = build_header(STREAM_AUDIO, seq, ts, nonce, len(ciphertext)) + ciphertext

            sock.sendto(pkt, (DEST_IP, AUDIO_PORT))
            seq = (seq + 1) & 0xFFFFFFFF

            elapsed = time.monotonic() - loop_start
            sleep_time = frame_duration - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

    finally:
        try:
            stream.stop_stream()
            stream.close()
        except Exception:
            pass
        pa.terminate()


def main():
    sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock_video.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
    sock_audio.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)

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
    video_frame_period = 1.0 / VIDEO_FPS

    print(f"Video sender started: {VIDEO_W}x{VIDEO_H}, jpeg_quality={JPEG_QUALITY}, fps={VIDEO_FPS}")

    try:
        while True:
            loop_start = time.monotonic()

            frame = picam2.capture_array()
            ok, enc = cv2.imencode(".jpg", frame, encode_param)
            if not ok:
                continue

            jpeg = enc.tobytes()

            # Skip very large frames instead of letting them cause fragmentation pain
            if len(jpeg) > 60000:
                continue

            ts = now_ms()

            tmp_header = build_header(STREAM_VIDEO, seq, ts, b"\x00" * 12, 0)
            aad = tmp_header[:18]

            nonce, ciphertext = enc_video.encrypt(STREAM_VIDEO, aad, jpeg)
            pkt = build_header(STREAM_VIDEO, seq, ts, nonce, len(ciphertext)) + ciphertext

            if len(pkt) <= MAX_UDP_PACKET:
                sock_video.sendto(pkt, (DEST_IP, VIDEO_PORT))

            seq = (seq + 1) & 0xFFFFFFFF

            elapsed = time.monotonic() - loop_start
            sleep_time = video_frame_period - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("Stopping sender...")

    finally:
        try:
            picam2.stop()
        except Exception:
            pass

        enc_video.close()
        enc_audio.close()

        sock_video.close()
        sock_audio.close()


if __name__ == "__main__":
    main()