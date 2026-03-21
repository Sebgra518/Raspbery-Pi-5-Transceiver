import cv2
import socket
import struct
import threading
import time
from picamera2 import Picamera2
import pyaudio
from dotenv import load_dotenv
import os
from metricslogger import CsvLogger, now_ms, system_metrics_thread, write_run_manifest
from rustencryptor import RustEncryptor

load_dotenv()

#Network Setings
DEST_IP = os.getenv("DEST_IP", "127.0.0.1")
VIDEO_PORT = int(os.getenv("VIDEO_PORT", 5005))
AUDIO_PORT = int(os.getenv("AUDIO_PORT", 5004))

SOCKET_BUFFER_SIZE = int(os.getenv("SOCKET_BUFFER", 1024 * 1024))

MAGIC = b"AV01"
STREAM_VIDEO = 0
STREAM_AUDIO = 1

#Video Settings
VIDEO_W = int(os.getenv("VIDEO_WIDTH", 640))
VIDEO_H = int(os.getenv("VIDEO_HEIGHT", 480))
VIDEO_FPS = int(os.getenv("VIDEO_FPS", 15))
JPEG_QUALITY = int(os.getenv("JPEG_QUALITY", 70))
MAX_UDP_PACKET = 65000

#Audio Settings
AUDIO_RATE = int(os.getenv("AUDIO_RATE", 44100))
AUDIO_CH = int(os.getenv("AUDIO_CHANNELS", 1))
AUDIO_CHUNK = int(os.getenv("AUDIO_CHUNK", 1024))
AUDIO_INPUT_DEVICE_INDEX = int(os.getenv("AUDIO_INPUT_DEVICE", 0))

#ARMV8 Crypto Engine Settings
CRYPTO_MODE = os.getenv("CRYPTO_MODE", "auto").strip().lower()
CRYPTO_ARM_CAP = os.getenv("CRYPTO_ARM_CAP", "").strip()


def build_header(stream_type: int, seq: int, ts_ms: int, nonce: bytes, ct_len: int) -> bytes:
    try:
        stream_type_i = int(stream_type)
        seq_i = int(seq)
        ts_ms_i = int(ts_ms)
        ct_len_i = int(ct_len)
    except Exception as e:
        raise TypeError(
            "Header arg conversion failed: "
            f"stream_type={stream_type!r} ({type(stream_type)}), "
            f"seq={seq!r} ({type(seq)}), "
            f"ts_ms={ts_ms!r} ({type(ts_ms)}), "
            f"ct_len={ct_len!r} ({type(ct_len)})"
        ) from e

    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 12:
        raise TypeError(f"nonce must be 12 bytes, got {type(nonce)} len={len(nonce) if hasattr(nonce, '__len__') else 'n/a'}")

    return (
        MAGIC +
        struct.pack("!BBIQ", stream_type_i, 0, seq_i, ts_ms_i) +
        nonce +
        struct.pack("!I", ct_len_i)
    )

def build_encryptor_env():
    env = os.environ.copy()

    match CRYPTO_MODE:
        case "auto":
            env.pop("OPENSSL_armcap", None)
            print("Crypto mode: auto (OpenSSL runtime detection)")
        case "off":
            env["OPENSSL_armcap"] = "1"
            print("Crypto mode: off (OPENSSL_armcap=1)")
        case "custom":
            if not CRYPTO_ARM_CAP:
                raise ValueError("CRYPTO_MODE=custom requires CRYPTO_ARM_CAP")
            env["OPENSSL_armcap"] = CRYPTO_ARM_CAP
            print(f"Crypto mode: custom (OPENSSL_armcap={CRYPTO_ARM_CAP})")
        case _:
            raise ValueError("CRYPTO_MODE must be auto, off, or custom")

    return env

#Encryption threads for Audio/Video
def audio_thread_fn(sock, encryptor, stop_event, logger):
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
        while not stop_event.is_set():
            loop_start = time.monotonic()

            pcm = stream.read(AUDIO_CHUNK, exception_on_overflow=False)
            ts = now_ms()

            tmp_header = build_header(STREAM_AUDIO, seq, ts, b"\x00" * 12, 0)
            aad = tmp_header[:18]

            start = time.perf_counter()
            nonce, ciphertext = encryptor.encrypt(STREAM_AUDIO, aad, pcm)
            encrypt_time_ms = (time.perf_counter() - start) * 1000.0

            pkt = build_header(STREAM_AUDIO, seq, ts, nonce, len(ciphertext)) + ciphertext
            sock.sendto(pkt, (DEST_IP, AUDIO_PORT))

            logger.log(
                timestamp_ms=now_ms(),
                stream_type="audio",
                seq=seq,
                payload_bytes=len(pcm),
                packet_bytes=len(pkt),
                encrypt_time_ms=encrypt_time_ms,
                send_ok=1,
            )

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

def video_thread_fn(sock, encryptor, stop_event, logger):
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
        while not stop_event.is_set():
            loop_start = time.monotonic()

            frame = picam2.capture_array()
            ok, enc = cv2.imencode(".jpg", frame, encode_param)
            if not ok:
                continue

            jpeg = enc.tobytes()

            if len(jpeg) > 60000:
                logger.log(
                    timestamp_ms=now_ms(),
                    stream_type="video",
                    seq=seq,
                    payload_bytes=len(jpeg),
                    packet_bytes=0,
                    encrypt_time_ms=0.0,
                    send_ok=0,
                )
                continue

            ts = now_ms()

            tmp_header = build_header(STREAM_VIDEO, seq, ts, b"\x00" * 12, 0)
            aad = tmp_header[:18]

            start = time.perf_counter()
            nonce, ciphertext = encryptor.encrypt(STREAM_VIDEO, aad, jpeg)
            encrypt_time_ms = (time.perf_counter() - start) * 1000.0

            pkt = build_header(STREAM_VIDEO, seq, ts, nonce, len(ciphertext)) + ciphertext

            send_ok = 0
            if len(pkt) <= MAX_UDP_PACKET:
                sock.sendto(pkt, (DEST_IP, VIDEO_PORT))
                send_ok = 1

            logger.log(
                timestamp_ms=now_ms(),
                stream_type="video",
                seq=seq,
                payload_bytes=len(jpeg),
                packet_bytes=len(pkt) if send_ok else 0,
                encrypt_time_ms=encrypt_time_ms,
                send_ok=send_ok,
            )

            seq = (seq + 1) & 0xFFFFFFFF

            elapsed = time.monotonic() - loop_start
            sleep_time = video_frame_period - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

    finally:
        try:
            picam2.stop()
        except Exception:
            pass

def main():

    write_run_manifest("experiments/logs/run_manifest.json")

    sender_logger = CsvLogger(
        "experiments/logs/sender.csv",
        fieldnames=[
            "timestamp_ms",
            "stream_type",
            "seq",
            "payload_bytes",
            "packet_bytes",
            "encrypt_time_ms",
            "send_ok",
        ],
    )

    sender_system_logger = CsvLogger(
    "experiments/logs/sender_system.csv",
    fieldnames=[
        "timestamp_ms",
        "cpu_percent",
        "memory_mb",
        "threads",
        ],
    )

    stop_event = threading.Event()

    sys_thread = threading.Thread(
        target=system_metrics_thread,
        args=(stop_event, sender_system_logger),
        daemon=True,
    )
    sys_thread.start()

    sock_video = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_audio = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock_video.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
    sock_audio.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)

    encryptor_env = build_encryptor_env()

    enc_video = RustEncryptor("./target/release/udp_av_encryptor", env=encryptor_env)
    enc_audio = RustEncryptor("./target/release/udp_av_encryptor", env=encryptor_env)

    audio_thread = threading.Thread(
        target=audio_thread_fn,
        args=(sock_audio, enc_audio, stop_event, sender_logger),
        daemon=True,
    )

    video_thread = threading.Thread(
        target=video_thread_fn,
        args=(sock_video, enc_video, stop_event, sender_logger),
        daemon=True,
    )
    audio_thread.start()
    video_thread.start()

    try:
        video_thread.join()
    except KeyboardInterrupt:
        print("Stopping sender...")
    finally:
        stop_event.set()

        audio_thread.join(timeout=2.0)
        video_thread.join(timeout=2.0)
        sys_thread.join(timeout=2.0)

        enc_video.close()
        enc_audio.close()
        sock_video.close()
        sock_audio.close()

        sender_logger.close()
        sender_system_logger.close()


if __name__ == "__main__":
    main()