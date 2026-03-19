import socket
import struct
import threading
import time
import queue

import cv2
import numpy as np
import pyaudio
from Cryptodome.Cipher import AES

BIND_IP = "0.0.0.0"
VIDEO_PORT = 5005
AUDIO_PORT = 5004

MAGIC = b"AV01"
STREAM_VIDEO = 0
STREAM_AUDIO = 1

AUDIO_RATE = 44100
AUDIO_CH = 1
AUDIO_SAMPLES_PER_PACKET = 1024
AUDIO_BYTES_PER_SAMPLE = 2  # int16 mono
AUDIO_PACKET_BYTES = AUDIO_SAMPLES_PER_PACKET * AUDIO_BYTES_PER_SAMPLE

AUDIO_QUEUE_PACKETS = 100
AUDIO_PREFILL_PACKETS = 20
AUDIO_OUTPUT_DEVICE_INDEX = None  # set to an integer if you want a specific device

KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)
if len(KEY) != 32:
    raise RuntimeError("KEY must be 32 bytes for AES-256-GCM")


def parse_packet(data: bytes):
    if len(data) < 34:
        return None

    if data[:4] != MAGIC:
        return None

    stream_type, flags, seq, ts_ms = struct.unpack("!BBIQ", data[4:18])
    nonce = data[18:30]
    ct_len = struct.unpack("!I", data[30:34])[0]

    if len(data) != 34 + ct_len:
        return None

    ciphertext = data[34:]
    aad = data[:18]
    return stream_type, flags, seq, ts_ms, nonce, ciphertext, aad


def decrypt_packet(nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
    if len(ciphertext_and_tag) < 16:
        raise ValueError("ciphertext too short for GCM tag")
    ct = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ct, tag)


def make_silence_packet() -> bytes:
    return b"\x00" * AUDIO_PACKET_BYTES


def audio_receiver():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    sock.bind((BIND_IP, AUDIO_PORT))

    pa = pyaudio.PyAudio()

    print("=== Output Devices ===")
    for i in range(pa.get_device_count()):
        info = pa.get_device_info_by_index(i)
        print(
            f"Index {i}: {info['name']} | "
            f"out={info['maxOutputChannels']} | "
            f"defaultRate={info['defaultSampleRate']}"
        )

    stream_kwargs = dict(
        format=pyaudio.paInt16,
        channels=AUDIO_CH,
        rate=AUDIO_RATE,
        output=True,
        frames_per_buffer=AUDIO_SAMPLES_PER_PACKET,
    )
    if AUDIO_OUTPUT_DEVICE_INDEX is not None:
        stream_kwargs["output_device_index"] = AUDIO_OUTPUT_DEVICE_INDEX

    stream = pa.open(**stream_kwargs)

    audio_q = queue.Queue(maxsize=AUDIO_QUEUE_PACKETS)

    stats = {
        "recv": 0,
        "decrypted": 0,
        "dropped_queue_full": 0,
        "lost_packets": 0,
        "underruns": 0,
        "bad_size": 0,
    }

    stats_lock = threading.Lock()
    start_time = time.time()

    last_seq = None

    def net_thread():
        nonlocal last_seq

        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except Exception as e:
                print(f"audio socket recv error: {e}")
                continue

            pkt = parse_packet(data)
            if not pkt:
                continue

            stream_type, flags, seq, ts_ms, nonce, ciphertext, aad = pkt
            if stream_type != STREAM_AUDIO:
                continue

            with stats_lock:
                stats["recv"] += 1

            try:
                pcm = decrypt_packet(nonce, ciphertext, aad)
            except Exception as e:
                print(f"audio decrypt/auth failed: {e}")
                continue

            if len(pcm) != AUDIO_PACKET_BYTES:
                with stats_lock:
                    stats["bad_size"] += 1
                if len(pcm) < AUDIO_PACKET_BYTES:
                    pcm = pcm + (b"\x00" * (AUDIO_PACKET_BYTES - len(pcm)))
                else:
                    pcm = pcm[:AUDIO_PACKET_BYTES]

            missing = 0
            if last_seq is not None:
                delta = (seq - last_seq) & 0xFFFFFFFF
                if delta > 1:
                    missing = delta - 1
                    with stats_lock:
                        stats["lost_packets"] += missing
                    print(f"audio packet loss/jump: {last_seq} -> {seq} (missing {missing})")
            last_seq = seq

            # Insert silence for missing packets to preserve timing
            for _ in range(missing):
                silence = make_silence_packet()
                if audio_q.full():
                    try:
                        audio_q.get_nowait()
                        with stats_lock:
                            stats["dropped_queue_full"] += 1
                    except queue.Empty:
                        pass
                try:
                    audio_q.put_nowait(silence)
                except queue.Full:
                    with stats_lock:
                        stats["dropped_queue_full"] += 1

            if audio_q.full():
                try:
                    audio_q.get_nowait()
                    with stats_lock:
                        stats["dropped_queue_full"] += 1
                except queue.Empty:
                    pass

            try:
                audio_q.put_nowait(pcm)
                with stats_lock:
                    stats["decrypted"] += 1
            except queue.Full:
                with stats_lock:
                    stats["dropped_queue_full"] += 1

    def play_thread():
        started = False

        while True:
            if not started:
                qsize = audio_q.qsize()
                if qsize < AUDIO_PREFILL_PACKETS:
                    time.sleep(0.005)
                    continue
                started = True
                print(f"audio playback started, prefill={qsize} packets")

            try:
                pcm = audio_q.get(timeout=0.05)
            except queue.Empty:
                pcm = make_silence_packet()
                with stats_lock:
                    stats["underruns"] += 1
                print("audio underrun")

            try:
                stream.write(pcm)
            except Exception as e:
                print(f"audio playback error: {e}")
                time.sleep(0.01)

    def stats_thread():
        while True:
            time.sleep(2.0)
            with stats_lock:
                elapsed = max(time.time() - start_time, 0.001)
                print(
                    "[audio stats] "
                    f"recv={stats['recv']} "
                    f"decrypted={stats['decrypted']} "
                    f"lost={stats['lost_packets']} "
                    f"underruns={stats['underruns']} "
                    f"queue_drops={stats['dropped_queue_full']} "
                    f"bad_size={stats['bad_size']} "
                    f"qsize={audio_q.qsize()} "
                    f"pps={stats['recv'] / elapsed:.1f}"
                )

    t1 = threading.Thread(target=net_thread, daemon=True)
    t2 = threading.Thread(target=play_thread, daemon=True)
    t3 = threading.Thread(target=stats_thread, daemon=True)
    t1.start()
    t2.start()
    t3.start()

    t1.join()


def video_receiver():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    sock.bind((BIND_IP, VIDEO_PORT))
    last_seq = None

    while True:
        try:
            data, _ = sock.recvfrom(65535)
        except Exception as e:
            print(f"video socket recv error: {e}")
            continue

        pkt = parse_packet(data)
        if not pkt:
            continue

        stream_type, flags, seq, ts_ms, nonce, ciphertext, aad = pkt
        if stream_type != STREAM_VIDEO:
            continue

        try:
            jpeg = decrypt_packet(nonce, ciphertext, aad)
        except Exception as e:
            print(f"video decrypt/auth failed: {e}")
            continue

        arr = np.frombuffer(jpeg, dtype=np.uint8)
        frame = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if frame is None:
            continue

        if last_seq is not None and ((seq - last_seq) & 0xFFFFFFFF) != 1:
            print(f"video packet loss/jump: {last_seq} -> {seq}")
        last_seq = seq

        cv2.imshow("Video", frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break


def main():
    vt = threading.Thread(target=video_receiver, daemon=True)
    at = threading.Thread(target=audio_receiver, daemon=True)
    vt.start()
    at.start()
    vt.join()


if __name__ == "__main__":
    main()