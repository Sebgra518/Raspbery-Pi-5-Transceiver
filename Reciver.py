import argparse
import json
import socket
import struct
import time
import threading

import cv2
import numpy as np
import pyaudio
from Cryptodome.Cipher import AES

VERSION = 1
STREAM_VIDEO = 1
STREAM_AUDIO = 2

HEADER_FORMAT = "!BBIHHQ12s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

def decrypt_chunk(key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(aad)
    ciphertext = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]
    return cipher.decrypt_and_verify(ciphertext, tag)

class Reassembly:
    def __init__(self, timeout=300):
        self.frames = {}
        self.timeout = timeout

    def add(self, frame_id, idx, total, payload):
        now = time.monotonic_ns() // 1_000_000

        if frame_id not in self.frames:
            self.frames[frame_id] = {
                "chunks": {},
                "total": total,
                "time": now
            }

        f = self.frames[frame_id]
        f["chunks"][idx] = payload

        if len(f["chunks"]) == f["total"]:
            data = b''.join(f["chunks"][i] for i in range(total))
            del self.frames[frame_id]
            return data

        # cleanup
        for k in list(self.frames.keys()):
            if now - self.frames[k]["time"] > self.timeout:
                del self.frames[k]

        return None

def load_config(args):
    config = {}
    if args.config:
        with open(args.config) as f:
            config = json.load(f)

    def get(name, default):
        return getattr(args, name) if getattr(args, name) else config.get(name, default)

    key = bytes.fromhex(get("key_hex", None))
    return {
        "video_port": get("video_port", 5005),
        "audio_port": get("audio_port", 5004),
        "key": key
    }

def video_thread(cfg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", cfg["video_port"]))

    r = Reassembly()

    while True:
        pkt, _ = sock.recvfrom(2048)

        header = pkt[:HEADER_SIZE]
        body = pkt[HEADER_SIZE:]

        try:
            v, t, fid, idx, total, ts, nonce = struct.unpack(HEADER_FORMAT, header)
            if t != STREAM_VIDEO:
                continue

            plain = decrypt_chunk(cfg["key"], nonce, body, header)

            frame = r.add(fid, idx, total, plain)
            if frame:
                img = cv2.imdecode(np.frombuffer(frame, np.uint8), 1)
                if img is not None:
                    cv2.imshow("Video", img)
                    cv2.waitKey(1)
        except:
            pass

def audio_thread(cfg):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", cfg["audio_port"]))

    p = pyaudio.PyAudio()
    stream = p.open(format=pyaudio.paInt16, channels=1, rate=48000, output=True)

    r = Reassembly()

    while True:
        pkt, _ = sock.recvfrom(2048)
        header = pkt[:HEADER_SIZE]
        body = pkt[HEADER_SIZE:]

        try:
            v, t, fid, idx, total, ts, nonce = struct.unpack(HEADER_FORMAT, header)
            if t != STREAM_AUDIO:
                continue

            plain = decrypt_chunk(cfg["key"], nonce, body, header)

            audio = r.add(fid, idx, total, plain)
            if audio:
                stream.write(audio)
        except:
            pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--video-port", type=int)
    parser.add_argument("--audio-port", type=int)
    parser.add_argument("--key-hex", required=True)

    args = parser.parse_args()
    cfg = load_config(args)

    threading.Thread(target=video_thread, args=(cfg,), daemon=True).start()
    threading.Thread(target=audio_thread, args=(cfg,), daemon=True).start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()