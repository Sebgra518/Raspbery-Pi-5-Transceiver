import struct
import subprocess
import os


class RustCryptoWorker:
    def __init__(self, exe_path, stream, backend, key_hex, armcap=None):
        env = os.environ.copy()

        # Optional pass-through to OpenSSL runtime capability selection.
        # If armcap is None, leave it alone.
        if armcap is not None:
            env["OPENSSL_armcap"] = armcap

        self.proc = subprocess.Popen(
            [
                exe_path,
                "--stream", stream,
                "--backend", backend,
                "--key-hex", key_hex,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            env=env,
            bufsize=0,
        )

    def encrypt_to_packets(self, frame_id: int, payload: bytes):
        self.proc.stdin.write(struct.pack("!I", frame_id))
        self.proc.stdin.write(struct.pack("!I", len(payload)))
        self.proc.stdin.write(payload)
        self.proc.stdin.flush()

        packet_count = struct.unpack("!I", self._read_exact(4))[0]
        packets = []
        for _ in range(packet_count):
            pkt_len = struct.unpack("!I", self._read_exact(4))[0]
            packets.append(self._read_exact(pkt_len))
        return packets

    def _read_exact(self, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining:
            chunk = self.proc.stdout.read(remaining)
            if not chunk:
                raise RuntimeError("Rust crypto worker exited unexpectedly")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def close(self):
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass