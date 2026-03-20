import struct
import subprocess
import threading

class RustEncryptor:
    def __init__(self, exe_path: str, env=None):
        self.exe_path = exe_path
        self.env = env
        self.lock = threading.Lock()
        self.proc = self._start_proc()

    def _start_proc(self):
        return subprocess.Popen(
            [self.exe_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=self.env,
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