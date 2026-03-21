import csv
import os
import threading
import time
import psutil

def now_ms():
    return int(time.time() * 1000)

import json
import os
from datetime import datetime

def write_run_manifest(path):
    manifest = {
        "run_name": os.getenv("RUN_NAME", "default_run"),
        "timestamp": datetime.now().isoformat(),

        "network": {
            "dest_ip": os.getenv("DEST_IP"),
            "video_port": int(os.getenv("VIDEO_PORT", 5005)),
            "audio_port": int(os.getenv("AUDIO_PORT", 5004)),
        },

        "video": {
            "width": int(os.getenv("VIDEO_WIDTH", 640)),
            "height": int(os.getenv("VIDEO_HEIGHT", 480)),
            "fps": int(os.getenv("VIDEO_FPS", 15)),
            "jpeg_quality": int(os.getenv("JPEG_QUALITY", 70)),
        },

        "audio": {
            "rate": int(os.getenv("AUDIO_RATE", 44100)),
            "channels": int(os.getenv("AUDIO_CHANNELS", 1)),
            "chunk": int(os.getenv("AUDIO_CHUNK", 1024)),
        },

        "crypto": {
            "mode": os.getenv("CRYPTO_MODE"),
            "armcap": os.getenv("CRYPTO_ARM_CAP"),
        }
    }

    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)

def system_metrics_thread(stop_event, logger):
    proc = psutil.Process(os.getpid())
    proc.cpu_percent(interval=None)

    while not stop_event.is_set():
        cpu = proc.cpu_percent(interval=1.0)
        mem_mb = proc.memory_info().rss / (1024 * 1024)
        threads = proc.num_threads()

        logger.log(
            timestamp_ms=now_ms(),
            cpu_percent=cpu,
            memory_mb=mem_mb,
            threads=threads,
        )

class CsvLogger:
    def __init__(self, path, fieldnames):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.file = open(path, "a", newline="")
        self.writer = csv.DictWriter(self.file, fieldnames=fieldnames)
        self.lock = threading.Lock()
        if self.file.tell() == 0:
            self.writer.writeheader()
            self.file.flush()

    def log(self, **kwargs):
        with self.lock:
            self.writer.writerow(kwargs)
            self.file.flush()

    def close(self):
        with self.lock:
            self.file.close()