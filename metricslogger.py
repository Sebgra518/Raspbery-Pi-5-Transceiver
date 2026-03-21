import csv
import os
import threading
import time
import psutil

def now_ms():
    return int(time.time() * 1000)

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