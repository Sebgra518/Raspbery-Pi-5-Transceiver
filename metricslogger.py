import csv
import os
import threading
import time

def now_ms():
    return int(time.time() * 1000)

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