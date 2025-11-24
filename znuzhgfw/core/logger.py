import datetime
import os


class Logger:
    """
    Basit ama iş gören bir logger.
    Hem konsola hem dosyaya yazar.
    """

    def __init__(self, log_dir: str = "logs"):
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_path = os.path.join(log_dir, f"scan_{ts}.log")
        self._fh = open(self.log_path, "w", encoding="utf-8")

    def log(self, msg: str):
        line = f"[{datetime.datetime.now().isoformat()}] {msg}"
        print(line)
        self._fh.write(line + "\n")
        self._fh.flush()

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass
