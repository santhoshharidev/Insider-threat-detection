import subprocess
import tempfile
import os
from typing import Tuple


def run_python_code(code: str, timeout: int = 5) -> Tuple[int, str, str]:
    """Run python code in a temporary file and capture output. Returns (returncode, stdout, stderr)

    Note: This is a naive runner and should NOT be used for untrusted code in production.
    """
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "submission.py")
        with open(path, "w", encoding="utf-8") as f:
            f.write(code)
        try:
            p = subprocess.run(["python", path], capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            return -1, "", f"Timeout: {e}"
