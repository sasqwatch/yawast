from contextlib import contextmanager
import io
import sys


@contextmanager
def capture_sys_output():
    capture_out, capture_err = io.StringIO(), io.StringIO()
    current_out, current_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = capture_out, capture_err
        yield capture_out, capture_err
    finally:
        sys.stdout, sys.stderr = current_out, current_err
