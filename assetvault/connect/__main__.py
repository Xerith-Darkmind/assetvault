import os, runpy, sys

BIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin")
sys.path.insert(0, BIN)
runpy.run_path(os.path.join(BIN, "connect.py"), run_name="__main__")
