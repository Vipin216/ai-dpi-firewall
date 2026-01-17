import threading
import time
import subprocess
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_command(cmd):
    subprocess.run(cmd, cwd=BASE_DIR)

def start_sniffer():
    run_command(["python", "capture/sniffer.py"])

def run_pipeline():
    while True:
        time.sleep(10)

        run_command(["python", "features/feature_extractor.py"])
        run_command(["python", "detection/rule_engine.py"])
        run_command(["python", "ai/anomaly_detector.py"])
        run_command(["python", "decision/fusion_engine.py"])

def start_engine():
    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    pipeline_thread = threading.Thread(target=run_pipeline, daemon=True)

    sniffer_thread.start()
    pipeline_thread.start()

    print("[+] DPI Engine started in background")
