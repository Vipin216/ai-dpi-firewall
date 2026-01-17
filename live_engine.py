import subprocess
import threading
import time
import os
import signal
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def run(cmd):
    return subprocess.run(
        cmd,
        cwd=BASE_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def start_sniffer():
    print("[+] Starting packet sniffer...")
    subprocess.Popen(
        ["python", "capture/sniffer.py"],
        cwd=BASE_DIR
    )

def analysis_loop():
    while True:
        print("[*] Running analysis pipeline...")

        run(["python", "features/feature_extractor.py"])
        print("[+] Features updated")

        run(["python", "detection/rule_engine.py"])
        print("[+] Rules evaluated")

        run(["python", "ai/anomaly_detector.py"])
        print("[+] AI anomaly scores updated")

        run(["python", "decision/fusion_engine.py"])
        print("[+] Final decisions updated")

        print("[*] Sleeping for 10 seconds...\n")
        time.sleep(10)

def shutdown_handler(sig, frame):
    print("\n[!] Shutting down DPI engine cleanly...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    print("===================================")
    print(" AI DPI FIREWALL — LIVE ENGINE START ")
    print("===================================\n")

    start_sniffer()

    analysis_thread = threading.Thread(
        target=analysis_loop,
        daemon=True
    )
    analysis_thread.start()

    while True:
        time.sleep(1)
