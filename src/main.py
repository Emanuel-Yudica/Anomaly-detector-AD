import os
from multiprocessing import Process, Queue
import redis

# Module imports
from src.event_reader import monitor_events
from src.feature_builder import feature_builder
from src.redis_window import register_event_in_redis

#----------------------------------------------------------------------------------------------------------------------
# CONFIGURATION SWITCH
# True  -> Collects data and saves it into 'security_dataset.csv'(you must run this if it is your first time running).
# False -> Switches to live AI Anomaly Detection mode
TRAINING_MODE = False
#----------------------------------------------------------------------------------------------------------------------


REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))


def preload_historical_ips():

    r_local = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    historical_keys = "global:known_ips"
    file_path = "known_ips.txt"

    if os.path.exists(file_path):
        ips_to_load = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips_to_load.append(line)

        if ips_to_load:
            r_local.sadd(historical_keys, *ips_to_load)
            print(
                f"[*] Success: Preloaded {len(ips_to_load)} IPs from '{file_path}' into Redis."
            )
    else:
        print(
            f"[!] Warning: '{file_path}' file not found. Historical record will start empty."
        )


def redis_writer_worker(q: Queue):
    r_local = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    try:
        while True:
            event = q.get()
            register_event_in_redis(r_local, event)
    except KeyboardInterrupt:
        print("[*] Redis writer worker stopped")

if __name__ == "__main__":
    print("[*] Starting Anomaly Detection System...")
    print(
        f"[*] SYSTEM MODE: {'[DATA COLLECTION / TRAINING]' if TRAINING_MODE else '[LIVE INTRUSION DETECTION]'}"
    )
    preload_historical_ips()

    q = Queue()

    procs = [
        # P1: Monitors Windows Logs in real time
        Process(target=monitor_events, args=(q,)),
        # P2: Processes the queue and registers metrics into Redis
        Process(target=redis_writer_worker, args=(q,)),
        # P3: Analytical module (Passes the training configuration flag)
        Process(target=feature_builder, args=(TRAINING_MODE,)),
    ]

    for p in procs:
        p.start()

    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        print("\nStopping program")