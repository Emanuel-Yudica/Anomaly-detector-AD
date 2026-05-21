import csv
import os
import time
from datetime import datetime
import numpy as np
import redis

def feature_builder(training_mode: bool = True, vector_queue=None):

    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

    WINDOW_SIZE = 30
    CSV_FILENAME = "security_dataset.csv"
    
    # Global session counters
    global_total_events_processed = 0

    if training_mode:
        file_exists = os.path.exists(CSV_FILENAME)
        with open(CSV_FILENAME, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow([
                    "window_hour_minutes", "is_weekend", "failed_logins", "success_logins",
                    "total_ips", "total_users", "total_resources", "total_logon_types",
                    "total_auth_pkgs", "max_requests_per_ip", "average_requests",
                    "std_dev_requests", "new_ips"
                ])
                print(f"[*] Training Mode Active: Created '{CSV_FILENAME}' with headers.")
            else:
                print(f"[*] Training Mode Active: Found existing '{CSV_FILENAME}'. New data will be appended.")
    else:
        print("[*] Live Detection Mode Active: Feature Builder forwarding windows to P4 Evaluator Queue.")

    print("[*] Feature Builder synchronizing master clock...")
    now = time.time()
    wait_time = WINDOW_SIZE - (now % WINDOW_SIZE)
    time.sleep(wait_time)

    print(f"[*] Clock synchronized! Running in {'TRAINING' if training_mode else 'LIVE DETECTION'} mode.\n")
    
    try:
        while True:
            time.sleep(WINDOW_SIZE)

            current_ts = time.time()
            window_ts = int((current_ts // WINDOW_SIZE) * WINDOW_SIZE) - WINDOW_SIZE

            g_key = f"window:global:{window_ts}"
            ips_count_key = f"{g_key}:ips_counts"

            pipe = r.pipeline()
            pipe.hgetall(g_key)
            pipe.hgetall(ips_count_key)
            pipe.smembers(f"{g_key}:users")
            pipe.smembers(f"{g_key}:resources")
            pipe.smembers(f"{g_key}:logon_types")
            pipe.smembers(f"{g_key}:auth_pkgs")
            results = pipe.execute()

            metrics         = results[0]
            ips_with_counts = results[1]
            users           = results[2]
            resources       = results[3]
            logon_types     = results[4]
            auth_pkgs       = results[5]

            window_total_events = 0
            
            if not metrics:
                failed_logins = 0
                success_logins = 0
                is_weekend = 1 if datetime.now().weekday() in [5, 6] else 0
                total_ips = 0
                total_users = 0
                total_resources = 0
                total_logon_types = 0
                total_auth_pkgs = 0
                max_requests_per_ip = 0
                average_requests = 0.0
                std_dev_requests = 0.0
                new_ips = 0
            else:
                count_list = [int(count) for count in ips_with_counts.values()]
                window_total_events = sum(count_list)
                
                if len(count_list) > 1:
                    max_requests_per_ip = int(max(count_list))
                    average_requests    = float(np.mean(count_list))
                    std_dev_requests    = float(np.std(count_list))
                else:
                    max_requests_per_ip = int(max(count_list)) if count_list else 0
                    average_requests    = float(count_list[0]) if count_list else 0.0
                    std_dev_requests    = 0.0

                failed_logins     = int(metrics.get("failed_logins", 0))
                success_logins    = int(metrics.get("success_logins", 0))
                is_weekend        = int(metrics.get("is_weekend", 0))
                total_ips         = len(ips_with_counts)
                total_users       = len(users)
                total_resources   = len(resources)
                total_logon_types = len(logon_types)
                total_auth_pkgs   = len(auth_pkgs)
                new_ips           = int(metrics.get("new_ips", 0))

            global_total_events_processed += window_total_events

            dt_window = datetime.fromtimestamp(window_ts)
            window_hour_minutes = (dt_window.hour * 60) + dt_window.minute

            full_vector_dict = {
                "window_hour_minutes": window_hour_minutes,
                "is_weekend": is_weekend,
                "failed_logins": failed_logins,
                "success_logins": success_logins,
                "total_ips": total_ips,
                "total_users": total_users,
                "total_resources": total_resources,
                "total_logon_types": total_logon_types,
                "total_auth_pkgs": total_auth_pkgs,
                "max_requests_per_ip": max_requests_per_ip,
                "average_requests": average_requests,
                "std_dev_requests": std_dev_requests,
                "new_ips": new_ips
            }

            if training_mode:
              
                ai_vector = [full_vector_dict[col] for col in full_vector_dict.keys()]
                with open(CSV_FILENAME, mode="a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(ai_vector)
                current_screen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"{ai_vector} -> Appended to CSV +{current_screen_time}")
            
            else:
                payload = {
                    "vector": full_vector_dict,
                    "total_events": window_total_events,
                    "global_total": global_total_events_processed,
                    "users": list(users) if users else [],
                    "ips_with_counts": dict(ips_with_counts) if ips_with_counts else {}
                }
                
                if vector_queue is not None:
                    vector_queue.put(payload)
            
            if metrics:
                pipe_clear = r.pipeline()
                pipe_clear.delete(g_key, ips_count_key, f"{g_key}:users", f"{g_key}:resources", f"{g_key}:logon_types", f"{g_key}:auth_pkgs")
                pipe_clear.execute()

    except KeyboardInterrupt:
        print("[*] Feature Builder stopped.")