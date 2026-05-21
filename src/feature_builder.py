import csv
import os
import time
from datetime import datetime
import numpy as np
import redis
import joblib
import pandas as pd

def feature_builder(training_mode: bool = True):
    """Calculates feature vectors every 30s.
    
    Training Mode (True): Appends vectors to 'security_dataset.csv'.
    Detection Mode (False): Loads the trained ML model, evaluates for anomalies,
                            tracks global session statistics, and prints detailed
                            incident forensics when an anomaly occurs.
    """
    r = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)
    WINDOW_SIZE = 30
    CSV_FILENAME = "security_dataset.csv"
    MODEL_PATH = "anomaly_detector.pkl"
    
    # Global session counters
    global_total_events_processed = 0
    global_anomalies_detected = 0

    model = None
    model_features = []
    volume_threshold = 20  # Safe default fallback

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
        # LIVE DETECTION MODE: Load the AI Brain
        print("[*] Live Detection Mode Active: Loading ML Model...")
        if not os.path.exists(MODEL_PATH):
            print(f"[!] CRITICAL ERROR: Model artifact '{MODEL_PATH}' not found!")
            print("[!] You must run 'python train.py' successfully before switching to Detection Mode.")
            return
        
        # Load the trained Isolation Forest package
        artifact = joblib.load(MODEL_PATH)
        model = artifact["model"]
        model_features = artifact["features"]
        volume_threshold = artifact["volume_threshold"]
        print(f"[+] AI Brain loaded. Volume Safety Limit: {volume_threshold} events/window.")

    print("[*] Feature Builder synchronizing master clock...")
    now = time.time()
    wait_time = WINDOW_SIZE - (now % WINDOW_SIZE)
    time.sleep(wait_time)

    print(f"[*] P3: Clock synchronized! Running in {'TRAINING' if training_mode else 'LIVE DETECTION'} mode.\n")
    
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

            # Calculate local tracking variables for total window events
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

            # Update our global running metrics counter
            global_total_events_processed += window_total_events

            dt_window = datetime.fromtimestamp(window_ts)
            window_hour_minutes = (dt_window.hour * 60) + dt_window.minute

            # 13-feature full map dictionary
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
                # Mode A: Save strict array sequence to CSV
                ai_vector = [full_vector_dict[col] for col in full_vector_dict.keys()]
                with open(CSV_FILENAME, mode="a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(ai_vector)
                current_screen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"{ai_vector} -> Appended to CSV +{current_screen_time}")
            else:
                # Mode B: HYBRID LIVE DETECTION ENGINE
                current_screen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                if window_total_events == 0:
                    print(f"[*] [{current_screen_time}] Window Quiet  | Events in block: 0   | Total Session Events: {global_total_events_processed} | Total Anomalies: {global_anomalies_detected}")
                
                else:
                    raw_vector = [full_vector_dict[col] for col in model_features]
                    
                    scaled_vector = []
                    for col, val in zip(model_features, raw_vector):
                        if col == "is_weekend":
                            scaled_vector.append(val)
                        else:
                            scaled_vector.append(np.log1p(val))

                    input_df = pd.DataFrame([scaled_vector], columns=model_features)
                    
                    ai_prediction = model.predict(input_df)[0]
                    volume_breached = window_total_events > volume_threshold

                    if ai_prediction == -1 or volume_breached:
                        global_anomalies_detected += 1
                        
                        print("\n" + "🚨" * 25)
                        print(f"⚠️  [SECURITY ANOMALY DETECTED] - {current_screen_time}")
                        print("🚨" * 25)
                        print(f"🔬 Trigger Reason: {'[VOLUMETRIC BLAST ALERT]' if volume_breached else '[AI BEHAVIORAL ANOMALY]'}")
                        print(f"📊 Incident Impact Indicators:")
                        print(f"   ↳ Events in Window: {window_total_events} (Max Allowed: {volume_threshold})")
                        print(f"   ↳ Failed Logins: {failed_logins} | Success Logins: {success_logins}")
                        print(f"   ↳ Max Requests per IP: {max_requests_per_ip}")
                        print(f"👤 Compromised Elements Forensics:")
                        print(f"   ↳ Target Usernames: {list(users) if users else 'None'}")
                        print(f"   ↳ Network IPs Involved: {dict(sorted(ips_with_counts.items(), key=lambda item: int(item[1]), reverse=True)) if ips_with_counts else 'None'}")
                        print(f"📈 SESSION STATS: Total Log Events: {global_total_events_processed} | Cumulative Anomalies: {global_anomalies_detected}")
                        print("=" * 60 + "\n")
                    else:
                        print(f"[*] [{current_screen_time}] Window Normal | Events in block: {window_total_events} | Total Session Events: {global_total_events_processed} | Total Anomalies: {global_anomalies_detected}")
            
            # Atomic memory purge sequence from Redis RAM
            if metrics:
                pipe_clear = r.pipeline()
                pipe_clear.delete(g_key, ips_count_key, f"{g_key}:users", f"{g_key}:resources", f"{g_key}:logon_types", f"{g_key}:auth_pkgs")
                pipe_clear.execute()

    except KeyboardInterrupt:
        print("[*] Feature Builder stopped.")