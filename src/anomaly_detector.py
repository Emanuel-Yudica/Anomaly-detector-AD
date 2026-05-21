import os
from datetime import datetime
import numpy as np
import pandas as pd
import joblib

def ml_evaluator_worker(vector_queue):
   
    MODEL_PATH = "anomaly_detector.pkl"
    print("[*] AI Live Evaluator Process started.")
    
    if not os.path.exists(MODEL_PATH):
        print(f"[!] CRITICAL ERROR : Model '{MODEL_PATH}' not found!")
        return
        
    artifact = joblib.load(MODEL_PATH)
    model = artifact["model"]
    model_features = artifact["features"]
    volume_threshold = artifact["volume_threshold"]
    
    print(f"[+] AI Brain active and listening to vector_queue...")
    global_anomalies_detected = 0

    try:
        while True:

            task_data = vector_queue.get()
            
            full_vector_dict    = task_data["vector"]
            window_total_events = task_data["total_events"]
            global_total_events = task_data["global_total"]
            users               = task_data["users"]
            ips_with_counts     = task_data["ips_with_counts"]
            
            current_screen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if window_total_events == 0:
                print(f"[*] [{current_screen_time}] Window Quiet  | Events: 0 | Session: {global_total_events} | Anomalies: {global_anomalies_detected}")
                continue

            # Escalar vector para la IA
            raw_vector = [full_vector_dict[col] for col in model_features]
            scaled_vector = [val if col == "is_weekend" else np.log1p(val) for col, val in zip(model_features, raw_vector)]

            input_df = pd.DataFrame([scaled_vector], columns=model_features)
            
            ai_prediction = model.predict(input_df)[0]
            volume_breached = window_total_events > volume_threshold

            if ai_prediction == -1 or volume_breached:
                global_anomalies_detected += 1
                print("\n" + "🚨" * 25)
                print(f"⚠️  [SECURITY ANOMALY DETECTED] - {current_screen_time}")
                print("🚨" * 25)
                print(f"🔬 Trigger Reason: {'[VOLUMETRIC BLAST ALERT]' if volume_breached else '[ML BEHAVIORAL ANOMALY]'}")
                print(f"👤 Target Usernames: {list(users) if users else 'None'}")
                print(f"   ↳ Network IPs: {dict(sorted(ips_with_counts.items(), key=lambda x: int(x[1]), reverse=True)) if ips_with_counts else 'None'}")
                print("-" * 50 + "\n")
            else:
                print(f"[*] [{current_screen_time}] Window Normal | Window Events: {window_total_events} | Total events : {global_total_events} | Anomalies: {global_anomalies_detected}")

    except KeyboardInterrupt:
        pass