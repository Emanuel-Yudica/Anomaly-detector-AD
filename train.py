import os
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

def train_anomaly_detector():
    input_csv = "security_dataset.csv"
    model_output = "anomaly_detector.pkl"
    
    if not os.path.exists(input_csv):
        print(f"[!] Error: '{input_csv}' not found.")
        return

    df = pd.read_csv(input_csv)
    
    total_events_per_window = df['failed_logins'] + df['success_logins']
    historical_max_events = int(total_events_per_window.max())
    
    volume_threshold = int(historical_max_events * 1.5)
    if volume_threshold < 20: 
        volume_threshold = 20 # Change this if the ad is bigger
        
    if df['is_weekend'].nunique() == 1:
        features_to_use = [col for col in df.columns if col != 'is_weekend']
    else:
        features_to_use = list(df.columns)

    X_train = df[features_to_use].copy()
    numeric_cols = [c for c in features_to_use if c != 'is_weekend']
    X_train[numeric_cols] = np.log1p(X_train[numeric_cols])

    model = IsolationForest(
        n_estimators=150,
        contamination=0.08,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train)
    
    # save pkl file
    model_artifact = {
        "model": model,
        "features": features_to_use,
        "volume_threshold": volume_threshold
    }
    
    joblib.dump(model_artifact, model_output)
    
    print("-" * 60)
    print(f"[+] SUCCESS: Model trained with Hybrid Security Safeguards!")
    print(f"[+] Historical Max Window Events: {historical_max_events}")
    print(f"[+] Dynamic Volume Threshold Set to: {volume_threshold} events/window")
    print("-" * 60)

if __name__ == "__main__":
    train_anomaly_detector()