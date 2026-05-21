# Anomaly Detector for Active Directory

This tool detects security and behavioral anomalies within an Active Directory environment in real-time.

### 🛡️ Brute Force Detection Mechanisms

The system employs a **dual-layer protection matrix** to intercept both aggressive automated flooding and stealthy, slow-paced authentication attacks.

#### 1. Volumetric Layer (The $1.5\times$ Safety Net)
During the training phase, the system automatically benchmarks the historical peak of your network activity and establishes a hard cap:

$$\text{Volume Threshold} = \max(\text{window total events}) \times 1.5$$

* **Target:** Noisy, automated high-velocity brute force (e.g., Hydra, Medusa).
* **Behavior:** If a 30-second window exceeds this limit, **Process 4 triggers an instant alert**, bypassing the AI evaluation to save computing power and guarantee immediate notification.

#### 2. Behavioral Layer (Isolation Forest Routine Profiling)
Looks for **unfamiliar patterns**. By training on a full week of data, the Isolation Forest learns the "heartbeat" of the system (e.g., standard working hours, known admin IPs, regular user activity).

* **Target:** Lateral movement, compromised credentials, and out-of-hours insider threats.
* **Behavior:** If a window contains perfectly low traffic volume but introduces **anomalous features**—such as an administrator logging in at 3:00 AM on a Sunday, or activity originating from a completely new IP address—the AI isolates this vector. Since this coordinate doesn't fit the historical "cloud" of normal data, the model returns a `-1` score.

Here is an example of the decision tree of the ML

![Decision tree](https://github.com/Emanuel-Yudica/Anomaly-detector-AD/blob/dev/model_decision_tree_example.png)


| Detection Type | Volumetric Rule ($1.5\times$) | Isolation Forest (AI) | Trigger Example |
| :--- | :---: | :---: | :--- |
| **Volumetric Flood** | 🚨 Breached | — (Bypassed) | 2,000 requests in 30 seconds. |
| **Out-of-Routine Activity** | ✅ Safe | 🚨 Isolated (`-1`) | 1 single login at 4:00 AM from a new IP. |

### ⚠️ Disclaimer & Best Practices

To ensure high accuracy and minimize false positives, it is highly recommended to run the training mode for **at least one full week (7 consecutive days)**. 
* This allows the model to learn the baseline difference between high-volume weekdays and quieter weekends.
* Training the model for less than a week—or omitting weekend data—will result in a high rate of false positives during production.
* There is a [known_ips.txt](known_ips.txt) file for having white-listed directions. You must put all ips that can interact with the system in order to detect an unknown ip.

# 🚀Setup

To ensure proper communication with the Windows Event Log API (`pywin32`) and Redis, the terminal **must be launched as Administrator**, and the **Redis Server must be active**.

---

### 1️⃣ Initial Setup (First-Time Only)

Open Windows Terminal (`cmd` or `PowerShell`) as **Administrator**, navigate to your project's root directory (`AD-HIDS/`), and execute the following commands in order:

1. Create a Python virtual environment to isolate dependencies and activate
```bash
# A. Create a Python virtual environment to isolate dependencies and activate
python3 -m venv venv
.\venv\Scripts\Activate.ps1 #powershell
.\venv\Scripts\activate.bat #cmd
```
2. Upgrade pip and install all required framework dependencies
```bash

python3 -m pip install --upgrade pip
pip install -r requirements.txt
```
3. Collect Baseline Data (Run with TRAINING_MODE = True in main.py)

Let this run to populate your security_dataset.csv file, then stop it with Ctrl+C
```bash
python3 -m src.main.py
```
4. Train the Isolation Forest model and generate the .pkl brain file
```bash
python3 src/train.py
```
## 🛡️ Production Running Guide (Trained Model)

Use this section for daily monitoring once you have already populated your `known_ips.txt` whitelist and successfully generated the `anomaly_detector.pkl` model file.

### Prerequisites
* Ensure your **Redis Server** is running (`redis-cli ping` returns `PONG`).
* Terminal must be opened as **Administrator** to allow the pipeline to hook into the Windows Event Log API.
* Make sure the global flag inside `main.py` is set to production mode:

```python
 TRAINING_MODE=True
 ```
* Run virtual env
```python
 .\venv\Scripts\Activate.ps1
 ```
* Execute main
```python
python3 -m src.main
```

  
# Architecture
![Architecture](https://github.com/Emanuel-Yudica/Anomaly-detection-AD/blob/dev/architecture.jpg)
