from datetime import datetime, timezone
import redis

# TTL for individual analytical windows (30 seconds + safety margin)
WINDOW_TTL = 30

def get_window_ts(timestamp_str: str) -> int:
    """Converts a Windows UTC timestamp into a 30-second block in local time."""
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except ValueError:
        dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    
    # If no timezone info is present, assume UTC (native to Windows Event Logs)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    # Convert to the local timezone of the host machine running the script
    ts_local = dt.astimezone().timestamp()
    return int(ts_local // 30) * 30


def register_event_in_redis(r: redis.Redis, event: dict):
    """Structures event variables into Redis Hashes and Sets."""
    raw_ip = event["ip"].strip()
    username = event["username"]
    resource = event["resource"]
    success = event["success"]
    logon_type = event["logon_type"]
    auth_pkg = event["auth_pkg"]
    is_weekend = event["is_weekend"]
    window_ts = get_window_ts(event["timestamp"])

    # Basic normalization for local host IP values
    if not raw_ip or raw_ip in ["-", "::1", "127.0.0.1", "N/A"]:
        normalized_ip = "LOCAL_HOST"
    else:
        normalized_ip = raw_ip

    # Dynamic keys for the active window block
    g_key = f"window:global:{window_ts}"
    timer_key = f"timer:{window_ts}"
    ips_count_key = f"{g_key}:ips_counts"
    
    # Key for the permanent historical database set
    historical_ips_key = "global:known_ips"
    
    # --- NEW IP TRACKING LOGIC ---
    is_known = r.sismember(historical_ips_key, normalized_ip)
    is_new_ip = 0
    
    if not is_known:
        is_new_ip = 1
        # Auto-add immediately so it doesn't flag as new on the next request
        r.sadd(historical_ips_key, normalized_ip)
    # -----------------------------

    pipe = r.pipeline()

    # Login outcome counters
    if success:
        pipe.hincrby(g_key, "success_logins", 1)
    else:
        pipe.hincrby(g_key, "failed_logins", 1)

    pipe.hset(g_key, "is_weekend", is_weekend)
    
    # If the IP is entirely new, increment its specialized feature counter
    if is_new_ip:
        pipe.hincrby(g_key, "new_ips", 1)

    # Track unique elements and request distributions
    pipe.hincrby(ips_count_key, normalized_ip, 1)
    pipe.sadd(f"{g_key}:users", username)
    pipe.sadd(f"{g_key}:resources", resource)
    pipe.sadd(f"{g_key}:logon_types", logon_type)
    pipe.sadd(f"{g_key}:auth_pkgs", auth_pkg)

    # Set the window execution trigger tracker
    pipe.set(timer_key, "active", ex=WINDOW_TTL, nx=True)

    # Configure structural expiration rules to prevent Redis memory bloat
    EXTRA_DURATION = 60  # Gives the Feature Builder a buffer window to safely extract data
    pipe.expire(g_key, WINDOW_TTL + EXTRA_DURATION)
    pipe.expire(ips_count_key, WINDOW_TTL + EXTRA_DURATION)
    pipe.expire(f"{g_key}:users", WINDOW_TTL + EXTRA_DURATION)
    pipe.expire(f"{g_key}:resources", WINDOW_TTL + EXTRA_DURATION)
    pipe.expire(f"{g_key}:logon_types", WINDOW_TTL + EXTRA_DURATION)
    pipe.expire(f"{g_key}:auth_pkgs", WINDOW_TTL + EXTRA_DURATION)

    pipe.execute()