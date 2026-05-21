import win32evtlog
import win32event
import xml.etree.ElementTree as ET
import socket
from datetime import datetime

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
RESOURCE = socket.gethostname()

EVENT_SUCCESS = [4624, 4648, 4672, 4776]


def get_field(root, name: str) -> str:
    el = root.find(f".//{{{NS}}}Data[@Name='{name}']")
    return el.text if el is not None and el.text else "-"


def parse_event(xml_str: str) -> dict:
    root = ET.fromstring(xml_str)
    event_id = int(root.findtext(f".//{{{NS}}}EventID"))
    raw_timestamp = root.find(f".//{{{NS}}}TimeCreated").get("SystemTime")
    timestamp = raw_timestamp[:19].replace("T", " ")

    # Convert temporal string to datetime object for analytical operations
    dt_obj = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    
    # 1. Calculate the day's time in minutes (e.g., 02:30 AM = (2 * 60) + 30 = 150)
    hour_minutes = (dt_obj.hour * 60) + dt_obj.minute
    
    # 2. Detect if it falls on a weekend (weekday() returns 5 for Saturday and 6 for Sunday)
    is_weekend = 1 if dt_obj.weekday() in [5, 6] else 0
    # ----------------------------------------

    return {
        "event_id":         event_id,
        "timestamp":        timestamp,
        "hour_minutes":     hour_minutes,     # Numeric feature field (0 - 1439)
        "is_weekend":       is_weekend,       # Binary feature field (0 or 1)
        "username":         get_field(root, "TargetUserName"),
        "ip":               get_field(root, "IpAddress"),
        "resource":         RESOURCE,
        "success":          event_id in EVENT_SUCCESS,
        "logon_type":       get_field(root, "LogonType"),
        "auth_pkg":         get_field(root, "AuthenticationPackageName"),
        "workstation":      get_field(root, "WorkstationName"),
        "status":           get_field(root, "Status"),
        "sub_status":       get_field(root, "SubStatus"),
        "service":          get_field(root, "ServiceName"),
    }


def monitor_events(q):
    flags  = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    handle = win32evtlog.OpenEventLog("localhost", "Security")

    # ── STEP 1: Flush historical backlog ──────────────────────
    print("[*] Flushing previous log backlog...")
    while True:
        events = win32evtlog.ReadEventLog(handle, flags, 0)
        if not events:
            break
    print("[*] Backlog flushed successfully. Monitoring new events live...")

    # ── STEP 2: Register Win32 Change Notification Event ──────
    h_event = win32event.CreateEvent(None, 0, 0, None)
    win32evtlog.NotifyChangeEventLog(handle, h_event)

    try:
        while True:
            # Block until a new log event is posted (1-second timeout check)
            result = win32event.WaitForSingleObject(h_event, 1000)

            if result == win32event.WAIT_OBJECT_0:
                while True:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break

                    for ev in events:
                        # Extract the Raw XML structure via EvtRender
                        try:
                            xml_handle = win32evtlog.EvtQuery(
                                "Security",
                                win32evtlog.EvtQueryChannelPath,
                                f"*[System[EventRecordID={ev.RecordNumber}]]"
                            )
                            results = win32evtlog.EvtNext(xml_handle, 1)
                            if results:
                                xml_str = win32evtlog.EvtRender(
                                    results[0],
                                    win32evtlog.EvtRenderEventXml
                                )
                                event = parse_event(xml_str)
                                # print(f"[P1] {event['event_id']} | "
                                #       f"{event['username']} | {event['ip']}")
                                q.put(event)
                        except Exception as e:
                            print(f"[*] Error parsing event structure: {e}")
                            continue

                win32event.ResetEvent(h_event)

    except KeyboardInterrupt:
        print("\n[*] Log monitoring terminated manually.")
    finally:
        win32evtlog.CloseEventLog(handle)