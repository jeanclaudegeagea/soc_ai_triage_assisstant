import re
from collections import Counter


def extract_metrics(logs: str):
    ips = Counter()
    events = Counter()
    timestamps = []

    for line in logs.splitlines():
        ip_match = re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", line)
        if ip_match:
            ips[ip_match.group()] += 1

        if "failed" in line.lower():
            events["failed"] += 1
        elif "success" in line.lower():
            events["success"] += 1
        else:
            events["other"] += 1

        time_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
        if time_match:
            timestamps.append(time_match.group())

    return {
        "top_ips": ips.most_common(10),
        "event_distribution": dict(events),
        "event_count": sum(events.values()),
        "timestamps": timestamps,
    }
