def window():
    return "1h"


def groupby():
    return ["user_name"]


def automate():
    return False


def algorithm(event):
    user = event.get("user_name")
    if not user or user == "anonymous":
        return 0.0

    bytes_out = event.get("network_bytes_out")
    if not bytes_out:
        return 0.0

    res = stats.accumulate(["network_bytes_out"])
    bytes_list = res.get("network_bytes_out") or []
    total_bytes = sum(int(b or 0) for b in bytes_list)

    # 500MB = 500 * 1024 * 1024 = 524,288,000 bytes
    if total_bytes > 524288000:
        stats.dissipate(["network_bytes_out"])
        return 0.8

    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " has uploaded more than 500MB of data within 1 hour. "
        + "Last observed destination domain: "
        + str(event_data.get("destination_domain", "unknown"))
        + "."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Exfiltration (TA0010)"


def technique():
    return "Exfiltration Over Web Service (T1567)"


def artifacts():
    return stats.collect(
        ["user_name", "source_ip", "destination_domain", "network_bytes_out", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
