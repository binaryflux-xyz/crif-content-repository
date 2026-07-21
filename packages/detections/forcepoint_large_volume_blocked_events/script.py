def window():
    return "5m"


def groupby():
    return ["source_ip"]


def automate():
    return False


def algorithm(event):
    action = event.get("event_action")
    source_ip = event.get("source_ip")

    if not source_ip:
        return 0.0

    if action == "Blocked":
        if stats.count("total_blocked_events") >= 1000:
            stats.resetcount("total_blocked_events")
            return 0.9
    return 0.0


def context(event_data):
    return (
        "Source IP "
        + str(event_data.get("source_ip", "unknown"))
        + " generated at least 1000 blocked proxy events within a 5-minute window."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Proxy (T1090)"


def artifacts():
    return stats.collect(
        ["source_ip", "user_name", "event_action", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["source_ip", "user_name"]


def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
