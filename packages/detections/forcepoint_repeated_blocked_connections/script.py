def window():
    return "5m"


def groupby():
    return ["source_ip"]


def automate():
    return False


def algorithm(event):
    action = event.get("event_action")

    if action == "Blocked":
        if stats.count("blocked_connections") >= 10:
            stats.resetcount("blocked_connections")
            return 0.75

    return 0.0


def context(event_data):
    return (
        "Multiple blocked connections detected from source IP "
        + str(event_data.get("source_ip", "unknown"))
        + " within 5 minutes. Last blocked host: "
        + str(event_data.get("destination_hostname") or event_data.get("url") or "unknown")
    )


def criticality():
    return "MEDIUM"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Proxy (T1090)"


def artifacts():
    return stats.collect(
        ["source_ip", "user_name", "destination_hostname", "url", "policy_name", "application_category"]
    )


def correlationArtifacts():
    return ["source_ip", "user_name"]


def entity(event):
    return {"derived": False, "value": event.get("source_ip"), "type": "ipaddress"}
