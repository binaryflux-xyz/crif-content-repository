def window():
    return "10m"


def groupby():
    return ["user_name"]


def automate():
    return False


def algorithm(event):
    action = event.get("event_action")
    user = event.get("user_name")

    if not user or user == "anonymous":
        return 0.0

    if action == "Blocked":
        if stats.count("user_blocked_requests") > 20:
            stats.resetcount("user_blocked_requests")
            return 0.8
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " triggered more than 20 blocked requests within 10 minutes from source IP "
        + str(event_data.get("source_ip", "unknown"))
        + "."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Proxy (T1090)"


def artifacts():
    return stats.collect(
        ["user_name", "source_ip", "event_action", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
