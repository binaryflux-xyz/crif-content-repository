def window():
    return "10m"


def groupby():
    return ["user_name", "destination_domain"]


def automate():
    return False


def algorithm(event):
    user = event.get("user_name")
    domain = event.get("destination_domain")
    action = event.get("event_action")

    if not user or user == "anonymous" or not domain:
        return 0.0

    if action == "Blocked":
        if stats.count("blocked_domain_attempts") >= 4:
            stats.resetcount("blocked_domain_attempts")
            return 0.75
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " repeatedly attempted to access blocked domain '"
        + str(event_data.get("destination_domain", "unknown"))
        + "' (at least 4 times within 10 minutes)."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Proxy (T1090)"


def artifacts():
    return stats.collect(
        ["user_name", "destination_domain", "source_ip", "event_action", "url"]
    )


def correlationArtifacts():
    return ["user_name", "destination_domain"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
