def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    domain = (event.get("destination_domain") or "").lower()
    host = (event.get("destination_hostname") or "").lower()
    url = (event.get("url") or "").lower()

    messaging_patterns = ["telegram", "discord", "slack", "whatsapp", "signal"]

    if any(m in domain or m in host or m in url for m in messaging_patterns):
        return 0.6
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " accessed messaging platform API/domain: "
        + str(event_data.get("destination_hostname") or event_data.get("url") or "unknown")
        + "."
    )


def criticality():
    return "MEDIUM"


def tactic():
    return "Command and Control (TA0011)"


def technique():
    return "Application Layer Protocol (T1071)"


def artifacts():
    return stats.collect(
        ["user_name", "source_ip", "destination_hostname", "destination_domain", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
