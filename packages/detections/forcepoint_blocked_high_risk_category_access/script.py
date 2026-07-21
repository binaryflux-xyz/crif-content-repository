def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    action = event.get("event_action")
    category = event.get("application_category") or ""

    categories = [
        "Malware",
        "Phishing",
        "Adult",
        "Proxy Avoidance",
        "Hacking",
        "Cryptomining",
        "Cryptocurrency",
    ]

    if action == "Blocked" and any(c.lower() in category.lower() for c in categories):
        return 0.75

    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " was blocked from accessing high-risk category '"
        + str(event_data.get("application_category", "unknown"))
        + "' at "
        + str(event_data.get("destination_hostname") or event_data.get("url") or "unknown")
        + "."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Initial Access (TA0001)"


def technique():
    return "Drive-by Compromise (T1189)"


def artifacts():
    return stats.collect(
        ["user_name", "source_ip", "event_action", "application_category", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
