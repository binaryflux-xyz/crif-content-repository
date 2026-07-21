def window():
    return "30m"


def groupby():
    return ["user_name"]


def automate():
    return False


def algorithm(event):
    user = event.get("user_name")
    action = event.get("event_action")
    category = event.get("application_category")

    if not user or user == "anonymous" or not category:
        return 0.0

    if action == "Blocked":
        res = stats.accumulate(["application_category", "event_action"])
        cats = res.get("application_category") or []
        actions = res.get("event_action") or []

        # Filter categories where the event was blocked
        blocked_cats = [
            cats[i] for i in range(min(len(cats), len(actions)))
            if actions[i] == "Blocked"
        ]
        unique_cats = set(blocked_cats)

        if len(unique_cats) >= 5:
            stats.dissipate(["application_category", "event_action"])
            return 0.8

    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " was blocked across 5 or more distinct web categories within a 30-minute window."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Proxy (T1090)"


def artifacts():
    return stats.collect(
        ["user_name", "source_ip", "event_action", "application_category", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
