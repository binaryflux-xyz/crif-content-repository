def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    threat_name = event.get("threat_name")
    threat_category = event.get("threat_category")
    rule_name = event.get("rule_name")

    if (threat_name and threat_name != "None") or \
       (threat_category and threat_category != "None") or \
       (rule_name and rule_name != "None"):
        return 1.0

    return 0.0


def context(event_data):
    return (
        "Forcepoint proxy detected a threat. "
        + "Threat Name: " + str(event_data.get("threat_name", "N/A"))
        + ", Category: " + str(event_data.get("threat_category", "N/A"))
        + ", Rule: " + str(event_data.get("rule_name", "N/A"))
        + " for user: " + str(event_data.get("user_name", "unknown"))
        + " requesting: " + str(event_data.get("destination_hostname") or event_data.get("url") or "unknown")
    )


def criticality():
    return "HIGH"


def tactic():
    return "Initial Access (TA0001)"


def technique():
    return "Drive-by Compromise (T1189)"


def artifacts():
    return stats.collect(
        ["user_name", "threat_name", "threat_category", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
