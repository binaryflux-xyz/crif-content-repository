def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    ua = (event.get("useragent") or "").lower()

    rare_agents = ["curl", "python", "wget", "powershell", "nmap", "sqlmap"]

    if any(ra in ua for ra in rare_agents):
        return 0.7

    return 0.0


def context(event_data):
    return (
        "Non-browser user agent '"
        + str(event_data.get("useragent", "unknown"))
        + "' was observed in request from source IP "
        + str(event_data.get("source_ip", "unknown"))
        + " to "
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
        ["user_name", "source_ip", "useragent", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
