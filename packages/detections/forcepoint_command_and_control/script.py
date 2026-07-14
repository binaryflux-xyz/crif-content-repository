def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    category = event.get("application_category")

    if category == "Command and Control":
        return 1.0
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " established connection to Command and Control domain: "
        + str(
            event_data.get("destination_hostname")
            or event_data.get("destination_domain")
            or event_data.get("url")
        )
    )


def criticality():
    return "CRITICAL"


def tactic():
    return "Command and Control (TA0011)"


def technique():
    return "Web Protocols (T1071/001)"


def artifacts():
    return stats.collect(["user_name", "destination_hostname", "url"])


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}

