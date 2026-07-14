def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    category = event.get("application_category")

    if category == "Phishing":
        return 1.0
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " accessed a phishing website: "
        + str(
            event_data.get("destination_hostname")
            or event_data.get("destination_domain")
            or event_data.get("url")
        )
    )


def criticality():
    return "CRITICAL"


def tactic():
    return "Initial Access (TA0001)"


def technique():
    return "Drive-by Compromise (T1189)"


def artifacts():
    return stats.collect(["user_name", "destination_hostname", "url"])


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}

