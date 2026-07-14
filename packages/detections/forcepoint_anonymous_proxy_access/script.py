def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    category = event.get("application_category")

    proxy_categories = [
        "Proxy Avoidance",
        "Anonymous Proxy",
        "VPN",
        "Circumvention",
    ]

    if category in proxy_categories:
        return 0.5
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " accessed an anonymous proxy or VPN service: "
        + str(
            event_data.get("destination_hostname")
            or event_data.get("destination_domain")
            or event_data.get("url")
        )
    )


def criticality():
    return "MEDIUM"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Proxy (T1090)"


def artifacts():
    return stats.collect(["user_name", "destination_hostname", "url"])


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}

