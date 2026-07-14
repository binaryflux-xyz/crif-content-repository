def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    category = event.get("application_category") or ""
    domain = (event.get("destination_domain") or "").lower()
    host = (event.get("destination_hostname") or "").lower()

    cloud_categories = [
        "Cloud Storage",
        "Google Drive",
        "Dropbox",
        "OneDrive",
        "Mega",
        "Box",
        "WeTransfer",
    ]
    cloud_domains = [
        "drive.google.com",
        "dropbox.com",
        "onedrive.live.com",
        "mega.nz",
        "box.com",
        "wetransfer.com",
    ]

    is_cloud_category = category in cloud_categories
    is_cloud_domain = any(d in domain or d in host for d in cloud_domains)

    if is_cloud_category or is_cloud_domain:
        return 0.75
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " uploaded or sent data to cloud storage destination: "
        + str(
            event_data.get("destination_hostname")
            or event_data.get("destination_domain")
            or event_data.get("url")
        )
    )


def criticality():
    return "HIGH"


def tactic():
    return "Exfiltration (TA0010)"


def technique():
    return "Exfiltration Over Web Service (T1567)"


def artifacts():
    return stats.collect(
        ["user_name", "destination_hostname", "application_category", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}

