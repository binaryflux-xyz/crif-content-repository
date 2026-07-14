def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    file_name = (event.get("file_name") or "").lower()

    archive_extensions = (
        ".zip",
        ".rar",
        ".7z",
    )

    if file_name.endswith(archive_extensions):
        return 0.5
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " downloaded an archive file: "
        + str(event_data.get("file_name"))
        + " from "
        + str(
            event_data.get("destination_hostname")
            or event_data.get("destination_domain")
            or event_data.get("url")
        )
    )


def criticality():
    return "MEDIUM"


def tactic():
    return "Initial Access (TA0001)"


def technique():
    return "Drive-by Compromise (T1189)"


def artifacts():
    return stats.collect(
        ["user_name", "file_name", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}

