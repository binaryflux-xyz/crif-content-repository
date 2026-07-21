def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    file_name = (event.get("file_name") or "").lower()

    exec_extensions = (
        ".exe",
        ".dll",
        ".ps1",
        ".bat",
        ".vbs",
        ".jar",
        ".msi",
        ".iso",
        ".scr",
        ".zip",
        ".hta",
        ".js",
    )

    if file_name.endswith(exec_extensions):
        return 0.5
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " downloaded an executable file: "
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
    return "Execution (TA0002)"


def technique():
    return "User Execution (T1204)"


def artifacts():
    return stats.collect(
        ["user_name", "file_name", "destination_hostname", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}

