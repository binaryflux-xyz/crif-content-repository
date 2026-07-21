def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    bytes_out = event.get("network_bytes_out")

    # Check if outbound bytes exceed 50MB (50,000,000 bytes)
    if bytes_out and bytes_out > 50000000:
        return 0.75

    return 0.0


def context(event_data):
    return (
        "Large data upload detected via Forcepoint Proxy. User "
        + str(event_data.get("user_name", "unknown"))
        + " transferred " + str(event_data.get("network_bytes_out", 0)) + " bytes outbound"
        + " to " + str(event_data.get("destination_hostname") or event_data.get("destination_domain") or "unknown")
        + " using policy " + str(event_data.get("policy_name", "N/A"))
    )


def criticality():
    return "HIGH"


def tactic():
    return "Exfiltration (TA0010)"


def technique():
    return "Exfiltration Over Web Service (T1567)"


def artifacts():
    return stats.collect(
        ["user_name", "source_ip", "destination_hostname", "url", "network_bytes_out", "policy_name"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
