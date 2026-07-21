def window():
    return None


def groupby():
    return None


def automate():
    return False


def algorithm(event):
    domain = (event.get("destination_domain") or "").lower()
    host = (event.get("destination_hostname") or "").lower()

    doh_domains = [
        "cloudflare-dns.com",
        "dns.google",
        "quad9.net",
        "quad9.com",
        "dns.quad9.net",
        "mozilla.cloudflare-dns.com"
    ]

    if any(d in domain or d in host for d in doh_domains):
        return 0.8
    return 0.0


def context(event_data):
    return (
        "User "
        + str(event_data.get("user_name", "unknown"))
        + " accessed a known DNS over HTTPS (DoH) resolver domain: "
        + str(event_data.get("destination_hostname") or event_data.get("url") or "unknown")
        + "."
    )


def criticality():
    return "HIGH"


def tactic():
    return "Defense Evasion (TA0005)"


def technique():
    return "Protocol Tunneling (T1572)"


def artifacts():
    return stats.collect(
        ["user_name", "source_ip", "destination_hostname", "destination_domain", "url"]
    )


def correlationArtifacts():
    return ["user_name", "source_ip"]


def entity(event):
    return {"derived": False, "value": event.get("user_name"), "type": "user"}
