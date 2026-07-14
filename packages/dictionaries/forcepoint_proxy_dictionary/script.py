import calendar
from datetime import datetime, timedelta


def init(event):
    return "initialization completed"


def criteria(meta):
    return (
        meta.get('provider') == 'Forcepoint' and
        meta.get('group') == 'Forcepoint Proxy' and
        meta.get('type') == 'Web Security'
    )


def drop(event):
    return False


def timestamp(event):
    ts = event.get("deviceReceiptTime") or event.get("startTime") or event.get("endTime")

    if not ts:
        return None

    IST_OFFSET = timedelta(hours=5, minutes=30)

    try:
        dt = datetime.strptime(ts, "%Y/%m/%d %H:%M:%S IST")
        return int(calendar.timegm((dt - IST_OFFSET).timetuple()) * 1000)
    except:
        pass

    try:
        dt = datetime.strptime(ts, "%Y/%m/%d %H:%M:%S")
        return int(calendar.timegm((dt - IST_OFFSET).timetuple()) * 1000)
    except:
        return None


def message(event):
    parts = []

    action = event.get("deviceAction") or event.get("categoryOutcome")
    user = event.get("sourceUserName")
    client = event.get("requestClientApplication")
    url = event.get("requestContext")
    host = event.get("destinationHostName")
    domain = event.get("deviceCustomString5")
    category = event.get("categoryDeviceGroup")
    policy = event.get("deviceCustomString3")
    country = event.get("destinationGeoCountryCode")

    if action:
        parts.append("Web request %s" % action.lower())
    else:
        parts.append("Web request observed")

    if user:
        parts.append("by user '%s'" % user)

    if client:
        parts.append("using '%s'" % client)

    if host:
        parts.append("to host '%s'" % host)
    elif domain:
        parts.append("to domain '%s'" % domain)

    if url:
        parts.append("(%s)" % url)

    if category:
        parts.append("categorized as '%s'" % category)

    if policy:
        parts.append("under policy '%s'" % policy)

    if country and country != "Unknown":
        parts.append("destination country '%s'" % country)

    return " ".join(parts) + "."


def dictionary(event):
    out = {}

    # Event Information
    if event.get("name"):
        out["event_name"] = event.get("name")

    if event.get("deviceAction") or event.get("categoryOutcome"):
        out["event_action"] = event.get("deviceAction") or event.get("categoryOutcome")

    if event.get("deviceSeverity") or event.get("agentSeverity"):
        out["event_severity"] = event.get("deviceSeverity") or event.get("agentSeverity")

    # User
    if event.get("sourceUserName"):
        out["user_name"] = event.get("sourceUserName")

    # Source
    if event.get("agentAddress"):
        out["source_ip"] = event.get("agentAddress")

    if event.get("agentHostName"):
        out["source_hostname"] = event.get("agentHostName")

    # Destination
    if event.get("destinationHostName"):
        out["destination_hostname"] = event.get("destinationHostName")

    if event.get("destinationAddress"):
        out["destination_ip"] = event.get("destinationAddress")

    if event.get("destinationGeoCountryCode"):
        out["destination_country"] = event.get("destinationGeoCountryCode")

    # URL / Web Request
    if event.get("requestContext"):
        out["url"] = event.get("requestContext")

    if event.get("requestClientApplication"):
        out["applicationname"] = event.get("requestClientApplication")

    # Web Resource
    if event.get("fileName"):
        out["file_name"] = event.get("fileName")

    if event.get("filePath"):
        out["file_path"] = event.get("filePath")

    # Policy
    # if event.get("deviceCustomString2"):
    #     out["policy_group"] = event.get("deviceCustomString2")

    if event.get("deviceCustomString3"):
        out["policy_name"] = event.get("deviceCustomString3")

    # Domain
    if event.get("deviceCustomString4"):
        out["destination_domain"] = event.get("deviceCustomString4")

    # URL/Application Category
    if event.get("categoryDeviceGroup"):
        out["application_category"] = event.get("categoryDeviceGroup")

    out["event_details"] = message(event)

    return out