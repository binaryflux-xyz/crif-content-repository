"""
Root Cause Analysis for SIEM Stream: CyberArk Privilege & Credential Monitoring

Detections covered:
- sensitive_password_retrieval
- copy_password
- excessive_password_retreival
- privileged_account_created
- privileged_account_deleted
- safe_deleted
- safe_member_added
- safe_member_modified
- clear_safe_history
"""

def steps():
    return [
        # step 1
        {
            "name": "action",
            "parameters": {
                "action": "DictionaryEventSession",
                "fields": {
                    "event": {
                        "step": 0,
                        "path": "event",
                    }
                },
            },
            "template": "EventSession: retrieved "
                "{{ (output.result|length if output is mapping and output.result is iterable and output.result is not string else (output.rows|length if output is mapping and output.rows is iterable and output.rows is not string else (output|length if output is iterable and output is not string else 'n/a'))) }} "
                "CyberArk session row(s) for RCA. "
                "Gathered sensitive retrievals, credential copy events, safe management actions, and account modifications across sampled sessions."
        },
        # step 2
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/cyberark_credential_privilege_monitoring/rca.py",
                "function_name": "extract_artifacts",
                "variables": {"sessions": "step.1.output"},
            },
            "template": "Extracted distinct source and destination IPs from CyberArk events for enrichment.",
        },
        # step 3
        {
            "name": "threatlab",
            "parameters": {
                "threat_intel_id": "threatintel.abuseipdb.lookup_ip",
                "input": {
                    "ip": "step.2.output.source_ips",
                    "days": 90,
                    "verbose": "yes"
                }
            },
            "template": (
                "AbuseIPDB enrichment executed for extracted source IPs."
            )
        },
        # step 4
        {
            "name": "execute_python_from_s3",
            "parameters": {
                "s3_path": "s3://automation/stream-root-cause-analysis/cyberark_credential_privilege_monitoring/rca.py",
                "function_name": "run_rca",
                "variables": {
                    "sessions": "step.1.output",
                    "event": "event",
                    "abuseipdb": "step.3.output",
                },
            },
            "template": (
                "CyberArk RCA completed: "
                "{{ output.verdict if output else 'n/a' }} "
                "(score {{ output.score if output else 'n/a' }}). "
                "Heuristics executed: sensitive password retrieval analysis, copy password detection, "
                "excessive password retrieval volume check, safe lifecycle evaluation, and privilege manipulation check."
            ),
        },
        # step 5
        {
            "name": "evaluate",
            "parameters": {
                "step": 4,
                "condition": "output.verdict == 'TRUE_POSITIVE'",
                "if_step": 6,
                "else_step": 8
            },
            "template": "Evaluated the RCA verdict to decide whether to create an incident."
        },
        # step 6
        {
            "name": "execute_python",
            "parameters": {
                "code": "def _row_count(x):\n    if isinstance(x, dict):\n        r = x.get('result')\n        if isinstance(r, list):\n            return len(r)\n        rows = x.get('rows')\n        if isinstance(rows, list):\n            return len(rows)\n        return 0\n    if isinstance(x, list):\n        return len(x)\n    return 0\n\nrca_out = rca if isinstance(rca, dict) else {}\nverdict = rca_out.get('verdict') or 'n/a'\nscore = rca_out.get('score')\nscore_text = str(score) if score is not None else 'n/a'\nrows = _row_count(sessions)\n\noutput = {\n  'title': f\"CyberArk Privilege/Credential RCA: {verdict} (score {score_text})\",\n  'description': (\n    f\"Analyzed {rows} CyberArk telemetry event row(s) for credential harvesting, \"\n    f\"unauthorized account modifications, and safe administration patterns. \"\n    f\"Result: {verdict} with aggregate score {score_text}.\"\n  )\n}",
                "variables": {
                    "sessions": "step.1.output",
                    "rca": "step.4.output",
                    "event": "event"
                }
            },
            "template": "Incident payload prepared. Title: {{ output.title }}"
        },
        # step 7
        {
            "name": "action",
            "parameters": {
                "action": "CreateIncident",
                "fields": {
                    "incident": {
                        "step": 6,
                        "path": "output"
                    }
                }
            },
            "template": (
              "{% set inner = output.responses[output.incident_id] "
              "   if output and output.responses and output.incident_id "
              "   and output.incident_id in output.responses "
              "   else (output.responses.values()|list|first "
              "         if output and output.responses else none) %}"
              "{{ inner.result if inner and inner.result is defined else output.incident_id }}"),
        },
        # step 8
        {
            "name": "execute_python",
            "parameters": {
                "code": (
                    "def _rca_verdict(rca):\n"
                    "    if not isinstance(rca, dict):\n"
                    "        return 'n/a'\n"
                    "    out = rca.get('output')\n"
                    "    if isinstance(out, dict) and out.get('verdict'):\n"
                    "        return out.get('verdict')\n"
                    "    return rca.get('verdict') or 'n/a'\n"
                    "\n"
                    "def _incident_duplicate(inc):\n"
                    "    if not isinstance(inc, dict):\n"
                    "        return False\n"
                    "    if inc.get('duplicate') is True:\n"
                    "        return True\n"
                    "    resp = inc.get('responses') or {}\n"
                    "    if not isinstance(resp, dict):\n"
                    "        return False\n"
                    "    for inner in resp.values():\n"
                    "        if not isinstance(inner, dict):\n"
                    "            continue\n"
                    "        data = inner.get('data') or {}\n"
                    "        if isinstance(data, dict) and data.get('duplicate') is True:\n"
                    "            return True\n"
                    "    return False\n"
                    "\n"
                    "if _incident_duplicate(incident_create):\n"
                    "    verdict = 'FALSE_POSITIVE'\n"
                    "else:\n"
                    "    verdict = _rca_verdict(rca)\n"
                    "\n"
                    "output = {'verdict': verdict}\n"
                ),
                "variables": {
                    "incident_create": "step.7.output",
                    "rca": "step.4.output"
                },
            },
            "template": (
                "Status verdict for UpdateStatus: {{ output.verdict }} "
                "(FALSE_POSITIVE when incident create was a duplicate)."
            ),
        },
        # STEP 9
        {
            "name": "action",
            "parameters": {
                "action": "UpdateStatus",
                "fields": {
                    "id": {
                        "step": 0,
                        "path": "id",
                    },
                    "verdict": {
                        "step": 8,
                        "path": "output.verdict",
                    },
                    "detectiontime": {
                        "step": 0,
                        "path": "detectiontime",
                    },
                },
            },
            "template": "The alert status was modified in accordance with the verdict.",
        }
    ]


def template():
    """
    RCA report for the detection UI — CyberArk Privilege & Credential Monitoring (HTML).

    Report bindings:
      - ``step_0`` — CyberArk session telemetry.
      - ``step_1`` — extracted artifacts.
      - ``step_2`` — AbuseIPDB enrichment output.
      - ``step_3`` — RCA verdict output.
      - ``event`` — detection payload from playbook execution document.
    """
    return """<div class="rca-report" style="font-family:system-ui,Segoe UI,sans-serif;line-height:1.45;white-space:normal;">

{%- set s1 = step_0|default({}, true) -%}
{%- set artifacts = step_1 if step_1 is defined and step_1 is mapping else {} -%}
{%- set abuseip_data = step_2 if step_2 is defined and step_2 is mapping else {} -%}
{%- set rca = step_3|default({}, true) -%}

{%- set v = rca.get('verdict') if rca is mapping else none -%}
{%- set score = rca.get('score') if rca is mapping else none -%}
{%- set reason_text = rca.get('reason', '') if rca is mapping else '' -%}
{%- set conclusion_text = rca.get('conclusion', '') if rca is mapping else '' -%}

{%- set rows = (s1.get('result') if s1 is mapping else (s1 if s1 is iterable and s1 is not string else none)) -%}
{%- set src_ips = artifacts.get('source_ips') or [] -%}
{%- set dest_ips = artifacts.get('destination_ips') or [] -%}
{%- set users = artifacts.get('users') or [] -%}
{%- set target_users = artifacts.get('target_users') or [] -%}
{%- set safe_names = artifacts.get('safe_names') or [] -%}
{%- set signals = rca.get('observed_signals', []) -%}

{%- set abuseip_hits = [] -%}
{%- set abuseip_responses = abuseip_data.get('responses', {}) if abuseip_data is mapping else {} -%}
{%- if abuseip_responses is mapping -%}
  {%- for ip, result in abuseip_responses.items() -%}
    {%- set response = result.get('response', {}) if result is mapping else {} -%}
    {%- set data = response.get('data', {}) if response is mapping else {} -%}
    {%- set data = data if data else (result.get('data', result) if result is mapping else {}) -%}
    {%- set confidence = data.get('abuseConfidenceScore', 0)|int if data is mapping else 0 -%}
    {%- set reports = data.get('totalReports', 0)|int if data is mapping else 0 -%}
    {%- if confidence > 0 -%}
      {%- set _ = abuseip_hits.append({'ip': ip, 'confidence': confidence, 'reports': reports}) -%}
    {%- endif -%}
  {%- endfor -%}
{%- endif -%}

{%- set inc_create = step_7|default({}, true) -%}
{%- set incident_dup_id = inc_create.get('incident_id') if inc_create is mapping else none -%}
{%- set resp = inc_create.get('responses') if inc_create is mapping else none -%}
{%- set inner_dup = resp.get(incident_dup_id) if resp is mapping and incident_dup_id else none -%}
{%- set is_incident_dup = (inc_create.get('duplicate') if inc_create is mapping else false) or (inner_dup is mapping and inner_dup.get('data') is mapping and inner_dup.get('data').get('duplicate')) -%}

<div class="rca-body">
  <section class="summary-strip">
    {%- if v == 'TRUE_POSITIVE' -%}
    <strong class="text-danger">High-risk CyberArk privilege/credential activity</strong>
    <p>Security telemetry indicates high-severity policy violations, unauthorized access, or credential harvesting.</p>
    {%- elif v == 'SUSPICIOUS' -%}
    <strong class="text-warning">Suspicious CyberArk privilege/credential activity</strong>
    <p>Observed anomalies or minor policy breaches require verification with users/owners.</p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <strong>Likely benign / false positive</strong>
    <p>The reviewed telemetry and enrichment did not meet the configured risk threshold.</p>
    {%- else -%}
    <strong>RCA pending / unavailable</strong>
    <p>The RCA output is incomplete or unavailable.</p>
    {%- endif -%}
  </section>

  <section class="card rca-block">
    <h2>Session Review</h2>
    <div class="body-copy">
      <p>Retrieved CyberArk event telemetry for the alert window.</p>
      <span class="label">Outcome:</span>
      {%- if rows is not none and rows is iterable and rows is not string -%}
      <p>{{ rows|length }} telemetry row(s) were reviewed.</p>
      {%- elif rows is not none -%}
      <p>Session output was present, but returned in a non-list shape.</p>
      {%- else -%}
      <p>No session output was available for this run.</p>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>RCA Findings</h2>
    <div class="body-copy">
      <span class="label">Performed:</span>
      <p>Checked for sensitive credential retrievals, bypass/copy events, bulk harvesting thresholds, safe administration, membership modifications, account lifecycles, and IP reputations.</p>

      <span class="label">Outcome:</span>
      {%- if v -%}
      <p>Verdict: <strong>{{ v }}</strong>{% if score is not none %} - aggregate score <strong>{{ score }}</strong>{% endif %}.</p>
      {%- else -%}
      <p><em>RCA output was not available.</em></p>
      {%- endif -%}

      <span class="label">Observed Signals:</span>
      {%- if signals|length > 0 -%}
      <p>
        {%- for signal in signals -%}
        - {{ signal|e }}{% if not loop.last %}<br>{% endif %}
        {%- endfor -%}
      </p>
      {%- else -%}
      <p>- No administrative actions or policy violations were identified from telemetry.</p>
      {%- endif -%}

      <span class="label">Reputation Summary:</span>
      <div class="evidence-list">
        <div class="evidence-row">
          <div class="evidence-key">Flagged Source IPs</div>
          <div class="evidence-value">{{ abuseip_hits|length }} source IP(s) with reputation concerns</div>
        </div>
      </div>

      {%- if abuseip_hits|length > 0 -%}
      <span class="label">Flagged IP Details:</span>
      <div class="evidence-list">
        {%- for hit in abuseip_hits[:3] -%}
        <div class="evidence-row">
          <div class="evidence-key">AbuseIPDB</div>
          <div class="evidence-value">
            <strong>{{ hit.ip }}</strong><br>
            {% if hit.confidence >= 80 %}malicious{% else %}suspicious{% endif %}
            reputation - confidence {{ hit.confidence }}, {{ hit.reports }} report(s)
          </div>
        </div>
        {%- endfor -%}
      </div>
      {%- endif -%}
    </div>
  </section>

  <section class="card rca-block">
    <h2>Artifacts Used</h2>
    <div class="body-copy">
      {%- if users|length > 0 -%}
      <div class="evidence-row">
        <div class="evidence-key">Actor Users</div>
        <div class="evidence-value">{{ users[:3]|join(', ')|e }}{% if users|length > 3 %} <span title="{{ users|join(', ')|e }}">(+{{ users|length - 3 }} more)</span>{% endif %}</div>
      </div>
      {%- endif -%}

      {%- if target_users|length > 0 -%}
      <div class="evidence-row">
        <div class="evidence-key">Target Users/Accounts</div>
        <div class="evidence-value">{{ target_users[:3]|join(', ')|e }}{% if target_users|length > 3 %} <span title="{{ target_users|join(', ')|e }}">(+{{ target_users|length - 3 }} more)</span>{% endif %}</div>
      </div>
      {%- endif -%}

      {%- if safe_names|length > 0 -%}
      <div class="evidence-row">
        <div class="evidence-key">Safes</div>
        <div class="evidence-value">{{ safe_names[:3]|join(', ')|e }}{% if safe_names|length > 3 %} <span title="{{ safe_names|join(', ')|e }}">(+{{ safe_names|length - 3 }} more)</span>{% endif %}</div>
      </div>
      {%- endif -%}

      {%- if src_ips|length > 0 -%}
      <div class="evidence-row">
        <div class="evidence-key">Source IPs</div>
        <div class="evidence-value">{{ src_ips[:3]|join(', ')|e }}{% if src_ips|length > 3 %} <span title="{{ src_ips|join(', ')|e }}">(+{{ src_ips|length - 3 }} more)</span>{% endif %}</div>
      </div>
      {%- endif -%}

      {%- if dest_ips|length > 0 -%}
      <div class="evidence-row">
        <div class="evidence-key">Destination IPs</div>
        <div class="evidence-value">{{ dest_ips[:3]|join(', ')|e }}{% if dest_ips|length > 3 %} <span title="{{ dest_ips|join(', ')|e }}">(+{{ dest_ips|length - 3 }} more)</span>{% endif %}</div>
      </div>
      {%- endif -%}
    </div>
  </section>

  <section class="assessment-panel">
    <h2 class="assessment-title">Final Assessment</h2>
    {%- if is_incident_dup -%}
    <p class="assessment-copy" style="border-left: 3px solid #eab308; padding-left: 0.75rem; margin-bottom: 0.75rem;">
      RCA indicated <strong>{{ v or 'n/a' }}</strong>, but <strong>no new incident</strong> was created - an existing open incident was reused (<strong>{{ incident_dup_id }}</strong>).
      Detection status was set to <strong>FALSE_POSITIVE</strong> for deduplication alignment.
    </p>
    {%- elif v == 'TRUE_POSITIVE' -%}
    <p class="assessment-copy">
      <strong>Assessment:</strong> High-risk or policy-violating CyberArk administrative actions / credential retrievals were identified{% if score is not none %}. <strong>Score: {{ score }}.</strong>{% endif %}
    </p>
    {%- elif v == 'SUSPICIOUS' -%}
    <p class="assessment-copy">
      <strong>Assessment:</strong> Anomalous CyberArk activity was identified requiring authorization review{% if score is not none %}. <strong>Score: {{ score }}.</strong>{% endif %}
    </p>
    {%- elif v == 'FALSE_POSITIVE' -%}
    <p class="assessment-copy">
      <strong>Assessment:</strong> No meaningful CyberArk threat evidence met the configured RCA threshold{% if score is not none %}. <strong>Score: {{ score }}.</strong>{% endif %}
    </p>
    {%- else -%}
    <p class="assessment-copy">
      <strong>Assessment:</strong> Verdict is <strong>{{ v or 'pending or unavailable' }}</strong>.
    </p>
    {%- endif -%}
  </section>
</div>

<div class="rca-conclusion" data-rca-field="conclusion" style="display:none;">{{ conclusion_text }}</div>
</div>"""
