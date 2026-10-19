"""Threat classification helpers shared by the API and response engine."""
import json


SQL_INJECTION_RULE_IDS = {'31103', '31152', '31164', '31165', '100200', '100201', '100202', '100510'}
BRUTE_FORCE_RULE_IDS = {'5712', '5763', '100002', '100102', '100501'}
WEB_ATTACK_RULE_IDS = {'31151'}
WEB_DEFACEMENT_RULE_IDS = {'100300', '100301', '100302', '100303', '100304'}
THREAT_RULE_IDS = {
    'sql_injection': SQL_INJECTION_RULE_IDS,
    'brute_force': BRUTE_FORCE_RULE_IDS,
    'web_defacement': WEB_DEFACEMENT_RULE_IDS,
    'webshell_content': {'100305'},
    'web_attack': WEB_ATTACK_RULE_IDS,
    'shellshock': {'31166', '31167', '31168', '31169', '100490'},
    'webshell_probe': {'100400', '100401'},
    'wordpress_scan': {'100410', '100411'},
    'vulnerability_scan': {'100420', '100421'},
    'sensitive_file': {'100430'},
    'rce': {'100440'},
    'recon': {'100450', '100451'},
    'path_traversal': {'100460'},
    'xss': {'31105', '31154', '100468', '100469', '100470'},
    'ssrf': {'100480', '100481'},
    'ip_reputation': {'100600'},
    'host_command': {'100610'},
    'suspicious_process': {'100611'},
    'rootkit': {'510', '521'},
    'malware': {'87105'},
}

THREAT_LABELS = {
    'sql_injection': 'SQL Injection',
    'brute_force': 'Brute Force',
    'web_attack': 'Web Attack',
    'web_defacement': 'Web Defacement',
    'webshell_content': 'Possible Webshell File',
    'shellshock': 'Shellshock',
    'webshell_probe': 'Webshell Probe',
    'wordpress_scan': 'WordPress Scan',
    'vulnerability_scan': 'Vulnerability Scanner',
    'sensitive_file': 'Sensitive File Access',
    'rce': 'RCE / Command Injection',
    'recon': 'Service Enumeration',
    'path_traversal': 'Path Traversal / LFI',
    'xss': 'XSS',
    'ssrf': 'Possible SSRF',
    'ip_reputation': 'Known Bad IP',
    'host_command': 'Suspicious Command',
    'suspicious_process': 'Suspicious Process',
    'rootkit': 'Rootcheck Finding',
    'malware': 'Malware Reputation',
    'host_vulnerability': 'Host Vulnerability',
    'other': 'Other',
}

# These are operator instructions, not proof that an exploit succeeded.
THREAT_GUIDANCE = {
    'sql_injection': 'Review the URL and application log; use parameterized queries and verify that the request was rejected.',
    'brute_force': 'Check failed-login events for this endpoint, enable rate limiting/MFA, and review account access.',
    'shellshock': 'Check CGI/Bash exposure and patch the host; inspect process and command logs for execution.',
    'webshell_probe': 'Check whether the requested file exists; inspect FIM, web root, PHP processes, and recent uploads.',
    'wordpress_scan': 'Confirm whether WordPress exists; restrict unused endpoints and review login/plugin activity.',
    'vulnerability_scan': 'Review the scanned paths and approved scanner allowlist; patch exposed software.',
    'sensitive_file': 'Verify whether the file was served; deny public access and rotate any exposed secrets.',
    'rce': 'Check the target endpoint, patch vulnerable components, and inspect processes, FIM, and outbound traffic.',
    'recon': 'Review requested paths; close unused services and restrict administrative routes.',
    'path_traversal': 'Inspect the full URI and file-access logs; canonicalize paths and restrict file reads.',
    'xss': 'Check whether input was reflected/stored; encode output and apply a suitable content security policy.',
    'ssrf': 'Correlate with DNS and outbound connections; restrict server-side fetch targets and egress.',
    'ip_reputation': 'Confirm the list entry, review the request and pfSense block, and remove stale or false-positive reputation entries.',
    'host_command': 'Review the audited executable, user and process context; isolate the host if unauthorized and preserve logs.',
    'suspicious_process': 'Inspect the PID, executable path and parent process; determine whether this utility is approved.',
    'rootkit': 'Investigate the host offline; compare process visibility from trusted tools and preserve forensic evidence.',
    'malware': 'Check the VirusTotal result and file hash, isolate the file or host, and restore a trusted copy after investigation.',
    'host_vulnerability': 'Verify the affected package and CVE, then patch or apply a supported mitigation; a CVE alert has no attacker IP.',
    'web_defacement': 'Preserve evidence, verify the changed file, remove malicious content, restore a trusted version, and investigate who modified it.',
    'webshell_content': 'Isolate execution of the file, preserve a copy and its hash, inspect uploads/processes and FIM history, then restore clean code.',
    'web_attack': 'Review the raw request and response; repeated 400 errors can also be benign.',
    'other': 'Review the raw Wazuh event, affected host, and related logs before taking action.',
}

AUTO_BLOCKABLE_TYPES = {
    'sql_injection', 'brute_force', 'shellshock', 'webshell_probe',
    'wordpress_scan', 'vulnerability_scan', 'sensitive_file', 'rce',
    'recon', 'path_traversal', 'xss',
}

# Used when several Wazuh rules are emitted for one HTTP request. The rule
# level remains the primary signal; this order breaks ties in favour of the
# specific attack classification instead of a generic web error.
THREAT_PRIORITIES = {
    'sql_injection': 40,
    'web_defacement': 50,
    'webshell_content': 58,
    'brute_force': 30,
    'web_attack': 20,
    'other': 10,
    'shellshock': 60,
    'webshell_probe': 35,
    'wordpress_scan': 15,
    'vulnerability_scan': 15,
    'sensitive_file': 45,
    'rce': 55,
    'recon': 15,
    'path_traversal': 45,
    'xss': 30,
    'ssrf': 20,
    'ip_reputation': 65,
    'host_command': 35,
    'suspicious_process': 30,
    'rootkit': 70,
    'malware': 70,
    'host_vulnerability': 25,
}


def normalize_rule_groups(groups) -> set[str]:
    """Return lower-case Wazuh group names from JSON, a list, or CSV text."""
    if isinstance(groups, str):
        text = groups.strip()
        if not text:
            return set()
        try:
            groups = json.loads(text)
        except (TypeError, ValueError, json.JSONDecodeError):
            groups = text.split(',')
    if not isinstance(groups, (list, tuple, set)):
        return set()
    return {str(group).strip().lower() for group in groups if str(group).strip()}


def classify_threat(rule_id=None, description=None, groups=None) -> dict:
    """Classify an alert without requiring a database schema migration."""
    rule_id = str(rule_id or '')
    description_lower = str(description or '').lower()
    normalized_groups = normalize_rule_groups(groups)

    if rule_id in THREAT_RULE_IDS['webshell_content'] or 'webshell_content' in normalized_groups:
        code = 'webshell_content'
    elif rule_id in THREAT_RULE_IDS['ip_reputation']:
        code = 'ip_reputation'
    elif rule_id in THREAT_RULE_IDS['host_command']:
        code = 'host_command'
    elif rule_id in THREAT_RULE_IDS['suspicious_process']:
        code = 'suspicious_process'
    elif rule_id in THREAT_RULE_IDS['rootkit'] or 'rootcheck' in normalized_groups:
        code = 'rootkit'
    elif rule_id in THREAT_RULE_IDS['malware'] or 'virustotal' in normalized_groups:
        code = 'malware'
    elif 'vulnerability-detector' in normalized_groups or 'vulnerability_detection' in normalized_groups:
        code = 'host_vulnerability'
    elif rule_id in THREAT_RULE_IDS['shellshock'] or 'shellshock' in description_lower:
        code = 'shellshock'
    elif (
        rule_id in WEB_DEFACEMENT_RULE_IDS
        or 'web_defacement' in normalized_groups
        or 'malicious_content' in normalized_groups
        or 'website integrity' in description_lower
        or 'content injection' in description_lower
        or 'gambling spam' in description_lower
        or 'loan spam' in description_lower
    ):
        code = 'web_defacement'
    elif (
        rule_id in SQL_INJECTION_RULE_IDS
        or 'sql_injection' in normalized_groups
        or 'sql injection' in description_lower
        or 'sqli' in description_lower
    ):
        code = 'sql_injection'
    elif (
        rule_id in BRUTE_FORCE_RULE_IDS
        or 'brute_force' in normalized_groups
        or 'authentication_failures' in normalized_groups
        or 'brute force' in description_lower
        or 'multiple failed login' in description_lower
    ):
        code = 'brute_force'
    elif any(rule_id in ids or code_name in normalized_groups
             for code_name, ids in THREAT_RULE_IDS.items()
             if code_name not in {'sql_injection', 'brute_force', 'web_defacement', 'webshell_content', 'web_attack', 'shellshock', 'ip_reputation', 'host_command', 'suspicious_process', 'rootkit', 'malware'}):
        code = next(code_name for code_name, ids in THREAT_RULE_IDS.items()
                    if code_name not in {'sql_injection', 'brute_force', 'web_defacement', 'webshell_content', 'web_attack', 'shellshock', 'ip_reputation', 'host_command', 'suspicious_process', 'rootkit', 'malware'}
                    and (rule_id in ids or code_name in normalized_groups))
    elif (
        rule_id in WEB_ATTACK_RULE_IDS
        or 'web_attack' in normalized_groups
        or 'attack' in normalized_groups
    ):
        code = 'web_attack'
    else:
        code = 'other'

    return {'code': code, 'label': THREAT_LABELS[code]}


def can_auto_block(alert) -> bool:
    """Block only categories with a tested IP-bearing trigger.

    The generic Wazuh 31151 correlation is retained for existing lab behavior;
    arbitrary high-level alerts with an IP must not silently become blocks.
    """
    threat = classify_alert(alert)['code']
    rule_id = str(alert.get('rule_id') if isinstance(alert, dict) else getattr(alert, 'rule_id', ''))
    # Only the repeated SSRF rule may block; a single suspicious URL is weak evidence.
    return (rule_id == '100600' or threat in AUTO_BLOCKABLE_TYPES
            or (threat == 'ssrf' and rule_id == '100481')
            or (threat == 'web_attack' and rule_id == '31151'))


def classify_alert(alert) -> dict:
    """Classify either an Alert model or an alert-shaped mapping."""
    if isinstance(alert, dict):
        getter = alert.get
    else:
        getter = lambda name, default=None: getattr(alert, name, default)
    return classify_threat(
        getter('rule_id'),
        getter('rule_description'),
        getter('rule_groups'),
    )


def response_priority(alert) -> tuple[int, int]:
    """Return the response priority for an alert-shaped object or mapping."""
    if isinstance(alert, dict):
        level = alert.get('rule_level')
    else:
        level = getattr(alert, 'rule_level', 0)
    try:
        level = int(level or 0)
    except (TypeError, ValueError):
        level = 0
    threat = classify_alert(alert)
    return level, THREAT_PRIORITIES.get(threat['code'], 0)
