# reporter/reporter.py
import json
import os
from datetime import datetime

# ============================================================
# REMEDIATION MAPPING
# ============================================================

REMEDIATION_MAP = {
    "SQL Injection": {
        "description": "Use parameterized queries (prepared statements) to separate SQL logic from data",
        "fix": "Replace string concatenation with ? placeholders and parameter binding",
        "example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    },
    "Cross-Site Scripting (XSS)": {
        "description": "Escape all user input before rendering in HTML to prevent script execution",
        "fix": "Use autoescaping template engines or manual escaping with html.escape()",
        "example": "from html import escape; safe_output = escape(user_input)"
    },
    "Cross-Site Scripting (XSS) Detection": {
        "description": "Escape all user input before rendering in HTML to prevent script execution",
        "fix": "Use autoescaping template engines or manual escaping with html.escape()",
        "example": "from html import escape; safe_output = escape(user_input)"
    },
    "Command Injection": {
        "description": "Avoid shell=True and use argument lists instead of shell strings",
        "fix": "Use subprocess.run(['cmd', arg1, arg2]) instead of shell=True",
        "example": "subprocess.run(['ping', '-c', '1', host])"
    },
    "Command Injection Detection": {
        "description": "Avoid shell=True and use argument lists instead of shell strings",
        "fix": "Use subprocess.run(['cmd', arg1, arg2]) instead of shell=True",
        "example": "subprocess.run(['ping', '-c', '1', host])"
    },
    "Server-Side Request Forgery (SSRF)": {
        "description": "Validate and restrict URL inputs to allow only trusted domains",
        "fix": "Whitelist allowed domains and disallow internal IP ranges",
        "example": "if urlparse(url).netloc not in ALLOWED_DOMAINS: return 'Blocked'"
    },
    "Server-Side Request Forgery (SSRF) Detection": {
        "description": "Validate and restrict URL inputs to allow only trusted domains",
        "fix": "Whitelist allowed domains and disallow internal IP ranges",
        "example": "if urlparse(url).netloc not in ALLOWED_DOMAINS: return 'Blocked'"
    },
    "IDOR (Insecure Direct Object Reference)": {
        "description": "Implement authorization checks for every object access",
        "fix": "Verify the logged-in user owns the requested object before returning data",
        "example": "if request.user_id != object.owner_id: return 403"
    },
    "IDOR (Insecure Direct Object Reference) Detection": {
        "description": "Implement authorization checks for every object access",
        "fix": "Verify the logged-in user owns the requested object before returning data",
        "example": "if request.user_id != object.owner_id: return 403"
    },
    "Path Traversal": {
        "description": "Sanitize file paths and restrict to a base directory",
        "fix": "Use os.path.join with a safe base path and validate resolved path",
        "example": "safe_path = os.path.join(BASE_DIR, os.path.basename(user_input))"
    },
    "Path Traversal Detection": {
        "description": "Sanitize file paths and restrict to a base directory",
        "fix": "Use os.path.join with a safe base path and validate resolved path",
        "example": "safe_path = os.path.join(BASE_DIR, os.path.basename(user_input))"
    },
    "SSTI (Server-Side Template Injection)": {
        "description": "Avoid user-controlled template strings; use sandboxed engine",
        "fix": "Use static templates or Jinja2 SandboxedEnvironment",
        "example": "from jinja2.sandbox import SandboxedEnvironment; env = SandboxedEnvironment()"
    },
    "Server-Side Template Injection (SSTI)": {
        "description": "Avoid user-controlled template strings; use sandboxed engine",
        "fix": "Use static templates or Jinja2 SandboxedEnvironment",
        "example": "from jinja2.sandbox import SandboxedEnvironment; env = SandboxedEnvironment()"
    },
    "CSRF": {
        "description": "Add CSRF tokens to all state-changing requests",
        "fix": "Generate and validate anti-CSRF tokens in forms and AJAX calls",
        "example": "<input type='hidden' name='csrf_token' value='{{ csrf_token() }}'>"
    },
    "CSRF (Cross-Site Request Forgery) Detection": {
        "description": "Add CSRF tokens to all state-changing requests",
        "fix": "Generate and validate anti-CSRF tokens in forms and AJAX calls",
        "example": "<input type='hidden' name='csrf_token' value='{{ csrf_token() }}'>"
    },
    "JWT Weakness": {
        "description": "Use strong signing algorithms and verify signatures",
        "fix": "Use HS256 or RS256, verify signature, check expiration",
        "example": "jwt.decode(token, SECRET, algorithms=['HS256'])"
    },
    "JWT Weakness Detection": {
        "description": "Use strong signing algorithms and verify signatures",
        "fix": "Use HS256 or RS256, verify signature, check expiration",
        "example": "jwt.decode(token, SECRET, algorithms=['HS256'])"
    },
    "XXE": {
        "description": "Disable external entity processing in XML parsers",
        "fix": "Set parser features to disallow DTDs and external entities",
        "example": "parser.setFeature('http://apache.org/xml/features/disallow-doctype-decl', True)"
    },
    "XXE (XML External Entity) Detection": {
        "description": "Disable external entity processing in XML parsers",
        "fix": "Set parser features to disallow DTDs and external entities",
        "example": "parser.setFeature('http://apache.org/xml/features/disallow-doctype-decl', True)"
    },
    "Open Redirect": {
        "description": "Validate redirect URLs against a whitelist",
        "fix": "Only allow redirects to same-domain URLs",
        "example": "if not url.startswith('/'): return 'Invalid redirect'"
    },
    "Open Redirect Detection": {
        "description": "Validate redirect URLs against a whitelist",
        "fix": "Only allow redirects to same-domain URLs",
        "example": "if not url.startswith('/'): return 'Invalid redirect'"
    },
    "Log4j (CVE-2021-44228)": {
        "description": "Upgrade Log4j to version 2.17.0+ and apply JNDI mitigation",
        "fix": "Update dependency and set log4j2.formatMsgNoLookups=true",
        "example": "Set log4j2.formatMsgNoLookups=true"
    },
    "Log4j (CVE-2021-44228) Detection": {
        "description": "Upgrade Log4j to version 2.17.0+ and apply JNDI mitigation",
        "fix": "Update dependency and set log4j2.formatMsgNoLookups=true",
        "example": "Set log4j2.formatMsgNoLookups=true"
    },
    "NoSQL Injection": {
        "description": "Sanitize user input and use safe query builders",
        "fix": "Use MongoDB's $eq operator or mongoengine safe queries",
        "example": "collection.find({'username': user_input})"
    },
    "NoSQL Injection Detection": {
        "description": "Sanitize user input and use safe query builders",
        "fix": "Use MongoDB's $eq operator or mongoengine safe queries",
        "example": "collection.find({'username': user_input})"
    },
    "LDAP Injection": {
        "description": "Escape special characters in LDAP filters",
        "fix": "Use LDAP escaping functions before constructing filters",
        "example": "from ldap.filter import escape_filter_chars; safe = escape_filter_chars(input)"
    },
    "LDAP Injection Detection": {
        "description": "Escape special characters in LDAP filters",
        "fix": "Use LDAP escaping functions before constructing filters",
        "example": "from ldap.filter import escape_filter_chars; safe = escape_filter_chars(input)"
    },
    "XPATH Injection": {
        "description": "Use parameterized XPath queries",
        "fix": "Use variables instead of string concatenation in XPath",
        "example": "xpath.compile('//user[name=$name]', variables={'name': user_input})"
    },
    "XPATH Injection Detection": {
        "description": "Use parameterized XPath queries",
        "fix": "Use variables instead of string concatenation in XPath",
        "example": "xpath.compile('//user[name=$name]', variables={'name': user_input})"
    },
    "Host Header Injection": {
        "description": "Validate the Host header against a whitelist",
        "fix": "Only accept requests from known domains",
        "example": "if host not in ALLOWED_HOSTS: return 400"
    },
    "Host Header Injection Detection": {
        "description": "Validate the Host header against a whitelist",
        "fix": "Only accept requests from known domains",
        "example": "if host not in ALLOWED_HOSTS: return 400"
    },
    "CORS Misconfiguration": {
        "description": "Restrict Access-Control-Allow-Origin to trusted domains",
        "fix": "Use a whitelist and avoid returning 'null' or '*'",
        "example": "if origin in ALLOWED_ORIGINS: headers['ACAO'] = origin"
    },
    "CORS Misconfiguration Detection": {
        "description": "Restrict Access-Control-Allow-Origin to trusted domains",
        "fix": "Use a whitelist and avoid returning 'null' or '*'",
        "example": "if origin in ALLOWED_ORIGINS: headers['ACAO'] = origin"
    },
    "Race Condition": {
        "description": "Implement locking or atomic operations",
        "fix": "Use database transactions or Redis locks",
        "example": "with redis.lock('resource_lock'): process_request()"
    },
    "Race Condition Detection": {
        "description": "Implement locking or atomic operations",
        "fix": "Use database transactions or Redis locks",
        "example": "with redis.lock('resource_lock'): process_request()"
    },
    "GraphQL Injection": {
        "description": "Implement depth limiting and query cost analysis",
        "fix": "Use GraphQL libraries with built-in protection",
        "example": "depth_limit = 5; cost_limit = 100"
    },
    "GraphQL Injection Detection": {
        "description": "Implement depth limiting and query cost analysis",
        "fix": "Use GraphQL libraries with built-in protection",
        "example": "depth_limit = 5; cost_limit = 100"
    },
    "File Upload": {
        "description": "Validate file type, size, and scan for malware",
        "fix": "Use magic numbers, content-type validation, and quarantine",
        "example": "if not allowed_extension(filename): return 'Invalid file type'"
    },
    "Unrestricted File Upload Detection": {
        "description": "Validate file type, size, and scan for malware",
        "fix": "Use magic numbers, content-type validation, and quarantine",
        "example": "if not allowed_extension(filename): return 'Invalid file type'"
    },
    "Sensitive Data Exposure": {
        "description": "Never log or expose sensitive fields in API responses",
        "fix": "Redact fields like password, token, SSN, credit_card in responses",
        "example": "data.pop('password', None); data.pop('token', None)"
    },
    "Sensitive Data Exposure Detection": {
        "description": "Never log or expose sensitive fields in API responses",
        "fix": "Redact fields like password, token, SSN, credit_card in responses",
        "example": "data.pop('password', None); data.pop('token', None)"
    }
}

# ============================================================
# HELPERS
# ============================================================

def safe_str(value):
    """Safely convert any value to string with HTML escaping."""
    if value is None:
        return "N/A"
    return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

def get_remediation(vuln_name):
    """Get remediation for a vulnerability name with fuzzy matching."""
    # Exact match first
    if vuln_name in REMEDIATION_MAP:
        return REMEDIATION_MAP[vuln_name]
    
    # Fuzzy match
    for key in REMEDIATION_MAP:
        if key.lower() in vuln_name.lower() or vuln_name.lower() in key.lower():
            return REMEDIATION_MAP[key]
    
    # Default fallback
    return {
        "description": "Review the vulnerability and apply appropriate security controls",
        "fix": "Follow OWASP guidelines for this vulnerability type",
        "example": "Refer to OWASP Cheat Sheets for detailed guidance"
    }

# ============================================================
# REPORT GENERATORS
# ============================================================

def generate_json_report(findings, target_url, out_dir="reports"):
    """Generate JSON report in the specified output directory."""
    os.makedirs(out_dir, exist_ok=True)
    
    # Count confirmed/unverified
    confirmed_count = len([f for f in findings if f.get("confirmed", False)])
    unverified_count = len([f for f in findings if not f.get("confirmed", False)])
    
    report = {
        "target": target_url,
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(findings),
        "confirmed": confirmed_count,
        "unverified": unverified_count,
        "findings": []
    }
    
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        
        vuln_name = finding.get("rule", "Unknown")
        remediation = get_remediation(vuln_name)
        
        finding_copy = finding.copy()
        finding_copy["remediation"] = remediation
        
        # Add validation evidence if available
        validation = finding.get("validation", {})
        if validation:
            finding_copy["validation_status"] = validation.get("status", "UNKNOWN")
            finding_copy["confidence"] = validation.get("confidence", 0)
            finding_copy["evidence"] = validation.get("evidence", [])
            finding_copy["poc_command"] = validation.get("poc_command", "")
        
        report["findings"].append(finding_copy)
    
    report_path = os.path.join(out_dir, "scan_report.json")
    with open(report_path, "w", encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[+] JSON report saved to {report_path}")
    
    return report_path

def generate_html_report(findings, target_url, out_dir="reports"):
    """Generate HTML report in the specified output directory."""
    os.makedirs(out_dir, exist_ok=True)
    
    # Count findings by severity and status
    severity_counts = {}
    confirmed_count = 0
    unverified_count = 0
    
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        
        severity = finding.get("severity", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if finding.get("confirmed", False):
            confirmed_count += 1
        else:
            unverified_count += 1
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SUDARSHAN — DAST Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d0d14;
            color: #f0f0f8;
            padding: 30px;
        }}
        .container {{ max-width: 1200px; margin: auto; }}
        h1 {{ color: #00ff9d; font-size: 28px; margin-bottom: 10px; }}
        h2 {{ color: #7b61ff; margin-top: 30px; margin-bottom: 15px; }}
        h3 {{ color: #00ff9d; font-size: 16px; }}
        .subtitle {{ color: #6060a0; margin-bottom: 20px; }}
        .summary {{
            background: #1a1a26;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 25px;
            border: 1px solid #222232;
        }}
        .summary-grid {{ display: flex; flex-wrap: wrap; gap: 30px; }}
        .summary-item {{}}
        .summary-item .num {{ font-size: 32px; font-weight: bold; }}
        .summary-item .label {{ color: #6060a0; font-size: 14px; }}
        .num-confirmed {{ color: #00ff9d; }}
        .num-unverified {{ color: #ffb86b; }}
        .num-total {{ color: #7b61ff; }}
        .num-critical {{ color: #ff6b6b; }}
        .num-high {{ color: #ffb86b; }}
        .num-medium {{ color: #f1fa8c; }}
        .num-low {{ color: #00ff9d; }}
        .finding {{
            background: #1a1a26;
            border: 1px solid #222232;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
            transition: border-color 0.2s;
        }}
        .finding:hover {{ border-color: #7b61ff; }}
        .finding-header {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }}
        .finding-header .rule {{ font-weight: bold; font-size: 18px; color: #f0f0f8; }}
        .badge {{
            display: inline-block;
            padding: 2px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-critical {{ background: #ff6b6b; color: #1a1a26; }}
        .badge-high {{ background: #ffb86b; color: #1a1a26; }}
        .badge-medium {{ background: #f1fa8c; color: #1a1a26; }}
        .badge-low {{ background: #00ff9d; color: #1a1a26; }}
        .badge-confirmed {{ background: #00ff9d; color: #1a1a26; }}
        .badge-unverified {{ background: #ffb86b; color: #1a1a26; }}
        .badge-confidence {{ background: #7b61ff; color: #f0f0f8; }}
        .finding-detail {{
            color: #a0a0c0;
            font-size: 14px;
            margin: 4px 0;
        }}
        .finding-detail strong {{ color: #f0f0f8; }}
        .remediation {{
            background: #0d1a1a;
            border-left: 4px solid #00ff9d;
            padding: 15px 20px;
            margin-top: 12px;
            border-radius: 0 6px 6px 0;
        }}
        .remediation p {{ margin: 4px 0; }}
        .remediation .fix-title {{ color: #00ff9d; font-weight: bold; }}
        .remediation code {{
            background: #0d0d14;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 13px;
            color: #f1fa8c;
        }}
        .evidence {{
            background: #0d0d14;
            padding: 10px 15px;
            margin-top: 10px;
            border-radius: 6px;
            font-size: 13px;
            color: #a0a0c0;
        }}
        .evidence summary {{ cursor: pointer; color: #7b61ff; }}
        .evidence ul {{ margin: 8px 0 0 20px; }}
        .footer {{
            color: #6060a0;
            font-size: 12px;
            margin-top: 40px;
            text-align: center;
            border-top: 1px solid #222232;
            padding-top: 20px;
        }}
        .poc-command {{
            background: #0d0d14;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
            color: #f1fa8c;
            margin-top: 6px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
<div class="container">
    <h1>🛡️ SUDARSHAN — DAST Scan Report</h1>
    <p class="subtitle"><strong>Target:</strong> {safe_str(target_url)} &nbsp;|&nbsp; <strong>Scan Date:</strong> {datetime.now().isoformat()}</p>
    
    <div class="summary">
        <h3>📊 Scan Summary</h3>
        <div class="summary-grid">
            <div class="summary-item">
                <div class="num num-total">{len(findings)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-item">
                <div class="num num-confirmed">{confirmed_count}</div>
                <div class="label">✅ Confirmed</div>
            </div>
            <div class="summary-item">
                <div class="num num-unverified">{unverified_count}</div>
                <div class="label">⚠️ Unverified</div>
            </div>
"""
    
    for severity, count in severity_counts.items():
        severity_class = severity.lower()
        html += f"""
            <div class="summary-item">
                <div class="num num-{severity_class}">{count}</div>
                <div class="label">{severity}</div>
            </div>
"""
    
    html += """
        </div>
    </div>
    
    <h2>🔍 Detailed Findings</h2>
"""
    
    for idx, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue
        
        vuln_name = safe_str(finding.get("rule", "Unknown"))
        severity = safe_str(finding.get("severity", "Unknown"))
        severity_class = severity.lower()
        payload = safe_str(finding.get("payload", "N/A"))
        url = safe_str(finding.get("url", "N/A"))
        indicator = safe_str(finding.get("indicator", "N/A"))
        parameter = safe_str(finding.get("parameter", "N/A"))
        rule_id = safe_str(finding.get("rule_id", "N/A"))
        
        confirmed = finding.get("confirmed", False)
        validation = finding.get("validation", {})
        confidence = validation.get("confidence", 0)
        evidence = validation.get("evidence", [])
        poc_command = validation.get("poc_command", "")
        
        remediation = get_remediation(vuln_name)
        
        status_badge = "badge-confirmed" if confirmed else "badge-unverified"
        status_text = "✅ CONFIRMED" if confirmed else "⚠️ UNVERIFIED"
        status_icon = "✅" if confirmed else "⚠️"
        
        html += f"""
    <div class="finding" id="finding-{idx}">
        <div class="finding-header">
            <span class="rule">{status_icon} [{rule_id}] {vuln_name}</span>
            <span class="badge badge-{severity_class}">{severity}</span>
            <span class="badge {status_badge}">{status_text}</span>
            <span class="badge badge-confidence">🎯 {confidence}%</span>
        </div>
        <div class="finding-detail"><strong>URL:</strong> {url}</div>
        <div class="finding-detail"><strong>Parameter:</strong> <code>{parameter}</code></div>
        <div class="finding-detail"><strong>Payload:</strong> <code>{payload}</code></div>
        <div class="finding-detail"><strong>Indicator:</strong> {indicator}</div>
"""
        
        if poc_command:
            html += f"""
        <div class="poc-command"><strong>💻 PoC Command:</strong> {poc_command}</div>
"""
        
        if remediation:
            html += f"""
        <div class="remediation">
            <p class="fix-title">🔧 Remediation</p>
            <p><strong>Description:</strong> {remediation.get('description', 'N/A')}</p>
            <p><strong>Fix:</strong> {remediation.get('fix', 'N/A')}</p>
            <p><strong>Example:</strong> <code>{remediation.get('example', 'N/A')}</code></p>
        </div>
"""
        
        if evidence:
            html += f"""
        <div class="evidence">
            <details>
                <summary>📋 Evidence ({len(evidence)} items)</summary>
                <ul>
"""
            for ev in evidence:
                html += f"<li>{safe_str(ev)}</li>"
            html += """
                </ul>
            </details>
        </div>
"""
        
        html += """
    </div>
"""
    
    html += f"""
    <div class="footer">
        Generated by SUDARSHAN v3.1 — Enterprise DAST Engine with Validation &amp; PoC Generation<br>
        <a href="https://github.com/CalculusGuy/SUDARSHAN" style="color: #7b61ff;">github.com/CalculusGuy/SUDARSHAN</a>
    </div>
</div>
</body>
</html>
"""
    
    report_path = os.path.join(out_dir, "scan_report.html")
    with open(report_path, "w", encoding='utf-8') as f:
        f.write(html)
    print(f"[+] HTML report saved to {report_path}")
    
    return report_path
