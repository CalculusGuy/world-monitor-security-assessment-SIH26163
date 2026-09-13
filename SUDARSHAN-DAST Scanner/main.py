# main.py
# SUDARSHAN — Enterprise DAST Engine with Validation
# Author: Nilanjan Chowdhury
# GitHub: github.com/CalculusGuy/SUDARSHAN

import os
import sys
import json
import argparse
import logging
import warnings
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import urllib3
from colorama import init, Fore, Style

from crawler.crawler import crawl
from engine.engine import test_url, test_form
from reporter.reporter import generate_json_report, generate_html_report

# Suppress all TLS warnings globally (clean output)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

# Directory the script itself lives in
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format=f"{Fore.CYAN}[%(levelname)s]{Style.RESET_ALL} %(message)s",
)
log = logging.getLogger("sudarshan")

# ============================================================
# ASCII LOGO — DRAGON
# ============================================================

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
                              __====-_  _-====___
                     _--^^^#####//      \\#####^^^--_
                  _-^##########// (    ) \\##########^-_
                 -############//  |\\^^/|  \\############-
               _/############//   (@::@)   \\############\\_
              /#############((     \\//     ))#############\\
             -###############\\    (oo)    //###############-
            -#################\\  / UUU \\  //#################-
           -###################\\/  (_)  \\//###################-
          _#/|##########/\\#####(   /\\   )#####/\\##########|\\#_
          |/ |##########/  \\##/\\   /  \\   /\\##/  \\##########| \\|
          |  |##########/    \\##/\\ /    \\ /\\##/    \\##########|  |
          |  |##########/      \\##/  _  \\##/      \\##########|  |
          |  |##########/       \\##/  /\\  \\##/       \\##########|  |
          \\  \\##########/       \\##/  (  )  \\##/       \\##########/  /
           \\  \\########/        \\##/   \\/   \\##/        \\########/  /
            \\  \\######/          \\##/        \\##/          \\######/  /
             \\  \\####/            \\##/  ( )  \\##/            \\####/  /
              \\  \\##/              \\##/ /\\ \\  \\##/              \\##/  /
               \\  \\/                \\##//  \\ \\##/                \\/  /
                \\  /                 \\//    \\/\\                 /  /
                 \\/                   ||    ||                   \\/
                                      ||    ||
                                      ||    ||
                                      ||    ||
                                      ||    ||
                                      ||    ||

{Fore.GREEN}   Enterprise DAST Engine for Modern Web Applications
{Fore.YELLOW}   Cuts through web vulnerabilities.
{Fore.WHITE}   Author: Nilanjan Chowdhury
{Fore.CYAN}   GitHub: github.com/CalculusGuy/SUDARSHAN
{Style.RESET_ALL}
"""

# ============================================================
# LOAD RULES
# ============================================================

def load_rules():
    """Load detection rules from rules/dast_rules.json."""
    rules_path = os.path.join(SCRIPT_DIR, "rules", "dast_rules.json")
    try:
        with open(rules_path, "r") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        log.info(f"{Fore.GREEN}Loaded {len(rules)} rules from {rules_path}")
        return rules
    except FileNotFoundError:
        log.error(f"{Fore.RED}Rules file not found: {rules_path}")
        return []
    except json.JSONDecodeError as e:
        log.error(f"{Fore.RED}Rules file is not valid JSON: {e}")
        return []

# ============================================================
# VALIDATION
# ============================================================

def validate_target(target: str) -> str:
    """Ensure the target has an explicit scheme."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        log.error(
            f"{Fore.RED}Invalid target URL: '{target}'. "
            f"Include a scheme, e.g. https://example.com"
        )
        sys.exit(1)
    return target

# ============================================================
# ARGPARSE CLI
# ============================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="SUDARSHAN — Enterprise DAST Engine with Validation",
        epilog="Example: python3 main.py --target https://example.com --threads 20 --poc"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target URL to scan (e.g., https://example.com)"
    )
    parser.add_argument(
        "--threads", "-th",
        type=int,
        default=10,
        help="Number of worker threads for concurrent testing (default: 10)"
    )
    parser.add_argument(
        "--report", "-r",
        choices=["json", "html", "both"],
        default="both",
        help="Report format (default: both)"
    )
    parser.add_argument(
        "--report-dir",
        default="reports",
        help="Directory to save reports (default: reports)"
    )
    parser.add_argument(
        "--max-pages", "-m",
        type=int,
        default=10,
        help="Maximum number of pages to crawl (default: 10)"
    )
    parser.add_argument(
        "--poc", "-p",
        action="store_true",
        help="Generate Proof-of-Concept scripts for confirmed vulnerabilities"
    )
    parser.add_argument(
        "--poc-dir",
        default="pocs",
        help="Directory to save PoC scripts (default: pocs)"
    )
    parser.add_argument(
        "--insecure", "-k",
        action="store_true",
        help="Disable TLS certificate verification (INSECURE — off by default)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Per-request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip validation engine (report all findings as potential)"
    )
    args = parser.parse_args()

    if args.threads < 1:
        parser.error("--threads must be >= 1")
    if args.max_pages < 1:
        parser.error("--max-pages must be >= 1")

    return args

# ============================================================
# THREADED SCAN HELPERS
# ============================================================

def run_url_tests(pages, rules, threads):
    """Test crawled URLs concurrently."""
    findings = []
    if not pages:
        return findings

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_to_page = {pool.submit(test_url, page, rules): page for page in pages}
        for future in as_completed(future_to_page):
            page = future_to_page[future]
            try:
                result = future.result()
                if result:
                    findings.extend(result)
                log.info(f"{Fore.WHITE}Tested: {page}")
            except Exception as e:
                log.warning(f"{Fore.YELLOW}Error testing {page}: {e}")
    return findings

def run_form_tests(forms, rules, target, threads):
    """Test discovered forms concurrently."""
    findings = []
    if not forms:
        return findings

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_to_form = {
            pool.submit(test_form, form, rules, target): form for form in forms
        }
        for future in as_completed(future_to_form):
            form = future_to_form[future]
            try:
                result = future.result()
                if result:
                    findings.extend(result)
                log.info(f"{Fore.WHITE}Tested form: {form.get('action', '<unknown>')}")
            except Exception as e:
                log.warning(
                    f"{Fore.YELLOW}Error testing form {form.get('action', '<unknown>')}: {e}"
                )
    return findings

# ============================================================
# VALIDATION ENGINE
# ============================================================

def validate_findings(findings, timeout=10, verify=False):
    """
    Run all findings through the validation engine.
    Returns validated findings with confidence scores.
    """
    if not findings:
        return []
    
    try:
        from validator.validator import FindingValidator
        validator = FindingValidator(timeout=timeout, verify=verify)
    except ImportError as e:
        log.warning(f"{Fore.YELLOW}Validator module not available: {e}")
        log.warning(f"{Fore.YELLOW}All findings will be reported as UNVERIFIED")
        return findings
    
    validated = []
    total = len(findings)
    
    print(f"\n{Fore.YELLOW}[*] Phase 3: Validating {total} findings...")
    
    for idx, finding in enumerate(findings, 1):
        # Extract vulnerability name from finding
        vuln_name = finding.get("rule", "Unknown Vulnerability")
        
        # Convert to validator format
        validator_finding = {
            "vulnerability": vuln_name,
            "url": finding.get("url", ""),
            "parameter": finding.get("parameter", finding.get("param", "")),
            "method": finding.get("method", "GET"),
            "evidence": finding.get("indicator", "")
        }
        
        # Run validation
        try:
            result = validator.validate(validator_finding)
            finding["validation"] = result.to_dict()
            finding["confirmed"] = result.is_confirmed()
            finding["confidence"] = result.confidence
            
            if result.is_confirmed():
                print(f"{Fore.GREEN}  ✅ [{idx}/{total}] CONFIRMED: {vuln_name} (Confidence: {result.confidence}%)")
                validated.append(finding)
            elif result.is_unverified():
                print(f"{Fore.YELLOW}  ⚠️ [{idx}/{total}] UNVERIFIED: {vuln_name} (Confidence: {result.confidence}%)")
                # Still include but mark as unverified
                validated.append(finding)
            else:
                print(f"{Fore.RED}  ❌ [{idx}/{total}] ERROR: {vuln_name}")
        except Exception as e:
            log.error(f"{Fore.RED}Validation error for {vuln_name}: {str(e)[:100]}")
            finding["validation"] = {
                "status": "ERROR",
                "confidence": 0,
                "evidence": [f"Validation error: {str(e)[:100]}"]
            }
            validated.append(finding)
    
    confirmed = [f for f in validated if f.get("confirmed", False)]
    print(f"\n{Fore.GREEN}[+] Validation complete: {len(confirmed)} confirmed, "
          f"{len(validated) - len(confirmed)} unverified/error")
    
    return validated

# ============================================================
# MAIN
# ============================================================

def main():
    args = parse_args()
    target = validate_target(args.target)
    threads = args.threads
    report_format = args.report
    max_pages = args.max_pages
    generate_poc_flag = args.poc
    poc_dir = args.poc_dir
    report_dir = args.report_dir
    skip_validation = args.no_validate

    if args.insecure:
        log.warning(f"{Fore.YELLOW}TLS certificate verification is DISABLED (--insecure).")

    os.makedirs(report_dir, exist_ok=True)
    if generate_poc_flag:
        os.makedirs(poc_dir, exist_ok=True)

    print(BANNER)
    print(f"{Fore.CYAN}[*] Target: {target}")
    print(f"{Fore.CYAN}[*] Threads: {threads}")
    print(f"{Fore.CYAN}[*] Report Format: {report_format} -> {report_dir}/")
    print(f"{Fore.CYAN}[*] Max Pages: {max_pages}")
    print(f"{Fore.CYAN}[*] TLS Verification: {'DISABLED' if args.insecure else 'enabled'}")
    print(f"{Fore.CYAN}[*] Validation Engine: {'DISABLED' if skip_validation else 'ENABLED'}")
    if generate_poc_flag:
        print(f"{Fore.CYAN}[*] PoC Generation: Enabled (Directory: {poc_dir})")
    print()

    findings = []

    try:
        print(f"{Fore.YELLOW}[*] Phase 1: Crawling...")
        pages, forms = crawl(target, max_pages=max_pages)
        print(f"{Fore.GREEN}[+] Found {len(pages)} pages, {len(forms)} forms")
    except KeyboardInterrupt:
        log.warning(f"{Fore.YELLOW}Crawl interrupted by user. Exiting.")
        sys.exit(130)
    except Exception as e:
        log.error(f"{Fore.RED}Crawl failed: {e}")
        sys.exit(1)

    rules = load_rules()
    if not rules:
        log.error(f"{Fore.RED}No rules loaded. Exiting.")
        sys.exit(1)

    try:
        print(f"\n{Fore.YELLOW}[*] Phase 2: Testing {len(pages)} URLs "
              f"and {len(forms)} forms with {threads} threads...")
        findings.extend(run_url_tests(pages, rules, threads))
        findings.extend(run_form_tests(forms, rules, target, threads))
    except KeyboardInterrupt:
        log.warning(
            f"{Fore.YELLOW}Testing interrupted by user. "
            f"Proceeding to report {len(findings)} findings collected so far."
        )

    # ============================================================
    # VALIDATION PHASE
    # ============================================================
    if not skip_validation and findings:
        findings = validate_findings(findings, timeout=args.timeout, verify=not args.insecure)
    elif skip_validation:
        print(f"\n{Fore.YELLOW}[*] Validation skipped (--no-validate). All findings marked as potential.")

    # ============================================================
    # REPORT GENERATION
    # ============================================================
    print(f"\n{Fore.YELLOW}[*] Phase 4: Generating reports...")
    try:
        if report_format in ["json", "both"]:
            generate_json_report(findings, target, out_dir=report_dir)
        if report_format in ["html", "both"]:
            generate_html_report(findings, target, out_dir=report_dir)
    except Exception as e:
        log.error(f"{Fore.RED}Report generation failed: {e}")

    # ============================================================
    # PoC GENERATION
    # ============================================================
    if generate_poc_flag and findings:
        # Only generate PoC for confirmed findings
        confirmed_findings = [f for f in findings if f.get("confirmed", False)]
        if confirmed_findings:
            try:
                # Check if poc_generator exists
                try:
                    from reporter.poc_generator import generate_poc
                    poc_files = generate_poc(confirmed_findings, target, poc_dir)
                    print(f"\n{Fore.GREEN}[+] PoC scripts generated: {len(poc_files)}")
                    for f in poc_files:
                        print(f"{Fore.CYAN}  - {f}")
                except ImportError:
                    # Fallback: generate simple PoC files
                    poc_files = []
                    for idx, finding in enumerate(confirmed_findings, 1):
                        poc_file = os.path.join(poc_dir, f"poc_{idx}_{finding.get('rule', 'vuln').replace(' ', '_')}.txt")
                        with open(poc_file, "w") as pf:
                            pf.write(f"SUDARSHAN PoC - Confirmed Vulnerability\n")
                            pf.write(f"{'='*50}\n\n")
                            pf.write(f"Vulnerability: {finding.get('rule', 'Unknown')}\n")
                            pf.write(f"Severity: {finding.get('severity', 'Unknown')}\n")
                            pf.write(f"URL: {finding.get('url', 'N/A')}\n")
                            pf.write(f"Parameter: {finding.get('parameter', 'N/A')}\n")
                            pf.write(f"Confidence: {finding.get('confidence', 0)}%\n\n")
                            pf.write(f"Validation Evidence:\n")
                            validation = finding.get("validation", {})
                            for ev in validation.get("evidence", []):
                                pf.write(f"  - {ev}\n")
                            pf.write(f"\nPoC Command:\n")
                            pf.write(f"  {validation.get('poc_command', 'Manual verification required')}\n")
                            pf.write(f"\nPoC Response Preview:\n")
                            pf.write(f"  {validation.get('poc_response', 'N/A')[:500]}\n")
                        poc_files.append(poc_file)
                    print(f"\n{Fore.GREEN}[+] PoC scripts generated: {len(poc_files)}")
                    for f in poc_files:
                        print(f"{Fore.CYAN}  - {f}")
            except Exception as e:
                log.error(f"{Fore.RED}PoC generation failed: {e}")
        else:
            print(f"\n{Fore.YELLOW}[+] No confirmed vulnerabilities found. PoC generation skipped.")

    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    confirmed_count = len([f for f in findings if f.get("confirmed", False)])
    unverified_count = len([f for f in findings if not f.get("confirmed", False)])

    print(f"\n{Fore.GREEN}[+] Scan complete!")
    print(f"{Fore.CYAN}  - Total findings: {len(findings)}")
    print(f"{Fore.GREEN}  - Confirmed: {confirmed_count}")
    print(f"{Fore.YELLOW}  - Unverified: {unverified_count}")
    print(f"{Fore.CYAN}[+] Reports saved to {report_dir}/")
    print(f"{Fore.GREEN}[+] SUDARSHAN — Cuts through web vulnerabilities.")

    # Non-zero exit on confirmed findings makes SUDARSHAN usable as a CI/CD gate.
    sys.exit(1 if confirmed_count > 0 else 0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user. Exiting.")
        sys.exit(130)
