#!/usr/bin/env python3
"""Merge the pipeline's scanner reports into one report and apply the security gate.

Inputs (in the --results folder):
    semgrep.sarif   SAST findings        (SARIF 2.1.0)
    trivy.sarif     dependency CVEs      (SARIF 2.1.0)
    gitleaks.sarif  hardcoded secrets    (SARIF 2.1.0)
    zap.json        DAST alerts          (ZAP JSON report)

Every finding is normalised to one shape (tool, rule, severity, location, OWASP
category), duplicates are dropped, accepted risks are set aside, and the gate
fails if anything left is at or above the --fail-on severity.

A missing or unreadable report also fails the gate: if a scanner breaks, the
pipeline must not quietly pass ("fail closed").

Exit codes: 0 gate passed, 1 gate failed, 2 bad input (e.g. invalid accepted-risks file).
Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {name: i for i, name in enumerate(SEVERITIES)}  # lower rank = more severe

REPORT_FILES = {
    "semgrep": "semgrep.sarif",
    "trivy": "trivy.sarif",
    "gitleaks": "gitleaks.sarif",
    "zap": "zap.json",
}

TOOL_LAYER = {
    "semgrep": "SAST · source code",
    "trivy": "SCA · dependencies",
    "gitleaks": "Secrets · hardcoded credentials",
    "zap": "DAST · running app",
}

OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}

# CWE -> OWASP Top 10 (2021), following the CWE lists OWASP publishes per category.
_CWES_BY_CATEGORY = {
    "A01": [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425,
            441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275],
    "A02": [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336,
            337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    "A03": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113,
            116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917, 943, 1333],
    "A04": [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434,
            444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799,
            807, 840, 841, 927, 1021, 1173],
    "A05": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 693, 756, 776, 942,
            1004, 1032, 1174],
    "A06": [937, 1035, 1104],
    "A07": [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613,
            620, 640, 798, 940, 1216],
    "A08": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09": [117, 223, 532, 778],
    "A10": [918],
}
CWE_TO_OWASP = {cwe: cat for cat, cwes in _CWES_BY_CATEGORY.items() for cwe in cwes}

# Used when a finding carries no CWE or OWASP tag of its own.
TOOL_DEFAULT_OWASP = {"trivy": "A06", "gitleaks": "A07"}

ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

MAX_TABLE_ROWS = 60


@dataclass
class Finding:
    tool: str
    rule_id: str
    title: str
    severity: str
    location: str
    owasp: str = ""
    cwe: str = ""
    help_url: str = ""
    detail: str = ""
    accepted_reason: str = ""

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.tool, self.rule_id, self.location)


# ---------------------------------------------------------------- parsing

def _first_line(text: str, limit: int = 140) -> str:
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _cwe_from(texts: list[str]) -> str:
    for text in texts:
        match = re.search(r"CWE-(\d+)", text or "", flags=re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
    return ""


def _owasp_from(tags: list[str], cwe: str, tool: str) -> str:
    for tag in tags:
        match = re.search(r"\bA(\d{2}):2021\b", tag or "")
        if match:
            return f"A{match.group(1)}"
    if cwe:
        category = CWE_TO_OWASP.get(int(cwe.split("-")[1]))
        if category:
            return category
    return TOOL_DEFAULT_OWASP.get(tool, "")


def _sarif_severity(tool: str, result: dict, rule: dict) -> str:
    if tool == "gitleaks":
        return "high"  # any live secret in the code is treated as high
    tags = [t.upper() for t in rule.get("properties", {}).get("tags", [])]
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if name in tags:
            return name.lower()
    score = rule.get("properties", {}).get("security-severity")
    try:
        score = float(score)
    except (TypeError, ValueError):
        score = None
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low" if score > 0 else "info"
    level = result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"
    return SARIF_LEVEL.get(level, "medium")


def _sarif_location(result: dict) -> str:
    for loc in result.get("locations", []):
        physical = loc.get("physicalLocation", {})
        uri = physical.get("artifactLocation", {}).get("uri", "")
        if not uri:
            continue
        uri = re.sub(r"^file://", "", uri)
        uri = re.sub(r"^/?src/", "", uri)  # scanners run with the repo mounted at /src
        line = physical.get("region", {}).get("startLine")
        return f"{uri}:{line}" if line else uri
    return "(no location)"


def _trivy_title(rule: dict, result: dict) -> tuple[str, str]:
    message = result.get("message", {}).get("text", "")
    # [ \t]* rather than \s*, so an empty field never swallows the next line
    fields = {k: v.strip() for k, v in re.findall(r"^([A-Za-z ]+):[ \t]*(.*)$", message, flags=re.MULTILINE)}
    package = fields.get("Package", "")
    version = fields.get("Installed Version", "")
    summary = _first_line(rule.get("shortDescription", {}).get("text", ""), 100)
    title = f"{package}@{version}: {summary}" if package else summary
    fixed = fields.get("Fixed Version", "")
    return title, (f"Fixed in {fixed}" if fixed else "No fixed version yet")


def parse_sarif(tool: str, data: dict) -> list[Finding]:
    findings = []
    for run in data.get("runs", []):
        rules_list = run.get("tool", {}).get("driver", {}).get("rules", [])
        rules = {rule.get("id"): rule for rule in rules_list}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id)
            if rule is None:
                index = result.get("ruleIndex")
                rule = rules_list[index] if isinstance(index, int) and index < len(rules_list) else {}
            tags = list(rule.get("properties", {}).get("tags", []))
            message = result.get("message", {}).get("text", "")
            short = rule.get("shortDescription", {}).get("text", "")
            full = rule.get("fullDescription", {}).get("text", "")

            detail = ""
            if tool == "trivy":
                title, detail = _trivy_title(rule, result)
            elif short and not short.startswith("Semgrep Finding"):
                title = _first_line(short)
            else:
                title = _first_line(message)

            cwe = _cwe_from(tags + [short, full])
            findings.append(Finding(
                tool=tool,
                rule_id=rule_id or "(unknown rule)",
                title=title or rule_id,
                severity=_sarif_severity(tool, result, rule),
                location=_sarif_location(result),
                owasp=_owasp_from(tags, cwe, tool),
                cwe=cwe,
                help_url=rule.get("helpUri", ""),
                detail=detail,
            ))
    return findings


def parse_zap(data: dict) -> list[Finding]:
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            plugin = str(alert.get("pluginid", ""))
            cwe_id = str(alert.get("cweid", "")).strip()
            cwe = f"CWE-{cwe_id}" if cwe_id.isdigit() and int(cwe_id) > 0 else ""
            instances = alert.get("instances", [])
            location = instances[0].get("uri", site.get("@name", "")) if instances else site.get("@name", "")
            count = len(instances)
            findings.append(Finding(
                tool="zap",
                rule_id=plugin or "(unknown rule)",
                title=alert.get("name") or alert.get("alert") or plugin,
                severity=ZAP_RISK.get(str(alert.get("riskcode", "0")), "info"),
                location=location,
                owasp=_owasp_from([], cwe, "zap"),
                cwe=cwe,
                help_url=f"https://www.zaproxy.org/docs/alerts/{plugin}/" if plugin else "",
                detail=f"{count} URL(s) affected" if count > 1 else "",
            ))
    return findings


def load_results(results_dir: Path, tools: list[str]) -> tuple[list[Finding], list[str]]:
    findings, errors = [], []
    for tool in tools:
        path = results_dir / REPORT_FILES[tool]
        if not path.is_file():
            errors.append(f"{tool}: report `{path.name}` is missing (the scanner may have crashed)")
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"{tool}: could not read `{path.name}` ({exc})")
            continue
        findings.extend(parse_zap(data) if tool == "zap" else parse_sarif(tool, data))
    return findings, errors


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen, unique = set(), []
    for finding in findings:
        if finding.key not in seen:
            seen.add(finding.key)
            unique.append(finding)
    return unique


# ---------------------------------------------------------- accepted risks

def load_accepted(path: Path | None) -> list[dict]:
    if path is None or not path.is_file():
        return []
    try:
        entries = json.loads(path.read_text(encoding="utf-8")).get("accepted", [])
    except (OSError, json.JSONDecodeError, AttributeError) as exc:
        raise ValueError(f"{path}: not valid JSON ({exc})") from exc
    for i, entry in enumerate(entries):
        missing = [k for k in ("tool", "rule_id", "reason") if not str(entry.get(k, "")).strip()]
        if missing:
            raise ValueError(f"{path}: entry {i} is missing {', '.join(missing)}")
        if entry.get("expires"):
            try:
                date.fromisoformat(entry["expires"])
            except ValueError as exc:
                raise ValueError(f"{path}: entry {i} has a bad expires date (use YYYY-MM-DD)") from exc
    return entries


def apply_accepted(findings: list[Finding], entries: list[dict], today: date) -> tuple[list[Finding], list[Finding], list[str]]:
    """Split findings into (active, accepted). Expired entries no longer apply."""
    notes, live = [], []
    for entry in entries:
        if entry.get("expires") and date.fromisoformat(entry["expires"]) < today:
            notes.append(f"Accepted risk `{entry['tool']}/{entry['rule_id']}` expired on {entry['expires']} and no longer applies")
        else:
            live.append(entry)

    active, accepted = [], []
    for finding in findings:
        match = next((e for e in live
                      if e["tool"] == finding.tool
                      and e["rule_id"] == finding.rule_id
                      and fnmatch.fnmatch(finding.location, e.get("location", "*"))), None)
        if match:
            finding.accepted_reason = match["reason"]
            accepted.append(finding)
        else:
            active.append(finding)
    return active, accepted, notes


# -------------------------------------------------------------------- gate

def blocking_findings(findings: list[Finding], fail_on: str) -> list[Finding]:
    if fail_on == "never":
        return []
    return [f for f in findings if RANK[f.severity] <= RANK[fail_on]]


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (RANK[f.severity], f.tool, f.owasp or "Z", f.location))


# ------------------------------------------------------------------ report

def _cell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _finding_rows(findings: list[Finding], with_reason: bool = False) -> list[str]:
    header = "| Severity | Scanner | OWASP | Finding | Location |"
    divider = "| --- | --- | --- | --- | --- |"
    if with_reason:
        header, divider = header + " Reason |", divider + " --- |"
    rows = [header, divider]
    for f in findings[:MAX_TABLE_ROWS]:
        title = f"[{_cell(f.title)}]({f.help_url})" if f.help_url else _cell(f.title)
        if f.detail:
            title += f" — {_cell(f.detail)}"
        owasp = f.owasp or "—"
        row = f"| {f.severity.upper()} | {f.tool} | {owasp} | {title} | `{_cell(f.location)}` |"
        if with_reason:
            row += f" {_cell(f.accepted_reason)} |"
        rows.append(row)
    if len(findings) > MAX_TABLE_ROWS:
        rows.append(f"\n_…and {len(findings) - MAX_TABLE_ROWS} more in `security-report.json`._")
    return rows


def build_markdown(active, accepted, blocking, errors, notes, fail_on, tools) -> str:
    passed = not blocking and not errors
    lines = ["## Security pipeline report", ""]
    if passed:
        lines.append(f"**Gate: ✅ PASSED** — no findings at or above **{fail_on}** severity.")
    else:
        reasons = []
        if blocking:
            reasons.append(f"{len(blocking)} finding(s) at or above **{fail_on}** severity")
        if errors:
            reasons.append(f"{len(errors)} scanner report(s) missing or unreadable")
        lines.append(f"**Gate: ❌ FAILED** — {' and '.join(reasons)}.")
    lines += ["", f"Policy: fail on `{fail_on}` and above · {len(active)} open finding(s) · {len(accepted)} accepted risk(s)", ""]

    lines += ["### Findings by scanner", "",
              "| Scanner | Layer | Critical | High | Medium | Low | Info |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    totals = dict.fromkeys(SEVERITIES, 0)
    for tool in tools:
        counts = {s: sum(1 for f in active if f.tool == tool and f.severity == s) for s in SEVERITIES}
        for s in SEVERITIES:
            totals[s] += counts[s]
        lines.append(f"| {tool} | {TOOL_LAYER[tool]} | " + " | ".join(str(counts[s]) for s in SEVERITIES) + " |")
    lines.append("| **Total** | | " + " | ".join(f"**{totals[s]}**" for s in SEVERITIES) + " |")
    lines.append("")

    by_category: dict[str, int] = {}
    for f in active:
        by_category[f.owasp or "—"] = by_category.get(f.owasp or "—", 0) + 1
    if by_category:
        lines += ["### Findings by OWASP Top 10 (2021)", "", "| Category | Findings |", "| --- | --- |"]
        for cat in sorted(by_category, key=lambda c: (c == "—", c)):
            name = f"{cat} {OWASP_2021[cat]}" if cat in OWASP_2021 else "Not mapped"
            lines.append(f"| {name} | {by_category[cat]} |")
        lines.append("")

    if errors:
        lines += ["### Scanner errors", ""] + [f"- {e}" for e in errors] + [""]

    if blocking:
        lines += ["### Blocking findings", ""] + _finding_rows(sort_findings(blocking)) + [""]

    others = [f for f in active if f not in blocking]
    if others:
        lines += ["<details>", f"<summary>Other findings ({len(others)}, below the gate threshold)</summary>", ""]
        lines += _finding_rows(sort_findings(others)) + ["", "</details>", ""]

    if accepted or notes:
        lines += ["### Accepted risks", ""]
        lines += [f"- {n}" for n in notes]
        if accepted:
            lines += ([""] if notes else []) + _finding_rows(sort_findings(accepted), with_reason=True)
        lines.append("")

    return "\n".join(lines)


# --------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--results", type=Path, required=True, help="folder holding the scanner reports")
    parser.add_argument("--accepted", type=Path, help="accepted-risks JSON file (optional)")
    parser.add_argument("--fail-on", choices=SEVERITIES[:4] + ["never"], default="high",
                        help="fail if any finding is at or above this severity (default: high)")
    parser.add_argument("--tools", default=",".join(REPORT_FILES),
                        help="comma-separated scanners to expect (default: all four)")
    parser.add_argument("--out-md", type=Path, default=Path("security-report.md"))
    parser.add_argument("--out-json", type=Path, default=Path("security-report.json"))
    args = parser.parse_args(argv)

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]
    unknown = [t for t in tools if t not in REPORT_FILES]
    if unknown:
        parser.error(f"unknown scanner(s): {', '.join(unknown)}")

    try:
        entries = load_accepted(args.accepted)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings, errors = load_results(args.results, tools)
    findings = deduplicate(findings)
    active, accepted, notes = apply_accepted(findings, entries, date.today())
    blocking = blocking_findings(active, args.fail_on)
    passed = not blocking and not errors

    markdown = build_markdown(active, accepted, blocking, errors, notes, args.fail_on, tools)
    args.out_md.write_text(markdown + "\n", encoding="utf-8")
    args.out_json.write_text(json.dumps({
        "generated": date.today().isoformat(),
        "policy": {"fail_on": args.fail_on, "scanners": tools},
        "gate": "passed" if passed else "failed",
        "errors": errors,
        "findings": [asdict(f) for f in sort_findings(active)],
        "accepted": [asdict(f) for f in sort_findings(accepted)],
    }, indent=2) + "\n", encoding="utf-8")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(markdown + "\n")

    print(f"{len(active)} open finding(s), {len(accepted)} accepted, {len(blocking)} blocking, {len(errors)} scanner error(s)")
    for error in errors:
        print(f"  error: {error}")
    print("Gate PASSED" if passed else f"Gate FAILED (policy: fail on {args.fail_on})")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
