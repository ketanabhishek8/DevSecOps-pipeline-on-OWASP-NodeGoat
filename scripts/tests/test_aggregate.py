"""Unit tests for scripts/aggregate.py. Run: python -m unittest discover -s scripts/tests -v"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import aggregate  # noqa: E402

SEMGREP = {"runs": [{
    "tool": {"driver": {"name": "Semgrep OSS", "rules": [{
        "id": "javascript.express.security.audit.express-nosql-injection",
        "shortDescription": {"text": "Semgrep Finding: javascript.express.security.audit.express-nosql-injection"},
        "defaultConfiguration": {"level": "error"},
        "helpUri": "https://semgrep.dev/r/example",
        "properties": {"tags": ["CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
                                "OWASP-A03:2021 - Injection", "HIGH CONFIDENCE", "security"]},
    }]}},
    "results": [{
        "ruleId": "javascript.express.security.audit.express-nosql-injection",
        "level": "error",
        "message": {"text": "User input flows into a MongoDB query.\nMore detail here."},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/app/data/allocations-dao.js"},
                                            "region": {"startLine": 77}}}],
    }],
}]}

TRIVY = {"runs": [{
    "tool": {"driver": {"name": "Trivy", "rules": [{
        "id": "CVE-0000-0001",
        "shortDescription": {"text": "marked: regular expression denial of service"},
        "helpUri": "https://avd.aquasec.com/nvd/cve-0000-0001",
        "properties": {"security-severity": "7.5", "tags": ["vulnerability", "security", "HIGH"]},
    }]}},
    "results": [{
        "ruleId": "CVE-0000-0001",
        "ruleIndex": 0,
        "level": "error",
        "message": {"text": "Package: marked\nInstalled Version: 0.3.5\nVulnerability CVE-0000-0001\n"
                            "Severity: HIGH\nFixed Version: 0.3.9"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/package-lock.json"},
                                            "region": {"startLine": 4210}}}],
    }],
}]}

GITLEAKS = {"runs": [{
    "tool": {"driver": {"name": "gitleaks", "rules": [{
        "id": "generic-api-key",
        "shortDescription": {"text": "Detected a Generic API Key"},
    }]}},
    "results": [{
        "ruleId": "generic-api-key",
        "message": {"text": "generic-api-key has detected secret for file app/config/env/test.js."},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/src/app/config/env/test.js"},
                                            "region": {"startLine": 6}}}],
    }],
}]}

ZAP = {"site": [{"@name": "http://localhost:4000", "alerts": [
    {"pluginid": "10038", "name": "Content Security Policy (CSP) Header Not Set",
     "riskcode": "2", "cweid": "693",
     "instances": [{"uri": "http://localhost:4000/login"}, {"uri": "http://localhost:4000/signup"}]},
    {"pluginid": "10010", "name": "Cookie No HttpOnly Flag", "riskcode": "1", "cweid": "1004",
     "instances": [{"uri": "http://localhost:4000/login"}]},
]}]}


def write_reports(folder: Path, skip: str = "") -> None:
    reports = {"semgrep.sarif": SEMGREP, "trivy.sarif": TRIVY, "gitleaks.sarif": GITLEAKS, "zap.json": ZAP}
    for name, data in reports.items():
        if name != skip:
            (folder / name).write_text(json.dumps(data), encoding="utf-8")


class ParsingTests(unittest.TestCase):
    def test_semgrep_uses_owasp_tag_and_message_title(self):
        [f] = aggregate.parse_sarif("semgrep", SEMGREP)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.owasp, "A03")
        self.assertEqual(f.cwe, "CWE-943")
        self.assertEqual(f.location, "app/app/data/allocations-dao.js:77")
        self.assertEqual(f.title, "User input flows into a MongoDB query.")

    def test_trivy_title_names_package_and_fix(self):
        [f] = aggregate.parse_sarif("trivy", TRIVY)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.owasp, "A06")
        self.assertTrue(f.title.startswith("marked@0.3.5:"))
        self.assertEqual(f.detail, "Fixed in 0.3.9")

    def test_gitleaks_is_high_and_strips_mount_path(self):
        [f] = aggregate.parse_sarif("gitleaks", GITLEAKS)
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.owasp, "A07")
        self.assertEqual(f.location, "app/config/env/test.js:6")

    def test_zap_maps_risk_and_cwe(self):
        csp, cookie = aggregate.parse_zap(ZAP)
        self.assertEqual((csp.severity, csp.owasp, csp.detail), ("medium", "A05", "2 URL(s) affected"))
        self.assertEqual((cookie.severity, cookie.owasp), ("low", "A05"))

    def test_duplicates_are_dropped(self):
        findings = aggregate.parse_sarif("semgrep", SEMGREP) * 2
        self.assertEqual(len(aggregate.deduplicate(findings)), 1)


class GateTests(unittest.TestCase):
    def setUp(self):
        self.findings = aggregate.parse_sarif("trivy", TRIVY) + aggregate.parse_zap(ZAP)

    def test_threshold(self):
        self.assertEqual(len(aggregate.blocking_findings(self.findings, "high")), 1)
        self.assertEqual(len(aggregate.blocking_findings(self.findings, "critical")), 0)
        self.assertEqual(len(aggregate.blocking_findings(self.findings, "medium")), 2)
        self.assertEqual(aggregate.blocking_findings(self.findings, "never"), [])

    def test_accepted_risk_is_set_aside(self):
        entries = [{"tool": "trivy", "rule_id": "CVE-0000-0001", "reason": "Not reachable", "expires": "2999-01-01"}]
        active, accepted, notes = aggregate.apply_accepted(self.findings, entries, date(2026, 1, 1))
        self.assertEqual([f.rule_id for f in accepted], ["CVE-0000-0001"])
        self.assertEqual(aggregate.blocking_findings(active, "high"), [])
        self.assertEqual(notes, [])

    def test_expired_acceptance_no_longer_applies(self):
        entries = [{"tool": "trivy", "rule_id": "CVE-0000-0001", "reason": "Old", "expires": "2020-01-01"}]
        active, accepted, notes = aggregate.apply_accepted(self.findings, entries, date(2026, 1, 1))
        self.assertEqual(accepted, [])
        self.assertEqual(len(notes), 1)

    def test_location_glob(self):
        entries = [{"tool": "zap", "rule_id": "10038", "location": "*/signup", "reason": "x"}]
        _, accepted, _ = aggregate.apply_accepted(self.findings, entries, date(2026, 1, 1))
        self.assertEqual(accepted, [])  # first instance is /login, so no match


class EndToEndTests(unittest.TestCase):
    def run_main(self, *extra, skip=""):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            write_reports(tmp, skip=skip)
            # Keep the gate's console output out of the test log, so CI logs
            # don't show fake "missing report" errors from these fixtures.
            with contextlib.redirect_stdout(io.StringIO()):
                code = aggregate.main(["--results", str(tmp), "--out-md", str(tmp / "r.md"),
                                       "--out-json", str(tmp / "r.json"), *extra])
            return code, (tmp / "r.md").read_text(), json.loads((tmp / "r.json").read_text())

    def test_fails_on_high(self):
        code, md, data = self.run_main("--fail-on", "high")
        self.assertEqual(code, 1)
        self.assertIn("Gate: ❌ FAILED", md)
        self.assertEqual(data["gate"], "failed")
        self.assertEqual(len(data["findings"]), 5)

    def test_passes_when_threshold_not_reached(self):
        code, md, _ = self.run_main("--fail-on", "critical")
        self.assertEqual(code, 0)
        self.assertIn("Gate: ✅ PASSED", md)

    def test_missing_report_fails_closed(self):
        code, md, data = self.run_main("--fail-on", "never", skip="zap.json")
        self.assertEqual(code, 1)
        self.assertIn("zap.json", data["errors"][0])
        self.assertIn("Scanner errors", md)

    def test_invalid_accepted_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "accepted.json"
            bad.write_text(json.dumps({"accepted": [{"tool": "zap", "rule_id": "10038"}]}))
            with self.assertRaises(ValueError):
                aggregate.load_accepted(bad)

    def test_table_cells_escape_pipes(self):
        f = aggregate.Finding("zap", "1", "a | b", "high", "x")
        self.assertIn("a \\| b", "\n".join(aggregate._finding_rows([f])))


if __name__ == "__main__":
    unittest.main()
