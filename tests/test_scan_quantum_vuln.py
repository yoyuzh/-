import subprocess
import sys
import unittest
from pathlib import Path

from scan_quantum_vuln import (
    format_findings,
    scan_code_for_crypto,
    scan_source_for_crypto,
    scan_with_regex,
)


class QuantumScannerTests(unittest.TestCase):
    def test_detects_rsa_usage_in_sample_file(self) -> None:
        findings = scan_code_for_crypto("sample_rsa_code.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["algorithm"], "RSA")
        self.assertEqual(findings[0]["line"], 15)
        self.assertEqual(findings[0]["file_name"], "sample_rsa_code.py")
        self.assertIn("高风险", findings[0]["risk_level"])

    def test_formats_human_readable_summary(self) -> None:
        findings = scan_code_for_crypto("sample_rsa_code.py")
        summary = format_findings(findings)
        self.assertIn("发现量子脆弱算法：RSA", summary)
        self.assertIn("第15行", summary)

    def test_regex_fallback_ignores_strings_and_comments(self) -> None:
        source = "\n".join(
            [
                "# rsa.generate_private_key() should not be reported",
                'doc = "rsa.generate_private_key()"',
                "message = 'ECDH() is only text here'",
            ]
        )
        findings = scan_with_regex(source)
        self.assertEqual(findings, [])

    def test_syntax_error_fallback_still_detects_alias_usage(self) -> None:
        broken_source = "\n".join(
            [
                "from cryptography.hazmat.primitives.asymmetric import ec as curves",
                "signature = curves.ECDSA(",
            ]
        )
        findings = scan_source_for_crypto(broken_source, filename="broken_sample.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["algorithm"], "ECDSA")
        self.assertEqual(findings[0]["line"], 2)
        self.assertEqual(findings[0]["file_name"], "broken_sample.py")

    def test_plain_method_names_do_not_trigger_false_positives(self) -> None:
        source = "\n".join(
            [
                "curve_helper.ECDH()",
                "service.rsa.generate_private_key()",
                "SigningKey.generate()",
            ]
        )
        findings = scan_source_for_crypto(source, filename="safe_sample.py")
        self.assertEqual(findings, [])

    def test_missing_file_returns_non_zero_exit_code(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "-B", "scan_quantum_vuln.py", "missing_demo_file.py"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("扫描失败", result.stderr)


if __name__ == "__main__":
    unittest.main()
