import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scan_quantum_vuln import format_findings, scan_code_for_crypto, scan_with_regex


class QuantumScannerTests(unittest.TestCase):
    def test_detects_rsa_usage_in_sample_file(self) -> None:
        findings = scan_code_for_crypto("sample_rsa_code.py")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["algorithm"], "RSA")
        self.assertEqual(findings[0]["line"], 15)
        self.assertIn("高风险", findings[0]["risk_level"])

    def test_formats_human_readable_summary(self) -> None:
        findings = scan_code_for_crypto("sample_rsa_code.py")
        summary = format_findings(findings)
        self.assertIn("发现量子脆弱算法：RSA", summary)
        self.assertIn("第15行", summary)

    def test_regex_fallback_ignores_strings_and_comments(self) -> None:
        source = '\n'.join(
            [
                '# rsa.generate_private_key() should not be reported',
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
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "broken_sample.py"
            test_file.write_text(broken_source, encoding="utf-8")
            findings = scan_code_for_crypto(test_file)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["algorithm"], "ECDSA")
        self.assertEqual(findings[0]["line"], 2)

    def test_plain_method_names_do_not_trigger_false_positives(self) -> None:
        source = "\n".join(
            [
                "curve_helper.ECDH()",
                "service.rsa.generate_private_key()",
                "SigningKey.generate()",
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            test_file = Path(temp_dir) / "safe_sample.py"
            test_file.write_text(source, encoding="utf-8")
            findings = scan_code_for_crypto(test_file)
        self.assertEqual(findings, [])

    def test_missing_file_returns_non_zero_exit_code(self) -> None:
        result = subprocess.run(
            [sys.executable, "scan_quantum_vuln.py", "missing_demo_file.py"],
            cwd="/Users/mac/Documents/daChuang",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("扫描失败", result.stderr)


if __name__ == "__main__":
    unittest.main()
