#!/usr/bin/env python3
"""Scan Python source files for quantum-vulnerable cryptographic algorithms."""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import re
import sys
import tokenize
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class AlgorithmProfile:
    name: str
    risk_level: str
    reason: str
    recommendation: str


@dataclass(frozen=True)
class Finding:
    line: int
    algorithm: str
    risk_level: str
    reason: str
    recommendation: str
    evidence: str


VULNERABLE_ALGOS: dict[str, AlgorithmProfile] = {
    "rsa": AlgorithmProfile(
        name="RSA",
        risk_level="高风险",
        reason="RSA 依赖大整数分解，Shor 算法可在容错量子计算环境下高效破解。",
        recommendation="密钥建立迁移到 FIPS 203 ML-KEM；签名迁移到 FIPS 204 ML-DSA。",
    ),
    "dsa": AlgorithmProfile(
        name="DSA",
        risk_level="高风险",
        reason="DSA 依赖离散对数难题，面向量子攻击时不再安全。",
        recommendation="使用 FIPS 204 ML-DSA 或其他后量子签名方案替代。",
    ),
    "dh": AlgorithmProfile(
        name="DH",
        risk_level="高风险",
        reason="Diffie-Hellman 依赖离散对数难题，Shor 算法可显著削弱其安全性。",
        recommendation="密钥交换迁移到 FIPS 203 ML-KEM。",
    ),
    "ecdh": AlgorithmProfile(
        name="ECDH",
        risk_level="高风险",
        reason="ECDH 建立在椭圆曲线离散对数问题之上，量子计算可高效求解。",
        recommendation="密钥交换迁移到 FIPS 203 ML-KEM。",
    ),
    "ecdsa": AlgorithmProfile(
        name="ECDSA",
        risk_level="高风险",
        reason="ECDSA 的安全性依赖椭圆曲线离散对数问题，量子攻击下存在根本风险。",
        recommendation="签名迁移到 FIPS 204 ML-DSA。",
    ),
    "ecc": AlgorithmProfile(
        name="ECC",
        risk_level="高风险",
        reason="ECC 家族依赖椭圆曲线离散对数问题，量子算法可系统性破坏其安全假设。",
        recommendation="按用途迁移到 FIPS 203 ML-KEM 或 FIPS 204 ML-DSA。",
    ),
}


DIRECT_REGEX_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "rsa",
        re.compile(r"\bcryptography\.hazmat\.primitives\.asymmetric\.rsa\.generate_private_key\s*\("),
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key",
    ),
    ("rsa", re.compile(r"\bRSA\.generate\s*\("), "RSA.generate"),
    ("dsa", re.compile(r"\bDSA\.generate\s*\("), "DSA.generate"),
    (
        "dh",
        re.compile(r"\bcryptography\.hazmat\.primitives\.asymmetric\.dh\.generate_parameters\s*\("),
        "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters",
    ),
    (
        "ecc",
        re.compile(r"\bcryptography\.hazmat\.primitives\.asymmetric\.ec\.generate_private_key\s*\("),
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
    ),
    (
        "ecdh",
        re.compile(r"\bcryptography\.hazmat\.primitives\.asymmetric\.ec\.ECDH\s*\("),
        "cryptography.hazmat.primitives.asymmetric.ec.ECDH",
    ),
    (
        "ecdsa",
        re.compile(r"\bcryptography\.hazmat\.primitives\.asymmetric\.ec\.ECDSA\s*\("),
        "cryptography.hazmat.primitives.asymmetric.ec.ECDSA",
    ),
    ("ecdsa", re.compile(r"\becdsa\.SigningKey\.generate\s*\("), "ecdsa.SigningKey.generate"),
)


ALIAS_REGEX_RULES: dict[str, tuple[tuple[str, str, str], ...]] = {
    "rsa": (
        ("rsa", r"\b{alias}\.generate_private_key\s*\(", "{alias}.generate_private_key"),
        ("rsa", r"\b{alias}\.generate\s*\(", "{alias}.generate"),
    ),
    "dsa": (
        ("dsa", r"\b{alias}\.generate_private_key\s*\(", "{alias}.generate_private_key"),
        ("dsa", r"\b{alias}\.generate\s*\(", "{alias}.generate"),
    ),
    "dh": (
        ("dh", r"\b{alias}\.generate_parameters\s*\(", "{alias}.generate_parameters"),
        ("dh", r"\b{alias}\.generate_private_key\s*\(", "{alias}.generate_private_key"),
    ),
    "ecc": (
        ("ecc", r"\b{alias}\.generate_private_key\s*\(", "{alias}.generate_private_key"),
        ("ecdh", r"\b{alias}\.ECDH\s*\(", "{alias}.ECDH"),
        ("ecdsa", r"\b{alias}\.ECDSA\s*\(", "{alias}.ECDSA"),
    ),
    "ecdh": (
        ("ecdh", r"\b{alias}\s*\(", "{alias}"),
    ),
    "ecdsa": (
        ("ecdsa", r"\b{alias}\s*\(", "{alias}"),
        ("ecdsa", r"\b{alias}\.generate\s*\(", "{alias}.generate"),
    ),
}


MODULE_HINTS: tuple[tuple[str, str], ...] = (
    ("cryptography.hazmat.primitives.asymmetric.rsa", "rsa"),
    ("cryptography.hazmat.primitives.asymmetric.dsa", "dsa"),
    ("cryptography.hazmat.primitives.asymmetric.dh", "dh"),
    ("cryptography.hazmat.primitives.asymmetric.ec", "ecc"),
    ("Crypto.PublicKey.RSA", "rsa"),
    ("Crypto.PublicKey.DSA", "dsa"),
    ("ecdsa", "ecdsa"),
)


NAME_HINTS: dict[str, str] = {
    "rsa": "rsa",
    "dsa": "dsa",
    "dh": "dh",
    "ecdh": "ecdh",
    "ecdsa": "ecdsa",
    "ecc": "ecc",
    "ec": "ecc",
    "ellipticcurve": "ecc",
}


def match_module_hint(module_name: str) -> str | None:
    lowered = module_name.lower()
    for prefix, algorithm_key in MODULE_HINTS:
        if lowered == prefix.lower() or lowered.startswith(f"{prefix.lower()}."):
            return algorithm_key
    return None


def classify_name(raw_name: str) -> str | None:
    tokens = [token for token in re.split(r"[^a-zA-Z0-9_]+", raw_name.lower()) if token]
    for token in tokens:
        if token in NAME_HINTS:
            return NAME_HINTS[token]
    return None


def get_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_dotted_name(node.value)
        if parent:
            return f"{parent}.{node.attr}"
        return node.attr
    return None


class QuantumCryptoVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.findings: list[Finding] = []
        self._seen_keys: set[tuple[int, str, str]] = set()

    def add_finding(self, line: int, algorithm_key: str, evidence: str) -> None:
        profile = VULNERABLE_ALGOS[algorithm_key]
        finding = Finding(
            line=line,
            algorithm=profile.name,
            risk_level=profile.risk_level,
            reason=profile.reason,
            recommendation=profile.recommendation,
            evidence=evidence,
        )
        key = (finding.line, finding.algorithm, finding.evidence)
        if key not in self._seen_keys:
            self.findings.append(finding)
            self._seen_keys.add(key)

    def register_alias(self, alias: str, algorithm_key: str) -> None:
        self.aliases[alias] = algorithm_key

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            algorithm_key = match_module_hint(alias.name)
            if algorithm_key:
                self.register_alias(alias.asname or alias.name.split(".")[-1], algorithm_key)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module_name = node.module or ""
        parent_algorithm = match_module_hint(module_name)
        for alias in node.names:
            raw_target = alias.asname or alias.name
            algorithm_key = classify_name(alias.name) or parent_algorithm
            if algorithm_key:
                self.register_alias(raw_target, algorithm_key)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        dotted_name = get_dotted_name(node.func)
        if dotted_name:
            algorithm_key = self.resolve_algorithm_from_call(dotted_name)
            if algorithm_key:
                self.add_finding(node.lineno, algorithm_key, dotted_name)
        self.generic_visit(node)

    def resolve_algorithm_from_call(self, dotted_name: str) -> str | None:
        parts = dotted_name.split(".")
        if not parts:
            return None

        alias_algorithm = self.aliases.get(parts[0])
        if alias_algorithm:
            return resolve_alias_call(alias_algorithm, parts)
        return resolve_direct_call(dotted_name)


def resolve_alias_call(alias_algorithm: str, parts: list[str]) -> str | None:
    last_part = parts[-1]
    if alias_algorithm == "rsa" and last_part in {"generate_private_key", "generate"}:
        return "rsa"
    if alias_algorithm == "dsa" and last_part in {"generate_private_key", "generate"}:
        return "dsa"
    if alias_algorithm == "dh" and last_part in {"generate_parameters", "generate_private_key"}:
        return "dh"
    if alias_algorithm == "ecc" and last_part == "generate_private_key":
        return "ecc"
    if alias_algorithm == "ecc" and last_part == "ECDH":
        return "ecdh"
    if alias_algorithm == "ecc" and last_part == "ECDSA":
        return "ecdsa"
    if alias_algorithm == "ecdh" and len(parts) == 1:
        return "ecdh"
    if alias_algorithm == "ecdsa" and len(parts) == 1:
        return "ecdsa"
    if alias_algorithm == "ecdsa" and last_part == "generate":
        return "ecdsa"
    return None


def resolve_direct_call(dotted_name: str) -> str | None:
    known_direct_calls = {
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": "rsa",
        "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": "dsa",
        "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters": "dh",
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": "ecc",
        "cryptography.hazmat.primitives.asymmetric.ec.ECDH": "ecdh",
        "cryptography.hazmat.primitives.asymmetric.ec.ECDSA": "ecdsa",
        "Crypto.PublicKey.RSA.generate": "rsa",
        "Crypto.PublicKey.DSA.generate": "dsa",
        "ecdsa.SigningKey.generate": "ecdsa",
    }
    return known_direct_calls.get(dotted_name)


def analyze_with_ast(source: str) -> QuantumCryptoVisitor:
    tree = ast.parse(source)
    visitor = QuantumCryptoVisitor()
    visitor.visit(tree)
    return visitor


def scan_with_ast(source: str) -> list[Finding]:
    visitor = analyze_with_ast(source)
    return sorted(visitor.findings, key=lambda item: (item.line, item.algorithm))


def strip_strings_and_comments(source: str) -> str:
    lines = [list(line) for line in source.splitlines(keepends=True)]
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token_info in tokens:
            if token_info.type not in {tokenize.STRING, tokenize.COMMENT}:
                continue
            (start_line, start_col) = token_info.start
            (end_line, end_col) = token_info.end
            for line_index in range(start_line - 1, end_line):
                line = lines[line_index]
                from_col = start_col if line_index == start_line - 1 else 0
                to_col = end_col if line_index == end_line - 1 else len(line)
                for col in range(from_col, min(to_col, len(line))):
                    if line[col] != "\n":
                        line[col] = " "
    except tokenize.TokenError:
        pass
    return "".join("".join(line) for line in lines)


def extract_aliases_from_source(source: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        import_match = re.match(r"import\s+(.+)$", line)
        if import_match:
            for item in import_match.group(1).split(","):
                cleaned = item.strip()
                match = re.fullmatch(r"([A-Za-z0-9_\.]+)(?:\s+as\s+([A-Za-z0-9_]+))?", cleaned)
                if not match:
                    continue
                module_name, alias = match.groups()
                algorithm_key = match_module_hint(module_name)
                if algorithm_key:
                    aliases[alias or module_name.split(".")[-1]] = algorithm_key
            continue

        from_match = re.match(r"from\s+([A-Za-z0-9_\.]+)\s+import\s+(.+)$", line)
        if not from_match:
            continue
        module_name, imports_clause = from_match.groups()
        parent_algorithm = match_module_hint(module_name)
        for item in imports_clause.split(","):
            cleaned = item.strip().strip("()")
            match = re.fullmatch(r"([A-Za-z0-9_]+)(?:\s+as\s+([A-Za-z0-9_]+))?", cleaned)
            if not match:
                continue
            imported_name, alias = match.groups()
            algorithm_key = classify_name(imported_name) or parent_algorithm
            if algorithm_key:
                aliases[alias or imported_name] = algorithm_key
    return aliases


def scan_with_regex(source: str, aliases: dict[str, str] | None = None) -> list[Finding]:
    sanitized_source = strip_strings_and_comments(source)
    effective_aliases = aliases or extract_aliases_from_source(sanitized_source)
    findings: list[Finding] = []
    seen_keys: set[tuple[int, str]] = set()
    for line_number, line in enumerate(sanitized_source.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue

        for algorithm_key, pattern, evidence in DIRECT_REGEX_RULES:
            if not pattern.search(line):
                continue
            profile = VULNERABLE_ALGOS[algorithm_key]
            finding = Finding(
                line=line_number,
                algorithm=profile.name,
                risk_level=profile.risk_level,
                reason=profile.reason,
                recommendation=profile.recommendation,
                evidence=evidence,
            )
            key = (finding.line, finding.algorithm)
            if key not in seen_keys:
                findings.append(finding)
                seen_keys.add(key)

        for alias, base_algorithm in effective_aliases.items():
            for reported_algorithm, pattern_template, evidence_template in ALIAS_REGEX_RULES.get(
                base_algorithm, ()
            ):
                pattern = re.compile(pattern_template.format(alias=re.escape(alias)))
                if not pattern.search(line):
                    continue
                profile = VULNERABLE_ALGOS[reported_algorithm]
                finding = Finding(
                    line=line_number,
                    algorithm=profile.name,
                    risk_level=profile.risk_level,
                    reason=profile.reason,
                    recommendation=profile.recommendation,
                    evidence=evidence_template.format(alias=alias),
                )
                key = (finding.line, finding.algorithm)
                if key not in seen_keys:
                    findings.append(finding)
                    seen_keys.add(key)
    return sorted(findings, key=lambda item: (item.line, item.algorithm))


def merge_findings(findings: Iterable[Finding]) -> list[Finding]:
    merged_by_location: dict[tuple[int, str], Finding] = {}
    for finding in findings:
        key = (finding.line, finding.algorithm)
        if key not in merged_by_location:
            merged_by_location[key] = finding
    return sorted(
        merged_by_location.values(),
        key=lambda item: (item.line, item.algorithm, item.evidence),
    )


def make_source_id(filename: str, source: str) -> str:
    digest = hashlib.sha256(f"{filename}\0{source}".encode("utf-8")).hexdigest()
    return f"src_{digest[:12]}"


def scan_source_for_crypto(
    source: str,
    filename: str = "snippet.py",
    source_type: str = "snippet",
    source_id: str | None = None,
) -> list[dict[str, str | int]]:
    try:
        visitor = analyze_with_ast(source)
        ast_findings = sorted(visitor.findings, key=lambda item: (item.line, item.algorithm))
        aliases = visitor.aliases
    except SyntaxError:
        ast_findings = []
        aliases = extract_aliases_from_source(strip_strings_and_comments(source))

    regex_findings = scan_with_regex(source, aliases=aliases)
    findings = merge_findings([*ast_findings, *regex_findings])
    resolved_source_id = source_id or make_source_id(filename, source)
    return [
        {
            **asdict(item),
            "source_id": resolved_source_id,
            "file_name": filename,
            "source_type": source_type,
        }
        for item in findings
    ]


def scan_code_for_crypto(file_path: str | Path) -> list[dict[str, str | int]]:
    path = Path(file_path)
    source = path.read_text(encoding="utf-8")
    return scan_source_for_crypto(source, filename=path.name, source_type="manual_upload")


def format_findings(findings: list[dict[str, str | int]]) -> str:
    if not findings:
        return "未发现量子脆弱算法。"

    lines: list[str] = []
    for finding in findings:
        lines.append(
            f"【{finding['risk_level']}】在第{finding['line']}行发现量子脆弱算法：{finding['algorithm']}"
        )
        lines.append(f"  证据：{finding['evidence']}")
        lines.append(f"  原因：{finding['reason']}")
        lines.append(f"  建议：{finding['recommendation']}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="扫描 Python 代码中的量子脆弱密码算法。")
    parser.add_argument(
        "file",
        nargs="?",
        default="sample_rsa_code.py",
        help="待扫描的 Python 文件路径，默认扫描 sample_rsa_code.py",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出扫描结果。",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        findings = scan_code_for_crypto(args.file)
    except OSError as exc:
        print(f"扫描失败：{exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
    else:
        print(format_findings(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
