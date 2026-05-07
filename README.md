# 量子脆弱算法扫描演示

这个原型用于答辩演示“从代码中自动发现量子脆弱算法”的能力，重点展示对 `RSA`、`DSA`、`DH`、`ECDH`、`ECDSA`、`ECC` 等经典公钥算法的识别。

## 演示目标

输入一段 Python 代码，例如：

- `from cryptography.hazmat.primitives.asymmetric import rsa`
- `rsa.generate_private_key(...)`

输出类似：

```text
【高风险】在第15行发现量子脆弱算法：RSA
  证据：rsa.generate_private_key
  原因：RSA 依赖大整数分解，Shor 算法可在容错量子计算环境下高效破解。
  建议：密钥建立迁移到 FIPS 203 ML-KEM；签名迁移到 FIPS 204 ML-DSA。
```

## 运行方式

```bash
python3 scan_quantum_vuln.py sample_rsa_code.py
```

如果你想输出 JSON，方便接入后续系统：

```bash
python3 scan_quantum_vuln.py sample_rsa_code.py --json
```

## 实现思路

- 优先使用 `ast` 解析 Python 语法树，识别导入、别名和函数调用。
- 使用轻量正则表达式作为兜底方案，避免语法不完整时代码完全漏报。
- 输出风险等级、所在行号、证据、风险原因和后量子迁移建议。

## 演示文件

- 扫描器脚本：`scan_quantum_vuln.py`
- RSA 示例输入：`sample_rsa_code.py`
- 回归测试：`tests/test_scan_quantum_vuln.py`
