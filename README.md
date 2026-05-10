# 抗量子迁移风险扫描平台

本项目用于识别 Python 代码中可能需要进行抗量子密码迁移的传统公钥算法用法，例如 `RSA`、`DSA`、`DH`、`ECDH`、`ECDSA`、`ECC`。

当前版本为单服务架构：只启动一次 Python 服务，FastAPI 会同时提供 Web 页面和扫描 API，不再需要分别启动前端与后端。

## 功能概览

- 支持粘贴代码片段扫描。
- 支持多文件上传扫描。
- 展示文件名、行号、算法、风险等级、证据、原因和迁移建议。
- 支持点击结果查看对应行附近代码。
- 支持导出 Markdown 扫描报告。
- 后端保留 `source_type` 字段，后续可扩展 GitHub 仓库扫描。

## 项目结构

```text
.
├── backend/                 # FastAPI API 与静态页面挂载
│   ├── main.py              # 路由、上传处理、扫描接口
│   └── reporting.py         # Markdown 报告生成
├── web/                     # 无需构建的前端页面
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── scripts/                 # Windows PowerShell 启动/关闭脚本
├── tests/                   # 扫描器与 API 测试
├── scan_quantum_vuln.py     # 核心扫描器与 CLI
├── sample_rsa_code.py       # RSA 示例代码
├── start.py                 # 一键启动入口
└── requirements.txt         # Python 依赖
```

## 安装依赖

只需要安装 Python 依赖：

```bash
pip install -r requirements.txt
```

## 一键启动

在项目根目录运行：

```bash
python start.py
```

启动成功后，终端会打印访问地址。默认地址是：

```text
http://127.0.0.1:8000
```

如果 `8000` 端口已被占用，启动脚本会自动选择 `8001` 到 `8020` 之间的下一个可用端口，并在终端中打印实际访问地址。

默认健康检查地址：

```text
http://127.0.0.1:8000/api/health
```

如果启动时使用了其他端口，把地址中的 `8000` 换成终端打印的端口即可。

## PowerShell 启动

也可以在项目根目录运行：

```powershell
.\scripts\start.ps1
```

指定偏好的端口：

```powershell
.\scripts\start.ps1 -Port 8001
```

如果不希望自动切换端口，可以开启严格模式：

```powershell
.\scripts\start.ps1 -Port 8000 -StrictPort
```

如果 Windows 阻止脚本执行，可在当前 PowerShell 窗口临时放行：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

然后重新运行：

```powershell
.\scripts\start.ps1
```

## 关闭服务

如果服务在当前终端前台运行，回到该终端按：

```text
Ctrl + C
```

如果终端已经关闭，或 `8000` 端口仍被占用，可以在项目根目录运行：

```powershell
.\scripts\stop_dev_services.ps1
```

该脚本会尝试停止监听 `8000-8020` 端口的开发服务。运行前请确认这些端口没有被其他重要程序使用。

也可以手动查看端口占用：

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen
netstat -ano | findstr :8000
```

然后按需停止对应进程：

```powershell
Stop-Process -Id <PID>
```

## API 接口

页面和 API 都由同一个服务提供，默认地址为 `http://127.0.0.1:8000`。

- `GET /`：Web 可视化页面。
- `GET /api/health`：服务健康检查。
- `POST /api/scan/snippet`：扫描粘贴的代码片段。
- `POST /api/scan/files`：扫描上传的多个代码文件。
- `POST /api/report/markdown`：根据扫描结果生成 Markdown 报告。

## 命令行扫描

扫描示例文件：

```bash
python -B scan_quantum_vuln.py sample_rsa_code.py
```

输出 JSON：

```bash
python -B scan_quantum_vuln.py sample_rsa_code.py --json
```

示例输出：

```text
【高风险】在第15行发现量子脆弱算法：RSA
  证据：rsa.generate_private_key
  原因：RSA 依赖大整数分解，Shor 算法可在容错量子计算环境下高效破解。
  建议：密钥建立迁移到 FIPS 203 ML-KEM；签名迁移到 FIPS 204 ML-DSA。
```

## 风险样例文件

项目内置了一组用于 Web 上传测试的风险代码样例：

```text
sample_inputs/
├── risky_rsa_cryptography.py
├── risky_dh_dsa_cryptography.py
├── risky_ecc_cryptography.py
├── risky_pycryptodome_rsa_dsa.py
├── risky_ecdsa_library.py
└── risky_partial_syntax_fallback.py
```

这些文件是故意写入传统公钥算法用法的测试输入，不需要实际运行。启动服务后，可以在页面中选择“多文件上传”，一次性上传 `sample_inputs` 目录下的 `.py` 文件进行测试。

## 测试

运行扫描器和 API 测试：

```bash
python -B -m unittest discover -s tests -v
```

## 常见问题

- 访问页面无响应：确认 `python start.py` 仍在运行。
- 提示端口被占用：`python start.py` 和 `.\scripts\start.ps1` 会自动切换到下一个可用端口；也可以运行 `.\scripts\stop_dev_services.ps1` 清理旧服务。
- PowerShell 无法运行脚本：使用 `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` 临时放行当前窗口。
- 不需要再启动 `5173` 端口；整个项目现在只使用 `8000` 端口。

## 后续扩展方向

- 支持输入 GitHub 仓库地址，拉取项目后批量扫描。
- 增加异步任务、扫描进度和历史记录。
- 支持 CSV、JSON、PDF 等更多导出格式。
- 扩展 Java、Go、JavaScript 等语言的算法识别规则。
