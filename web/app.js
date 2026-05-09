const exampleCode = [
  "from cryptography.hazmat.primitives.asymmetric import rsa",
  "",
  "private_key = rsa.generate_private_key(",
  "    public_exponent=65537,",
  "    key_size=2048,",
  ")",
].join("\n");

const state = {
  mode: "snippet",
  files: [],
  result: null,
  selectedFinding: null,
};

const elements = {
  snippetMode: document.querySelector("#snippetMode"),
  fileMode: document.querySelector("#fileMode"),
  snippetPanel: document.querySelector("#snippetPanel"),
  filePanel: document.querySelector("#filePanel"),
  snippetFilename: document.querySelector("#snippetFilename"),
  snippetContent: document.querySelector("#snippetContent"),
  fileInput: document.querySelector("#fileInput"),
  fileList: document.querySelector("#fileList"),
  scanButton: document.querySelector("#scanButton"),
  exportReport: document.querySelector("#exportReport"),
  errorBanner: document.querySelector("#errorBanner"),
  sourceCount: document.querySelector("#sourceCount"),
  findingCount: document.querySelector("#findingCount"),
  algorithmCount: document.querySelector("#algorithmCount"),
  emptyState: document.querySelector("#emptyState"),
  resultGroups: document.querySelector("#resultGroups"),
  previewTitle: document.querySelector("#previewTitle"),
  previewLine: document.querySelector("#previewLine"),
  codePreview: document.querySelector("#codePreview"),
};

elements.snippetContent.value = exampleCode;

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setMode(mode) {
  state.mode = mode;
  elements.snippetMode.classList.toggle("active", mode === "snippet");
  elements.fileMode.classList.toggle("active", mode === "files");
  elements.snippetPanel.classList.toggle("hidden", mode !== "snippet");
  elements.filePanel.classList.toggle("hidden", mode !== "files");
  updateScanButton();
}

function showError(message) {
  if (!message) {
    elements.errorBanner.classList.add("hidden");
    elements.errorBanner.textContent = "";
    return;
  }
  elements.errorBanner.textContent = message;
  elements.errorBanner.classList.remove("hidden");
}

function updateScanButton(isScanning = false) {
  const disabled = isScanning || (state.mode === "files" && state.files.length === 0);
  elements.scanButton.disabled = disabled;
  elements.scanButton.textContent = isScanning ? "扫描中" : "开始扫描";
}

function renderFileList() {
  if (state.files.length === 0) {
    elements.fileList.innerHTML = '<span class="muted">尚未选择文件</span>';
    return;
  }
  elements.fileList.innerHTML = state.files
    .map((file) => `<span class="file-pill">${escapeHtml(file.name)}</span>`)
    .join("");
}

async function requestJson(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = response.statusText;
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch {
      // Keep the HTTP status text if the response is not JSON.
    }
    throw new Error(message);
  }
  return response.json();
}

async function scanSnippet() {
  return requestJson("/api/scan/snippet", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      filename: elements.snippetFilename.value || "snippet.py",
      content: elements.snippetContent.value,
    }),
  });
}

async function scanFiles() {
  const formData = new FormData();
  state.files.forEach((file) => formData.append("files", file, file.name));
  return requestJson("/api/scan/files", {
    method: "POST",
    body: formData,
  });
}

function groupFindings(findings) {
  return findings.reduce((groups, finding) => {
    groups[finding.file_name] = groups[finding.file_name] || [];
    groups[finding.file_name].push(finding);
    return groups;
  }, {});
}

function sourceForFinding(finding) {
  if (!state.result) {
    return null;
  }
  if (!finding) {
    return state.result.sources[0] || null;
  }
  return state.result.sources.find((source) => source.source_id === finding.source_id) || null;
}

function renderPreview() {
  const source = sourceForFinding(state.selectedFinding);
  if (!source) {
    elements.previewTitle.textContent = "代码预览";
    elements.previewLine.textContent = "";
    elements.codePreview.className = "preview-empty";
    elements.codePreview.textContent = "暂无代码内容";
    return;
  }

  const targetLine = state.selectedFinding ? state.selectedFinding.line : 1;
  const lines = source.content.split(/\r?\n/);
  const start = Math.max(1, targetLine - 3);
  const end = Math.min(lines.length, targetLine + 3);
  const visible = lines.slice(start - 1, end);

  elements.previewTitle.textContent = source.file_name;
  elements.previewLine.textContent = state.selectedFinding ? `第 ${targetLine} 行` : "";
  elements.codePreview.className = "";
  elements.codePreview.innerHTML = visible
    .map((line, index) => {
      const number = start + index;
      const active = number === targetLine ? " active-line" : "";
      return `<code class="code-line${active}"><span class="line-number">${number}</span>${escapeHtml(
        line || " "
      )}</code>`;
    })
    .join("");
}

function renderResults() {
  const result = state.result;
  const sources = result ? result.summary.source_count : 0;
  const findings = result ? result.summary.finding_count : 0;
  const algorithms = result ? Object.keys(result.summary.algorithm_counts).length : 0;

  elements.sourceCount.textContent = sources;
  elements.findingCount.textContent = findings;
  elements.algorithmCount.textContent = algorithms;
  elements.exportReport.disabled = !result;

  if (!result) {
    elements.emptyState.className = "empty-state";
    elements.emptyState.textContent = "等待扫描";
    elements.resultGroups.classList.add("hidden");
    renderPreview();
    return;
  }

  if (result.findings.length === 0) {
    elements.emptyState.className = "empty-state success";
    elements.emptyState.textContent = "未发现已知量子脆弱公钥算法用法";
    elements.resultGroups.classList.add("hidden");
    renderPreview();
    return;
  }

  elements.emptyState.classList.add("hidden");
  elements.resultGroups.classList.remove("hidden");
  const grouped = groupFindings(result.findings);
  elements.resultGroups.innerHTML = Object.entries(grouped)
    .map(
      ([fileName, fileFindings]) => `
        <section class="file-group">
          <div class="file-group-header">
            <h2>${escapeHtml(fileName)}</h2>
            <span>${fileFindings.length} 项</span>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>行号</th>
                  <th>算法</th>
                  <th>风险</th>
                  <th>证据</th>
                  <th>迁移建议</th>
                </tr>
              </thead>
              <tbody>
                ${fileFindings
                  .map(
                    (finding) => `
                      <tr data-source-id="${escapeHtml(finding.source_id)}" data-line="${finding.line}" data-algorithm="${escapeHtml(
                        finding.algorithm
                      )}">
                        <td>${finding.line}</td>
                        <td>${escapeHtml(finding.algorithm)}</td>
                        <td>${escapeHtml(finding.risk_level)}</td>
                        <td>${escapeHtml(finding.evidence)}</td>
                        <td>${escapeHtml(finding.recommendation)}</td>
                      </tr>`
                  )
                  .join("")}
              </tbody>
            </table>
          </div>
        </section>`
    )
    .join("");

  elements.resultGroups.querySelectorAll("tbody tr").forEach((row) => {
    row.addEventListener("click", () => {
      const sourceId = row.getAttribute("data-source-id");
      const line = Number(row.getAttribute("data-line"));
      const algorithm = row.getAttribute("data-algorithm");
      state.selectedFinding =
        state.result.findings.find(
          (finding) =>
            finding.source_id === sourceId &&
            finding.line === line &&
            finding.algorithm === algorithm
        ) || null;
      elements.resultGroups.querySelectorAll("tbody tr").forEach((item) => {
        item.classList.toggle("selected", item === row);
      });
      renderPreview();
    });
  });

  renderPreview();
}

async function runScan() {
  showError("");
  updateScanButton(true);
  try {
    state.result = state.mode === "snippet" ? await scanSnippet() : await scanFiles();
    state.selectedFinding = state.result.findings[0] || null;
    renderResults();
  } catch (error) {
    showError(error instanceof Error ? error.message : "扫描失败");
  } finally {
    updateScanButton(false);
  }
}

function downloadText(filename, content) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

async function exportReport() {
  if (!state.result) {
    return;
  }
  showError("");
  elements.exportReport.disabled = true;
  elements.exportReport.textContent = "导出中";
  try {
    const response = await fetch("/api/report/markdown", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(state.result),
    });
    if (!response.ok) {
      throw new Error("报告导出失败");
    }
    downloadText("quantum-scan-report.md", await response.text());
  } catch (error) {
    showError(error instanceof Error ? error.message : "报告导出失败");
  } finally {
    elements.exportReport.disabled = !state.result;
    elements.exportReport.textContent = "导出 Markdown 报告";
  }
}

elements.snippetMode.addEventListener("click", () => setMode("snippet"));
elements.fileMode.addEventListener("click", () => setMode("files"));
elements.fileInput.addEventListener("change", (event) => {
  state.files = Array.from(event.target.files || []);
  renderFileList();
  updateScanButton();
});
elements.scanButton.addEventListener("click", runScan);
elements.exportReport.addEventListener("click", exportReport);

renderResults();
