<script setup>
import { ref, computed, onMounted } from 'vue';

// --- 常量与默认值 ---
const DEFAULT_RSA_CODE = `from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

def payload() -> bytes:
    return b"demo-message"

if __name__ == "__main__":
    message = payload()

    # 演示：这里故意使用 RSA，便于扫描器识别
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    print(signature[:8])`;

// --- 状态变量 ---
const scanMode = ref('snippet'); // 'snippet' or 'files'
const snippetFilename = ref('snippet.py');
const snippetContent = ref(DEFAULT_RSA_CODE);
const selectedFiles = ref([]);
const isScanning = ref(false);
const scanResult = ref(null);
const errorMsg = ref('');
const expandedFindings = ref(new Set());

// --- 计算属性 ---
const fileList = computed(() => selectedFiles.value.map(f => f.name));

const findingsByFile = computed(() => {
  if (!scanResult.value) return {};
  const grouped = {};
  scanResult.value.findings.forEach(finding => {
    if (!grouped[finding.file_name]) {
      grouped[finding.file_name] = [];
    }
    grouped[finding.file_name].push(finding);
  });
  return grouped;
});

const algorithmStats = computed(() => {
  if (!scanResult.value) return [];
  return Object.entries(scanResult.value.summary.algorithm_counts).map(([name, count]) => ({ name, count }));
});

// --- 方法 ---
const readJsonResponse = async (response, fallbackMessage) => {
  const text = await response.text();
  if (!text) {
    if (response.ok) return null;
    throw new Error(fallbackMessage || `请求失败（HTTP ${response.status}）`);
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error(fallbackMessage || '服务返回了非 JSON 内容，请确认后端 API 已正常启动');
  }
};

const toggleMode = (mode) => {
  scanMode.value = mode;
  errorMsg.value = '';
};

const handleFileSelect = (event) => {
  const files = Array.from(event.target.files);
  // 只接受 .py, .pyw, .txt
  const filtered = files.filter(f => /\.(py|pyw|txt)$/i.test(f.name));
  selectedFiles.value = filtered;
  if (filtered.length < files.length) {
    alert('部分文件格式不支持，仅限 .py, .pyw, .txt');
  }
};

const startScan = async () => {
  isScanning.value = true;
  errorMsg.value = '';
  scanResult.value = null;
  expandedFindings.value = new Set();

  try {
    let response;
    if (scanMode.value === 'snippet') {
      response = await fetch('/api/scan/snippet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filename: snippetFilename.value,
          content: snippetContent.value
        })
      });
    } else {
      if (selectedFiles.value.length === 0) {
        throw new Error('请先选择文件');
      }
      const formData = new FormData();
      selectedFiles.value.forEach(file => {
        formData.append('files', file);
      });
      // 注意：后端 parse_multipart_files 是手动解析的，直接发送即可
      response = await fetch('/api/scan/files', {
        method: 'POST',
        body: formData
      });
    }

    if (!response.ok) {
      const errData = await readJsonResponse(response, `扫描失败（HTTP ${response.status}）`);
      throw new Error(errData.detail || '扫描失败');
    }

    scanResult.value = await readJsonResponse(response, '扫描接口没有返回有效结果');
  } catch (err) {
    errorMsg.value = err.message;
  } finally {
    isScanning.value = false;
  }
};

const toggleFinding = (id) => {
  if (expandedFindings.value.has(id)) {
    expandedFindings.value.delete(id);
  } else {
    expandedFindings.value.add(id);
  }
};

const getCodeSnippet = (fileName, lineNum) => {
  if (!scanResult.value) return [];
  const source = scanResult.value.sources.find(s => s.file_name === fileName);
  if (!source) return [];
  
  const lines = source.content.split('\n');
  const start = Math.max(0, lineNum - 4);
  const end = Math.min(lines.length, lineNum + 3);
  
  return lines.slice(start, end).map((text, idx) => ({
    number: start + idx + 1,
    text,
    isTarget: start + idx + 1 === lineNum
  }));
};

const exportMarkdown = async () => {
  if (!scanResult.value) return;
  try {
    const response = await fetch('/api/report/markdown', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scanned_at: scanResult.value.scanned_at,
        source_type: scanResult.value.source_type,
        sources: scanResult.value.sources,
        findings: scanResult.value.findings
      })
    });

    if (!response.ok) throw new Error('导出报告失败');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `quantum-scan-report-${new Date().getTime()}.md`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (err) {
    alert(err.message);
  }
};

const formatTime = (isoStr) => {
  if (!isoStr) return '';
  // 后端已经返回北京时间字符串，直接截取或稍微格式化
  return isoStr.replace('T', ' ').split('.')[0];
};

onMounted(() => {
  // 默认填充 RSA
});
</script>

<template>
  <div class="app-container">
    <header class="main-header">
      <div class="logo">
        <span class="icon">🛡️</span>
        <h1>抗量子迁移风险扫描平台</h1>
      </div>
      <div class="header-actions">
        <button v-if="scanResult" @click="exportMarkdown" class="btn btn-outline">导出 Markdown 报告</button>
      </div>
    </header>

    <main class="main-layout">
      <!-- 左侧：工作区 -->
      <section class="workspace">
        <div class="card">
          <div class="tabs">
            <button :class="{ active: scanMode === 'snippet' }" @click="toggleMode('snippet')">代码片段扫描</button>
            <button :class="{ active: scanMode === 'files' }" @click="toggleMode('files')">多文件上传扫描</button>
          </div>

          <div class="tab-content">
            <!-- 代码片段模式 -->
            <div v-if="scanMode === 'snippet'" class="snippet-area">
              <div class="form-group">
                <label>文件名</label>
                <input v-model="snippetFilename" type="text" placeholder="e.g. main.py" class="input-field" />
              </div>
              <div class="form-group">
                <label>源代码</label>
                <textarea v-model="snippetContent" placeholder="在此粘贴 Python 代码..." class="code-editor"></textarea>
              </div>
            </div>

            <!-- 文件扫描模式 -->
            <div v-else class="upload-area">
              <div class="upload-dropzone" @click="$refs.fileInput.click()">
                <input type="file" ref="fileInput" multiple @change="handleFileSelect" hidden accept=".py,.pyw,.txt" />
                <div class="dropzone-hint">
                  <span class="upload-icon">📁</span>
                  <p>点击或拖拽文件到此处</p>
                  <small>支持 .py, .pyw, .txt (单文件 ≤ 2MB)</small>
                </div>
              </div>
              <div v-if="selectedFiles.length > 0" class="file-list">
                <h4>待扫描文件 ({{ selectedFiles.length }})</h4>
                <ul>
                  <li v-for="name in fileList" :key="name">{{ name }}</li>
                </ul>
              </div>
            </div>

            <div class="actions">
              <button @click="startScan" :disabled="isScanning" class="btn btn-primary">
                {{ isScanning ? '扫描中...' : '开始扫描' }}
              </button>
            </div>
          </div>
        </div>

        <div v-if="errorMsg" class="error-banner">
          ⚠️ {{ errorMsg }}
        </div>
      </section>

      <!-- 右侧：结果展示区 -->
      <section class="results-area">
        <!-- 欢迎/空状态 -->
        <div v-if="!scanResult && !isScanning && !errorMsg" class="empty-state">
          <div class="empty-icon">🔍</div>
          <h2>等待扫描</h2>
          <p>请在左侧输入代码或上传文件以开始风险评估</p>
        </div>

        <!-- 扫描中 -->
        <div v-if="isScanning" class="scanning-state">
          <div class="loader"></div>
          <p>正在分析加密算法风险，请稍候...</p>
        </div>

        <!-- 结果汇总 -->
        <div v-if="scanResult" class="results-content">
          <div class="summary-grid">
            <div class="summary-card">
              <span class="label">文件总数</span>
              <span class="value">{{ scanResult.summary.source_count }}</span>
            </div>
            <div class="summary-card">
              <span class="label">发现风险</span>
              <span class="value danger">{{ scanResult.summary.finding_count }}</span>
            </div>
            <div class="summary-card">
              <span class="label">受影响算法</span>
              <span class="value">{{ Object.keys(scanResult.summary.algorithm_counts).length }}</span>
            </div>
            <div class="summary-card">
              <span class="label">扫描时间</span>
              <span class="value small">{{ formatTime(scanResult.scanned_at) }}</span>
            </div>
          </div>

          <!-- 无风险提示 -->
          <div v-if="scanResult.findings.length === 0" class="no-risk-banner">
            ✅ 扫描完成：未发现已知的传统非对称加密或不安全算法风险。
          </div>

          <!-- 分组结果列表 -->
          <div v-else class="findings-list">
            <div v-for="(findings, fileName) in findingsByFile" :key="fileName" class="file-group">
              <h3 class="file-title">📄 {{ fileName }}</h3>
              
              <div v-for="(f, idx) in findings" :key="idx" class="finding-item">
                <div class="finding-header">
                  <span class="line-badge">行 {{ f.line }}</span>
                  <span class="algo-tag">{{ f.algorithm }}</span>
                  <span class="risk-desc">{{ f.risk_level }}: {{ f.evidence }}</span>
                  <button @click="toggleFinding(fileName + idx)" class="btn-text">
                    {{ expandedFindings.has(fileName + idx) ? '收起代码' : '展开代码' }}
                  </button>
                </div>

                <div v-if="expandedFindings.has(fileName + idx)" class="code-view">
                  <pre><code><div v-for="line in getCodeSnippet(fileName, f.line)" :key="line.number" :class="{ 'highlight-line': line.isTarget }"><span class="line-no">{{ line.number }}</span> {{ line.text }}</div></code></pre>
                </div>

                <div class="finding-details">
                  <div class="detail-row">
                    <strong>原因分析：</strong> <span>{{ f.reason }}</span>
                  </div>
                  <div class="detail-row">
                    <strong>迁移建议：</strong> <span>{{ f.recommendation }}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>
  </div>
</template>

<style>
/* --- 基础样式 --- */
:root {
  --primary-color: #2563eb;
  --bg-color: #f8fafc;
  --card-bg: #ffffff;
  --border-color: #e2e8f0;
  --text-main: #1e293b;
  --text-muted: #64748b;
  --danger-color: #dc2626;
  --success-color: #16a34a;
  --highlight-bg: #fef9c3;
}

body {
  margin: 0;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background-color: var(--bg-color);
  color: var(--text-main);
}

.app-container {
  display: flex;
  flex-direction: column;
  height: 100vh;
}

/* --- 页眉 --- */
.main-header {
  background: #1e293b;
  color: white;
  padding: 0.75rem 1.5rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.logo {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.logo h1 {
  margin: 0;
  font-size: 1.25rem;
  font-weight: 600;
}

/* --- 布局 --- */
.main-layout {
  display: flex;
  flex: 1;
  overflow: hidden;
  padding: 1.5rem;
  gap: 1.5rem;
}

@media (max-width: 1024px) {
  .main-layout {
    flex-direction: column;
    overflow-y: auto;
  }
  .app-container { height: auto; }
}

.workspace {
  flex: 0 0 450px;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

@media (max-width: 1024px) {
  .workspace { flex: none; width: 100%; }
}

.results-area {
  flex: 1;
  overflow-y: auto;
  background: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1.5rem;
}

/* --- 卡片与表单 --- */
.card {
  background: var(--card-bg);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.tabs {
  display: flex;
  background: #f1f5f9;
  border-bottom: 1px solid var(--border-color);
}

.tabs button {
  flex: 1;
  padding: 0.75rem;
  border: none;
  background: none;
  cursor: pointer;
  font-weight: 500;
  color: var(--text-muted);
  transition: all 0.2s;
}

.tabs button.active {
  background: var(--card-bg);
  color: var(--primary-color);
  box-shadow: inset 0 -2px 0 var(--primary-color);
}

.tab-content {
  padding: 1rem;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  font-size: 0.875rem;
  margin-bottom: 0.4rem;
  font-weight: 500;
}

.input-field {
  width: 100%;
  padding: 0.5rem;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  box-sizing: border-box;
}

.code-editor {
  width: 100%;
  height: 350px;
  font-family: 'Fira Code', 'Courier New', monospace;
  font-size: 13px;
  padding: 0.75rem;
  border: 1px solid var(--border-color);
  border-radius: 4px;
  resize: none;
  box-sizing: border-box;
}

.upload-dropzone {
  border: 2px dashed var(--border-color);
  border-radius: 8px;
  padding: 2rem;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s;
}

.upload-dropzone:hover {
  border-color: var(--primary-color);
}

.upload-icon { font-size: 2.5rem; margin-bottom: 1rem; display: block; }

.file-list {
  margin-top: 1rem;
  max-height: 200px;
  overflow-y: auto;
}

.file-list h4 { margin: 0 0 0.5rem 0; font-size: 0.9rem; }
.file-list ul { padding-left: 1.25rem; margin: 0; color: var(--text-muted); font-size: 0.85rem; }

.actions { margin-top: 1rem; }

.btn {
  padding: 0.6rem 1.25rem;
  border-radius: 4px;
  font-weight: 500;
  cursor: pointer;
  border: none;
  transition: opacity 0.2s;
}

.btn:disabled { opacity: 0.5; cursor: not-allowed; }

.btn-primary { background: var(--primary-color); color: white; width: 100%; }
.btn-outline { background: transparent; border: 1px solid #ffffff; color: white; font-size: 0.85rem; }
.btn-text { background: none; color: var(--primary-color); font-size: 0.85rem; padding: 0; }

.error-banner {
  background: #fef2f2;
  color: var(--danger-color);
  padding: 0.75rem;
  border-radius: 4px;
  border: 1px solid #fee2e2;
  font-size: 0.875rem;
}

/* --- 结果区域 --- */
.empty-state, .scanning-state {
  height: 100%;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  color: var(--text-muted);
}

.empty-icon { font-size: 4rem; margin-bottom: 1rem; }

.loader {
  border: 3px solid #f3f3f3;
  border-top: 3px solid var(--primary-color);
  border-radius: 50%;
  width: 40px;
  height: 40px;
  animation: spin 1s linear infinite;
  margin-bottom: 1rem;
}

@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}

.summary-card {
  background: #f8fafc;
  padding: 1rem;
  border-radius: 6px;
  display: flex;
  flex-direction: column;
  align-items: center;
  border: 1px solid var(--border-color);
}

.summary-card .label { font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.25rem; }
.summary-card .value { font-size: 1.5rem; font-weight: 700; }
.summary-card .value.danger { color: var(--danger-color); }
.summary-card .value.small { font-size: 0.85rem; text-align: center; }

.no-risk-banner {
  background: #f0fdf4;
  color: var(--success-color);
  padding: 1rem;
  border-radius: 6px;
  text-align: center;
  border: 1px solid #dcfce7;
}

/* --- Findings 列表 --- */
.file-group { margin-bottom: 2rem; }
.file-title {
  border-bottom: 2px solid var(--border-color);
  padding-bottom: 0.5rem;
  font-size: 1.1rem;
  margin-bottom: 1rem;
}

.finding-item {
  border: 1px solid var(--border-color);
  border-radius: 6px;
  margin-bottom: 1rem;
  overflow: hidden;
}

.finding-header {
  background: #f1f5f9;
  padding: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.75rem;
  flex-wrap: wrap;
}

.line-badge {
  background: #475569;
  color: white;
  padding: 0.1rem 0.4rem;
  border-radius: 3px;
  font-size: 0.75rem;
  font-family: monospace;
}

.algo-tag {
  background: #dbeafe;
  color: var(--primary-color);
  padding: 0.1rem 0.5rem;
  border-radius: 12px;
  font-size: 0.75rem;
  font-weight: 600;
}

.risk-desc { flex: 1; font-weight: 500; font-size: 0.9rem; }

.code-view {
  background: #fafafa;
  border-bottom: 1px solid var(--border-color);
  padding: 0.5rem;
  overflow-x: auto;
}

.code-view pre { margin: 0; font-size: 12px; line-height: 1.5; }
.code-view code { font-family: 'Fira Code', monospace; }

.highlight-line {
  background: var(--highlight-bg);
  display: block;
  width: 100%;
}

.line-no {
  color: #94a3b8;
  width: 2rem;
  display: inline-block;
  text-align: right;
  margin-right: 0.5rem;
  user-select: none;
}

.finding-details {
  padding: 1rem;
  font-size: 0.875rem;
}

.detail-row {
  margin-bottom: 0.5rem;
  line-height: 1.6;
}

.detail-row strong { color: #475569; }
</style>
