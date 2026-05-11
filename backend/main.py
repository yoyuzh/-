from __future__ import annotations

from email import policy
from email.parser import BytesParser
from pathlib import Path
from pathlib import PurePath
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.reporting import beijing_now_iso, build_markdown_report, build_summary
from scan_quantum_vuln import make_source_id, scan_source_for_crypto

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_UPLOAD_BYTES = 10 * 1024 * 1024
PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_DIR = PROJECT_ROOT / "web"
SourceType = Literal["snippet", "manual_upload", "github_repository"]


class SnippetScanRequest(BaseModel):
    filename: str = Field(default="snippet.py", min_length=1, max_length=240)
    content: str = Field(default="", max_length=MAX_SOURCE_BYTES)


class SourceRecord(BaseModel):
    source_id: str
    file_name: str
    source_type: SourceType
    content: str
    line_count: int
    char_count: int


class FindingRecord(BaseModel):
    source_id: str
    file_name: str
    source_type: SourceType
    line: int
    algorithm: str
    risk_level: str
    evidence: str
    reason: str
    recommendation: str


class ScanSummary(BaseModel):
    source_count: int
    finding_count: int
    algorithm_counts: dict[str, int]


class ScanResponse(BaseModel):
    scanned_at: str
    source_type: SourceType
    sources: list[SourceRecord]
    findings: list[FindingRecord]
    summary: ScanSummary


class ReportRequest(BaseModel):
    scanned_at: Optional[str] = None
    source_type: SourceType = "manual_upload"
    sources: list[SourceRecord] = Field(default_factory=list)
    findings: list[FindingRecord] = Field(default_factory=list)


app = FastAPI(title="Quantum Crypto Migration Scanner", version="0.1.0")

app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


def normalize_filename(filename: str, fallback: str = "snippet.py") -> str:
    cleaned = filename.replace("\\", "/").split("/")[-1].strip()
    cleaned = PurePath(cleaned).name
    return cleaned or fallback


def build_scan_response(
    documents: list[tuple[str, str]],
    source_type: SourceType,
) -> ScanResponse:
    scanned_at = beijing_now_iso()
    sources: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    for index, (filename, content) in enumerate(documents):
        if len(content.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise HTTPException(status_code=413, detail=f"{filename} exceeds the 2 MB limit")

        source_id = make_source_id(f"{index}:{filename}", content)
        source_record = {
            "source_id": source_id,
            "file_name": filename,
            "source_type": source_type,
            "content": content,
            "line_count": len(content.splitlines()),
            "char_count": len(content),
        }
        sources.append(source_record)
        findings.extend(
            scan_source_for_crypto(
                content,
                filename=filename,
                source_type=source_type,
                source_id=source_id,
            )
        )

    summary = build_summary(sources, findings)
    return ScanResponse(
        scanned_at=scanned_at,
        source_type=source_type,
        sources=sources,
        findings=findings,
        summary=summary,
    )


def parse_multipart_files(content_type: str, body: bytes) -> list[tuple[str, str]]:
    if "multipart/form-data" not in content_type:
        raise HTTPException(status_code=415, detail="Expected multipart/form-data")
    if len(body) > MAX_TOTAL_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 10 MB limit")

    raw_message = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
    )
    message = BytesParser(policy=policy.default).parsebytes(raw_message)
    if not message.is_multipart():
        raise HTTPException(status_code=400, detail="Invalid multipart payload")

    documents: list[tuple[str, str]] = []
    for part in message.iter_parts():
        filename = part.get_filename()
        if not filename:
            continue

        payload = part.get_payload(decode=True) or b""
        if len(payload) > MAX_SOURCE_BYTES:
            raise HTTPException(status_code=413, detail=f"{filename} exceeds the 2 MB limit")

        try:
            content = payload.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"{filename} is not valid UTF-8 text",
            ) from exc

        documents.append((normalize_filename(filename, "uploaded.py"), content))

    if not documents:
        raise HTTPException(status_code=400, detail="No files were uploaded")
    return documents


def model_to_dict(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html", headers={"Cache-Control": "no-store"})


@app.post("/api/scan/snippet", response_model=ScanResponse)
def scan_snippet(payload: SnippetScanRequest) -> ScanResponse:
    filename = normalize_filename(payload.filename, "snippet.py")
    return build_scan_response([(filename, payload.content)], source_type="snippet")


@app.post("/api/scan/files", response_model=ScanResponse)
async def scan_files(request: Request) -> ScanResponse:
    content_type = request.headers.get("content-type", "")
    body = await request.body()
    documents = parse_multipart_files(content_type, body)
    return build_scan_response(documents, source_type="manual_upload")


@app.post("/api/report/markdown")
def export_markdown_report(payload: ReportRequest) -> Response:
    sources = [model_to_dict(source) for source in payload.sources]
    findings = [model_to_dict(finding) for finding in payload.findings]
    report = build_markdown_report(
        sources=sources,
        findings=findings,
        source_type=payload.source_type,
        scanned_at=payload.scanned_at,
    )
    return Response(
        content=report,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="quantum-scan-report.md"'},
    )
