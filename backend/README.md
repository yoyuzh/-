# Backend

FastAPI service for the quantum-vulnerable public-key algorithm scanner.

```bash
python start.py
```

Open `http://127.0.0.1:8000`.

The API exposes:

- `POST /api/scan/snippet`
- `POST /api/scan/files`
- `POST /api/report/markdown`
- `GET /api/health`
