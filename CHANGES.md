# What was fixed

## Frontend ↔ Supabase connection (the core issue)
The Flask frontend previously only read static demo JSON and had **no Supabase
connection**, so it never showed the real `security_events` the backend writes.

- Added `frontend/utils/supabase_store.py`: a fail-safe Supabase wrapper that
  reads/writes the `security_events` table and maps rows to the exact shape the
  UI templates expect. If Supabase is missing or unreachable, it returns
  cleanly and the UI falls back to demo data (never crashes).
- Wired `frontend/utils/data_manager.py` to prefer live Supabase data for the
  dashboard KPIs, monitor feed, review queue, and event logging — with demo
  JSON as fallback. Rich metadata (evaluation metrics, protection status) is
  preserved and only the live counts are overlaid.
- Added `/health` and `/api/health` to the Flask app so you can verify the
  connection (`data_source: supabase | demo_json`).
- Added `FRONTEND_WRITES_SUPABASE` flag to avoid double-logging when the
  FastAPI backend is also the analyzer.

## Security
- **Removed the exposed Supabase secret** (`sb_secret_…`) from `Backend/.env`.
  It was shipped in the original zip and **must be rotated** in the Supabase
  dashboard (Settings → API → reset the service_role/secret key), then pasted
  into your local `.env`.
- Added `.gitignore` (ignores real `.env` files, `__pycache__`, `__MACOSX`,
  editor junk) and `.env.example` files for both the frontend and backend.

## Developer experience
- `supabase_schema.sql` — the exact `security_events` table definition (derived
  from how the backend reads/writes it), ready to paste into Supabase.
- `frontend/requirements.txt` now includes `supabase` and `python-dotenv`.
- `frontend/README.md` documents demo vs live mode and Supabase setup.
- Removed macOS/editor cruft (`__MACOSX/`, `__pycache__/`, `.DS_Store`,
  empty "New folder").

## Verified
- Demo mode: all pages return 200; prompt analysis works and logs locally.
- Live mode (tested against a mock Supabase client): inserts, filtered reads,
  KPI/threat-distribution aggregation, and review-queue decision updates all
  work, and live rows render correctly in the templates.

## Note on the two backends
The project contains two FastAPI apps (`Backend/` modular, `FastApi/`
single-file), both targeting the same Supabase table. This change set makes the
**frontend** connect correctly regardless of which one you run. Consolidating
the two backends into one is a separate cleanup worth doing later.
