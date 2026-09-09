# PromptAstra Frontend (Flask)

The PromptGuard security console UI. It runs in two modes automatically:

- **Demo mode (default):** no configuration needed. The UI serves the bundled
  sample data in `data/*.json` and analyses prompts with a built-in
  deterministic heuristic engine. Everything works offline.
- **Live mode:** when Supabase credentials are present, the dashboard, monitor,
  and review queue read **real** `security_events` from Supabase, and analysed
  prompts are written back to that same table (the one the FastAPI backend uses).

The switch is automatic and fail-safe: if Supabase is configured but
unreachable, the UI silently falls back to demo data instead of crashing.

## Setup

```bash
cd frontend
pip install -r requirements.txt
cp .env.example .env        # then edit .env
python app.py               # http://127.0.0.1:5000
```

Check the data source at any time:

```bash
curl http://127.0.0.1:5000/health
# {"status":"healthy","supabase":"connected","data_source":"supabase", ...}
```

## Connecting Supabase

1. In Supabase, run the SQL in `../supabase_schema.sql` to create the
   `security_events` table (skip if the backend already created it).
2. Put your credentials in `frontend/.env`:

   ```env
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_KEY=your-service-role-key
   ```

   For a server-side app the **service-role key** is simplest. If you prefer the
   anon key, add RLS policies allowing `select`/`insert` on `security_events`
   (see the schema file).
3. Restart the app. `/health` should now report `"data_source":"supabase"`.

### Avoiding double logging

If you also run the FastAPI backend as the analyzer (via `PROMPTGUARD_API_URL`),
the backend already logs each event to Supabase. Set `FRONTEND_WRITES_SUPABASE=0`
so the frontend doesn't write a second copy.

## How the mapping works

Supabase stores events as
`id, prompt, decision, risk_score, threat_category, reason, rule_score, ml_score, created_at`.
`utils/supabase_store.py` maps each row to the shape the templates expect
(`attack_type`, `severity`, `status`, `confidence`, `argus_exposed`, …), so no
template changes are required. Live KPI counts and the threat distribution on the
dashboard are computed from the real rows and overlaid on the descriptive
metadata in `data/system_stats.json`.

> Note on scores: `risk_score` is a transparent 0–100 **security risk score**
> used to prioritise review, not a validated probability of harm.
