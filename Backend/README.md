# Project Astra - Backend Infrastructure

Project Astra is an AI Security Gateway designed to monitor, inspect, score risk, and enforce governance policies on AI prompt interactions and model responses.

## Architecture & File Responsibilities

```
Backend/
├── app/
│   ├── __init__.py          # Core package initializer
│   ├── main.py              # Application entrypoint & FastAPI app initialization
│   ├── config.py            # Environment configuration & settings management
│   ├── database.py          # Supabase client setup & database connections
│   │
│   ├── models/
│   │   ├── __init__.py      # Models package initializer
│   │   ├── request_models.py# Schemas for incoming request payloads
│   │   └── response_models.py# Schemas for outgoing gateway responses
│   │
│   ├── routes/
│   │   ├── __init__.py      # Router package initializer
│   │   ├── analyze.py       # Endpoints for prompt security analysis & payload inspection
│   │   ├── logs.py          # Endpoints for security audit logs & history
│   │   └── stats.py         # Endpoints for gateway metrics & dashboard analytics
│   │
│   ├── services/
│   │   ├── __init__.py      # Services package initializer
│   │   ├── rule_engine.py   # Pattern matching, regex & static rule inspection engine
│   │   ├── ml_detector.py   # Machine Learning threat & prompt injection detector service
│   │   ├── risk_scorer.py   # Scoring engine synthesizing rule and ML signals
│   │   └── policy_engine.py # Governance engine enforcing action policies (allow, block, redact)
│   │
│   └── utils/
│       ├── __init__.py      # Utilities package initializer
│       └── constants.py     # System constants, error codes, and threshold definitions
│
├── .env                     # Environment configuration & Supabase secrets
├── .gitignore               # Version control ignore definitions
├── requirements.txt         # Project dependencies
└── README.md                # Backend documentation and file responsibilities
```

## Component Breakdown

- **`app/main.py`**: Boots the ASGI app, registers CORS middleware, and mounts API router instances.
- **`app/config.py`**: Parses environment variables via Pydantic Settings / `python-dotenv`.
- **`app/database.py`**: Manages connection lifecycle and Supabase client bindings.
- **`app/models/`**: Defines Pydantic data models for request validation and response formatting.
- **`app/routes/`**: Handles HTTP endpoints separated by resource responsibility (`analyze`, `logs`, `stats`).
- **`app/services/`**: Encapsulates core business logic for security checks, ML analysis, risk calculation, and policy enforcement.
- **`app/utils/constants.py`**: Holds global constants, fixed status strings, and default thresholds.
