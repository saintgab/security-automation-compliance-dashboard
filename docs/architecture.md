
# Security Automation & Compliance Dashboard — Architecture

```mermaid
flowchart TD
    AWS["AWS Security Hub CSPM - LIVE"] --> API["Boto3 GetFindings - Paginated Collection"]
    MOCK["GitHub Alerts + Scanner - SYNTHETIC"] --> NORMAL["Finding Normalization"]
    API --> NORMAL
    NORMAL --> RISK["Risk Scoring and SLA Tracking"]
    RISK --> DB[("SQLite - Separate Live and Mock Databases")]
    DB --> DASH["Streamlit Dashboard"]
    DB --> EVIDENCE["Compliance Evidence Engine"]
    EVIDENCE --> CATALOG["12-Control Catalog - SOC 2 / ISO 27001"]
    EVIDENCE --> FRESH["Latest Collection and 24h Freshness"]
    FRESH --> REPORT["Markdown Evidence Report and SHA-256 Manifest"]
    CI["GitHub Actions - 38 Automated Tests"] -.-> NORMAL
    CI -.-> EVIDENCE
```

## Security design

- Live AWS Security Hub collection uses a dedicated least-privilege IAM user.
- Live and synthetic findings are stored in separate SQLite databases.
- Compliance evidence uses structured AWS Security Hub control identifiers.
- Missing findings retain their historical records rather than being automatically resolved.
- SHA-256 manifests provide integrity comparison, not independently signed evidence.
- GitHub Alerts and vulnerability scanner integrations remain synthetic.
