"""
Security Automation & Compliance Dashboard
--------------------------------------------
Reads directly from data/findings.db -- there is no separate "dashboard
data" export step. What you see here is exactly what's in the database
after the last collector run, which is the whole point: this is a view
into the pipeline, not a mockup of one.

Run:
    python collect.py          # populate/refresh the database first
    streamlit run app.py
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = Path(__file__).parent
DB_PATH = ROOT / "data" / "findings.db"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLOR = {
    "critical": "#F0455C",
    "high": "#F5A623",
    "medium": "#EBCB4D",
    "low": "#5AA9E6",
    "info": "#64748B",
}
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

SLA_ORDER = ["overdue", "due_soon", "on_track", "resolved", "accepted_risk"]
SLA_COLOR = {
    "overdue": "#F0455C",
    "due_soon": "#F5A623",
    "on_track": "#34D399",
    "resolved": "#64748B",
    "accepted_risk": "#A78BFA",
}
SLA_ICON = {"overdue": "🔴", "due_soon": "🟡", "on_track": "🟢", "resolved": "✅", "accepted_risk": "🟣"}

st.set_page_config(
    page_title="Security Automation & Compliance Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ---------------------------------------------------------------------------
# Styling -- default Streamlit reads as a generic data-app template, so this
# leans into a SOC-console feel: dark, monospace data, tight KPI cards.
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .stApp { background-color: #0B0E14; }
    [data-testid="stMetric"] {
        background-color: #131722;
        border: 1px solid #232838;
        border-radius: 8px;
        padding: 14px 16px;
    }
    [data-testid="stMetricLabel"] { font-size: 0.78rem; opacity: 0.75; letter-spacing: 0.02em; }
    [data-testid="stMetricValue"] { font-family: "JetBrains Mono", "SFMono-Regular", Consolas, monospace; }
    .pipeline-caption {
        font-family: "JetBrains Mono", Consolas, monospace;
        font-size: 0.78rem;
        color: #6B7280;
        border-top: 1px solid #232838;
        padding-top: 10px;
        margin-top: 8px;
    }
    .run-note { color: #8B95A5; font-size: 0.85rem; }
    div[data-testid="stDataFrame"] { font-family: "JetBrains Mono", Consolas, monospace; font-size: 0.85rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(ttl=5)
def load_data(db_path: str, _mtime: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    conn = sqlite3.connect(db_path)
    findings = pd.read_sql_query("SELECT * FROM findings", conn)
    runs = pd.read_sql_query("SELECT * FROM collector_runs ORDER BY finished_at DESC", conn)
    conn.close()
    for col in ("first_seen", "last_seen", "sla_due_date", "first_ingested_at", "last_updated_at"):
        findings[col] = pd.to_datetime(findings[col], utc=True, errors="coerce")
    for col in ("started_at", "finished_at"):
        runs[col] = pd.to_datetime(runs[col], utc=True, errors="coerce")
    return findings, runs


if not DB_PATH.exists():
    st.error(
        f"No database found at `{DB_PATH}`. Run `python collect.py` first to populate it "
        "from the three mock sources (AWS Security Hub, GitHub alerts, scanner)."
    )
    st.stop()

findings, runs = load_data(str(DB_PATH), DB_PATH.stat().st_mtime)

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
left, right = st.columns([3, 1])
with left:
    st.title("🛡️ Security Automation & Compliance Dashboard")
    st.caption("AWS Security Hub · GitHub Alerts · Scanner findings — normalized, risk-scored, SLA-tracked")
with right:
    if not runs.empty:
        last_run = runs.iloc[0]
        st.markdown(
            f"<div class='run-note'>Last collector run<br>"
            f"<b>{last_run['finished_at'].strftime('%Y-%m-%d %H:%M UTC')}</b><br>"
            f"{int(last_run['total_findings'])} findings · "
            f"{int(last_run['new_findings'])} new · {int(last_run['updated_findings'])} updated</div>",
            unsafe_allow_html=True,
        )

# ---------------------------------------------------------------------------
# Sidebar filters
# ---------------------------------------------------------------------------
st.sidebar.header("Filters")
sev_options = [s for s in SEVERITY_ORDER if s in findings["severity"].unique()]
sel_severity = st.sidebar.multiselect("Severity", sev_options, default=sev_options)

status_options = sorted(findings["status"].unique())
sel_status = st.sidebar.multiselect("Status", status_options, default=status_options)

owner_options = sorted(findings["owner"].unique())
sel_owner = st.sidebar.multiselect("Owner", owner_options, default=owner_options)

source_options = sorted(findings["source"].unique())
sel_source = st.sidebar.multiselect("Source", source_options, default=source_options)

search = st.sidebar.text_input("Search asset / title")

filtered = findings[
    findings["severity"].isin(sel_severity)
    & findings["status"].isin(sel_status)
    & findings["owner"].isin(sel_owner)
    & findings["source"].isin(sel_source)
]
if search:
    mask = filtered["asset"].str.contains(search, case=False, na=False) | filtered["title"].str.contains(
        search, case=False, na=False
    )
    filtered = filtered[mask]

st.sidebar.markdown("---")
st.sidebar.caption(
    "Ownership is assigned by source-appropriate rule (Security Hub → Cloud Infra; "
    "GitHub alerts → AppSec; scanner findings → per-asset heuristic). "
    "See `collector/sources.py`."
)

# ---------------------------------------------------------------------------
# KPI row
# ---------------------------------------------------------------------------
open_mask = ~filtered["status"].isin(["resolved", "accepted_risk"])
open_df = filtered[open_mask]

total_open = len(open_df)
critical_open = len(open_df[open_df["severity"] == "critical"])
overdue = len(filtered[filtered["sla_status"] == "overdue"])
resolved_or_accepted = len(filtered[filtered["status"].isin(["resolved", "accepted_risk"])])
sla_compliance = (
    100 * (len(filtered) - overdue) / len(filtered) if len(filtered) else 100.0
)
avg_risk = open_df["risk_score"].mean() if total_open else 0.0

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Open findings", total_open)
k2.metric("Critical (open)", critical_open)
k3.metric("Overdue SLA", overdue, delta=None)
k4.metric("SLA compliance", f"{sla_compliance:.0f}%")
k5.metric("Avg risk score (open)", f"{avg_risk:.0f}")

st.markdown("")

# ---------------------------------------------------------------------------
# Charts row 1: severity breakdown + SLA status
# ---------------------------------------------------------------------------
c1, c2 = st.columns(2)

with c1:
    st.subheader("Open findings by severity")
    sev_counts = (
        open_df["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0).astype(int).reset_index()
    )
    sev_counts.columns = ["severity", "count"]
    fig = px.bar(
        sev_counts,
        x="severity",
        y="count",
        color="severity",
        color_discrete_map=SEVERITY_COLOR,
        category_orders={"severity": SEVERITY_ORDER},
        text="count",
    )
    fig.update_layout(
        showlegend=False,
        plot_bgcolor="#131722",
        paper_bgcolor="#131722",
        font_color="#E6E8EE",
        margin=dict(l=10, r=10, t=10, b=10),
        height=320,
    )
    st.plotly_chart(fig, width='stretch')

with c2:
    st.subheader("SLA status (all filtered findings)")
    sla_counts = (
        filtered["sla_status"].value_counts().reindex(SLA_ORDER).fillna(0).astype(int).reset_index()
    )
    sla_counts.columns = ["sla_status", "count"]
    fig2 = go.Figure(
        data=[
            go.Pie(
                labels=sla_counts["sla_status"],
                values=sla_counts["count"],
                hole=0.55,
                marker=dict(colors=[SLA_COLOR[s] for s in sla_counts["sla_status"]]),
                textinfo="label+value",
            )
        ]
    )
    fig2.update_layout(
        showlegend=False,
        paper_bgcolor="#131722",
        font_color="#E6E8EE",
        margin=dict(l=10, r=10, t=10, b=10),
        height=320,
    )
    st.plotly_chart(fig2, width='stretch')

# ---------------------------------------------------------------------------
# Charts row 2: findings by owner (stacked by severity) + top risk
# ---------------------------------------------------------------------------
c3, c4 = st.columns(2)

with c3:
    st.subheader("Open findings by owner")
    owner_sev = (
        open_df.groupby(["owner", "severity"]).size().reset_index(name="count")
    )
    fig3 = px.bar(
        owner_sev,
        x="owner",
        y="count",
        color="severity",
        color_discrete_map=SEVERITY_COLOR,
        category_orders={"severity": SEVERITY_ORDER},
    )
    fig3.update_layout(
        plot_bgcolor="#131722",
        paper_bgcolor="#131722",
        font_color="#E6E8EE",
        margin=dict(l=10, r=10, t=10, b=10),
        height=340,
        legend_title_text="",
    )
    st.plotly_chart(fig3, width='stretch')

with c4:
    st.subheader("Top 10 by risk score")
    top10 = open_df.nlargest(10, "risk_score")[["title", "asset", "severity", "risk_score"]]
    top10 = top10.iloc[::-1]  # so highest ends up on top in a horizontal bar
    fig4 = px.bar(
        top10,
        x="risk_score",
        y="title",
        orientation="h",
        color="severity",
        color_discrete_map=SEVERITY_COLOR,
        category_orders={"severity": SEVERITY_ORDER},
        hover_data=["asset"],
    )
    fig4.update_layout(
        plot_bgcolor="#131722",
        paper_bgcolor="#131722",
        font_color="#E6E8EE",
        margin=dict(l=10, r=10, t=10, b=10),
        height=340,
        yaxis_title="",
        showlegend=False,
    )
    fig4.update_yaxes(categoryorder="array", 
    categoryarray=list(top10["title"])) 
    st.plotly_chart(fig4, width='stretch')

# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------
st.subheader(f"Findings ({len(filtered)})")

table_df = filtered.copy()
table_df["severity"] = table_df["severity"].map(lambda s: f"{SEVERITY_ICON.get(s,'')} {s}")
table_df["sla_status"] = table_df["sla_status"].map(lambda s: f"{SLA_ICON.get(s,'')} {s}")
table_df["days_to_sla"] = (table_df["sla_due_date"] - pd.Timestamp.now(tz="UTC")).dt.days

display_cols = [
    "title", "asset", "severity", "status", "owner", "source",
    "risk_score", "sla_status", "days_to_sla", "cve_ids",
]
table_df = table_df[display_cols].sort_values("risk_score", ascending=False)

st.dataframe(
    table_df,
    width='stretch',
    hide_index=True,
    column_config={
        "risk_score": st.column_config.ProgressColumn(
            "Risk score", min_value=0, max_value=float(findings["risk_score"].max() or 1), format="%.0f"
        ),
        "days_to_sla": st.column_config.NumberColumn("Days to SLA", help="Negative = past due"),
        "cve_ids": st.column_config.TextColumn("CVEs"),
    },
    height=420,
)

# ---------------------------------------------------------------------------
# Collector run history (audit trail -- feeds the evidence report)
# ---------------------------------------------------------------------------
with st.expander("Collector run history (audit trail)"):
    st.caption(
        "Every collector execution is logged here with a timestamp and source list. "
        "This table is what the evidence-generation step reads to prove *when* control "
        "data was last pulled, not just what it currently shows."
    )
    st.dataframe(
        runs[["run_id", "started_at", "finished_at", "sources_pulled", "total_findings", "new_findings", "updated_findings"]],
        width='stretch',
        hide_index=True,
    )

st.markdown(
    "<div class='pipeline-caption'>"
    "AWS Security Hub / GitHub Alerts / Scanner &nbsp;→&nbsp; collect.py &nbsp;→&nbsp; "
    "SQLite (data/findings.db) &nbsp;→&nbsp; risk scoring + SLA logic &nbsp;→&nbsp; this dashboard "
    "&nbsp;→&nbsp; evidence report"
    "</div>",
    unsafe_allow_html=True,
)
