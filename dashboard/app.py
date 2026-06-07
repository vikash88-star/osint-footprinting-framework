# dashboard/app.py
# PURPOSE: Streamlit web dashboard to view scan results visually.
# Run with: streamlit run dashboard/app.py
# Opens in browser at http://localhost:8501

import streamlit as st
import sqlite3
import pandas as pd
import json
import os
import sys

# Make sure imports work from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

st.set_page_config(
    page_title="OSINT Framework",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 OSINT Footprinting Dashboard")
st.caption("Built on Kali Linux — 100% Free Tools")

# ── Sidebar — target selector ─────────────────────────────────────
st.sidebar.header("Target")

# Find all .db files in output/
output_dir = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "output"
)
db_files = [f for f in os.listdir(output_dir) if f.endswith(".db")] \
           if os.path.exists(output_dir) else []

if not db_files:
    st.warning("No scan results found. Run a scan first:")
    st.code("python3 osint.py --target example.com")
    st.stop()

selected_db = st.sidebar.selectbox(
    "Select scan result",
    db_files,
    format_func=lambda x: x.replace("_", ".").replace(".db", "")
)

db_path = os.path.join(output_dir, selected_db)
target  = selected_db.replace("_", ".").replace(".db", "")

st.sidebar.success(f"Target: {target}")

# ── Load data ────────────────────────────────────────────────────
@st.cache_data
def load_table(db_path, table):
    try:
        conn = sqlite3.connect(db_path)
        df   = pd.read_sql(f"SELECT * FROM {table}", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

subs_df   = load_table(db_path, "subdomains")
ports_df  = load_table(db_path, "ports")
emails_df = load_table(db_path, "emails")
whois_df  = load_table(db_path, "whois_data")
tech_df   = load_table(db_path, "techstack")

# ── Metric cards ─────────────────────────────────────────────────
st.subheader(f"Scan Summary — {target}")
c1, c2, c3, c4, c5 = st.columns(5)

live_subs = len(subs_df[subs_df["status"] == "live"]) \
            if "status" in subs_df.columns else 0

c1.metric("Subdomains",  len(subs_df),  f"{live_subs} live")
c2.metric("Open Ports",  len(ports_df))
c3.metric("Emails",      len(emails_df))

if "breach_count" in emails_df.columns and len(emails_df) > 0:
    breached = len(emails_df[emails_df["breach_count"] > 0])
    c4.metric("Breached Emails", breached,
              delta=f"-{breached} at risk",
              delta_color="inverse")
else:
    c4.metric("Breached Emails", 0)

exposed_count = 0
if "exposed_files" in tech_df.columns:
    for val in tech_df["exposed_files"]:
        try:
            exposed_count += len(json.loads(val)) if val else 0
        except Exception:
            pass
c5.metric("Exposed Files", exposed_count,
          delta="check immediately" if exposed_count > 0 else None,
          delta_color="inverse" if exposed_count > 0 else "off")

st.divider()

# ── Tabs ──────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🌐 Subdomains", "🔌 Ports", "📧 Emails", "🛠 Tech Stack", "📋 WHOIS"
])

with tab1:
    st.subheader("Discovered Subdomains")
    if not subs_df.empty:
        live_df = subs_df[subs_df["status"] == "live"]
        st.success(f"{len(live_df)} live subdomains")
        st.dataframe(subs_df, use_container_width=True)
    else:
        st.info("No subdomains data yet.")

with tab2:
    st.subheader("Open Ports & Services")
    if not ports_df.empty:
        st.warning(f"{len(ports_df)} open ports found")
        # Parse CVEs column
        def cve_count(val):
            try: return len(json.loads(val)) if val else 0
            except: return 0
        ports_df["cve_count"] = ports_df["vulns"].apply(cve_count)
        st.dataframe(ports_df[["ip","port","service","version","cve_count"]],
                     use_container_width=True)
        total_cves = ports_df["cve_count"].sum()
        if total_cves > 0:
            st.error(f"⚠ {total_cves} total CVEs matched by Shodan")
    else:
        st.info("No ports data yet.")

with tab3:
    st.subheader("Email Breach Analysis")
    if not emails_df.empty:
        breached_df = emails_df[emails_df["breach_count"] > 0] \
                      if "breach_count" in emails_df.columns else pd.DataFrame()
        if not breached_df.empty:
            st.error(f"⚠ {len(breached_df)} emails found in breach databases")
        st.dataframe(emails_df, use_container_width=True)
    else:
        st.info("No email data yet.")

with tab4:
    st.subheader("Tech Stack Fingerprinting")
    if not tech_df.empty:
        # Expand exposed files
        all_exposed = []
        for _, row in tech_df.iterrows():
            try:
                files = json.loads(row["exposed_files"]) if row["exposed_files"] else []
                for f in files:
                    all_exposed.append({
                        "subdomain": row["subdomain"],
                        "path":      f.get("path"),
                        "severity":  f.get("severity"),
                        "status":    f.get("status"),
                        "desc":      f.get("desc")
                    })
            except Exception:
                pass

        st.dataframe(tech_df[["subdomain","technologies","waf"]],
                     use_container_width=True)

        if all_exposed:
            st.subheader("⚠ Exposed Sensitive Files")
            st.error(f"{len(all_exposed)} exposed files detected")
            st.dataframe(pd.DataFrame(all_exposed), use_container_width=True)
    else:
        st.info("No tech stack data yet.")

with tab5:
    st.subheader("WHOIS Registration Data")
    if not whois_df.empty:
        for col in whois_df.columns:
            if col != "id":
                st.write(f"**{col.replace('_',' ').title()}:** "
                         f"{whois_df.iloc[0][col]}")
    else:
        st.info("No WHOIS data yet.")
