import streamlit as st
import pandas as pd
import boto3
import json
import io
import gzip
import altair as alt

# -----------------------------
# Config & Title
# -----------------------------
st.set_page_config(page_title="Multi-Cloud Security Dashboard", layout="wide")
st.title("☁️ Multi-Cloud Security Monitoring Dashboard")

st.markdown("""
This dashboard analyzes **AWS CloudTrail logs** and **demo GCP audit logs** to detect:
- Suspicious IAM activity
- S3 bucket changes
- Authentication failures
- Unusual API calls

📌 *Next step: Integrating real GCP & Azure logs.*
""")

# -----------------------------
# Sensitive / Critical Events
# -----------------------------
sensitive_events = ["DeleteBucket", "PutBucketAcl", "ModifyIAMPolicy", "DeleteTrail", "StopLogging"]
critical_events = ["DeleteBucket", "ModifyIAMPolicy", "StopLogging"]
threshold = 3

# -----------------------------
# Load Logs (AWS / Demo GCP)
# -----------------------------
@st.cache_data
def fetch_aws_logs(bucket_name="nikhil-cloudtrail-logs-eu"):
    try:
        s3 = boto3.client("s3")
        logs = []

        objects = s3.list_objects_v2(Bucket=bucket_name)
        for obj in objects.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".gz"):
                continue

            body = s3.get_object(Bucket=bucket_name, Key=key)["Body"].read()
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as f:
                data = json.loads(f.read().decode("utf-8"))

            for record in data.get("Records", []):
                logs.append({
                    "eventTime": record.get("eventTime"),
                    "eventName": record.get("eventName"),
                    "userName": record.get("userIdentity", {}).get("userName", "Unknown"),
                    "sourceIPAddress": record.get("sourceIPAddress"),
                    "eventSource": record.get("eventSource"),
                    "userAgent": record.get("userAgent")
                })

        df = pd.DataFrame(logs)
        if not df.empty:
            df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True).dt.tz_localize(None)
        return df

    except Exception:
        st.warning("⚠️ AWS access not available. Loading local AWS demo logs.")
        df = pd.read_csv("data/aws_logs.csv")
        df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True).dt.tz_localize(None)
        df["userName"] = df.get("userName", "DemoUser")
        return df


@st.cache_data
def fetch_gcp_demo_logs():
    data = [
        {"eventTime": "2025-12-15T08:00:00Z", "eventName": "instances.start", "userName": "user1", "eventSource": "compute.googleapis.com"},
        {"eventTime": "2025-12-15T08:05:00Z", "eventName": "buckets.delete", "userName": "admin1", "eventSource": "storage.googleapis.com"},
        {"eventTime": "2025-12-15T08:10:00Z", "eventName": "loginFailed", "userName": "user2", "eventSource": "iam.googleapis.com"}
    ]
    df = pd.DataFrame(data)
    df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True).dt.tz_localize(None)
    return df

# -----------------------------
# Sidebar: Cloud Selection
# -----------------------------
cloud_provider = st.sidebar.selectbox(
    "Select Cloud Provider",
    ["AWS", "GCP (Demo)"]
)

df = fetch_aws_logs() if cloud_provider == "AWS" else fetch_gcp_demo_logs()

if df.empty:
    st.warning("⚠️ No logs found.")
    st.stop()

# -----------------------------
# Sidebar: Filters
# -----------------------------
st.sidebar.header("🔎 Filters")

event_names = st.sidebar.multiselect(
    "Event Name(s)",
    sorted(df["eventName"].unique())
)

users = st.sidebar.multiselect(
    "User(s)",
    sorted(df["userName"].unique())
)

# -----------------------------
# ✅ FIXED DATE RANGE FILTER
# -----------------------------
min_date = df["eventTime"].min().date()
max_date = df["eventTime"].max().date()

date_range = st.sidebar.date_input(
    "Date Range",
    [min_date, max_date]
)

if len(date_range) == 2:
    start_date = pd.to_datetime(date_range[0])
    end_date = pd.to_datetime(date_range[1]) + pd.Timedelta(days=1)
    df = df[(df["eventTime"] >= start_date) & (df["eventTime"] < end_date)]

if event_names:
    df = df[df["eventName"].isin(event_names)]

if users:
    df = df[df["userName"].isin(users)]

show_sensitive_only = st.sidebar.checkbox("Show only sensitive events")
if show_sensitive_only:
    df = df[df["eventName"].isin(sensitive_events)]

# -----------------------------
# Display Logs
# -----------------------------
st.subheader("📋 Filtered Logs")

def highlight_sensitive(row):
    return ["background-color: #FFB6C1" if row["eventName"] in sensitive_events else "" for _ in row]

st.dataframe(df.style.apply(highlight_sensitive, axis=1), use_container_width=True)

# -----------------------------
# Suspicious Activity Detection
# -----------------------------
anomaly_df = df[df["eventName"].isin(critical_events)]
user_counts = anomaly_df.groupby("userName").size().reset_index(name="Count")
suspicious_users = user_counts[user_counts["Count"] >= threshold]

st.subheader("⚠️ Suspicious Activity")
if not suspicious_users.empty:
    st.warning("Suspicious activity detected!")
    st.dataframe(suspicious_users)
else:
    st.write("No suspicious activity detected.")

# -----------------------------
# Visualizations
# -----------------------------
st.subheader("📊 Visualizations")

col1, col2 = st.columns(2)

with col1:
    st.markdown("**Events by Source Service**")
    st.bar_chart(df["eventSource"].value_counts())

with col2:
    st.markdown("**Events Over Time**")
    st.line_chart(df.groupby(df["eventTime"].dt.date).size())

event_type_counts = df["eventName"].value_counts().reset_index()
event_type_counts.columns = ["Event", "Count"]

st.subheader("📊 Event Type Distribution")
pie_chart = alt.Chart(event_type_counts).mark_arc().encode(
    theta=alt.Theta(field="Count", type="quantitative"),
    color=alt.Color(field="Event", type="nominal"),
    tooltip=["Event", "Count"]
)
st.altair_chart(pie_chart, use_container_width=True)

# -----------------------------
# Download Option
# -----------------------------
csv = df.to_csv(index=False).encode("utf-8")
st.sidebar.header("⬇️ Export Data")
st.sidebar.download_button(
    "Download Filtered Logs",
    csv,
    "filtered_logs.csv",
    "text/csv"
)

st.success("✅ Dashboard loaded successfully!")
st.markdown("---")
st.caption("Built by Nikhil Sharma | Multi-Cloud Security Monitoring Project")
