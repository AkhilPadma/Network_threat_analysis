import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

# Upload option
st.sidebar.title("Upload CSV (optional)")
uploaded_file = st.sidebar.file_uploader("Upload threat dataset CSV", type="csv")

# Robust data loader
@st.cache_data
def load_data(file_path):
    try:
        df = pd.read_csv(file_path)

        if df.empty or df.shape[1] == 0:
            st.error("The CSV file is empty or has no columns.")
            st.stop()

        if 'timestamp' not in df.columns:
            st.error("Missing required 'timestamp' column.")
            st.stop()

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df.dropna(subset=['timestamp'], inplace=True)
        df['hour'] = df['timestamp'].dt.floor('H')
        df['12_hour'] = df['timestamp'].dt.floor('12H')
        df['24_hour'] = df['timestamp'].dt.floor('24H')

        # Identify available threat columns
        threat_cols = ['is_intrusion', 'malware_like', 'is_spike', 'rare_ip']
        available_threats = [col for col in threat_cols if col in df.columns]

        if not available_threats:
            st.error("No valid threat columns found (expected: is_intrusion, malware_like, is_spike, rare_ip).")
            st.stop()

        return df, available_threats

    except pd.errors.EmptyDataError:
        st.error("The file is completely empty.")
        st.stop()
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()

# Load data from uploaded file or default
default_path = "final_threat_dataset.csv"
if uploaded_file is not None:
    df, threat_columns = load_data(uploaded_file)
elif os.path.exists(default_path):
    df, threat_columns = load_data(default_path)
else:
    st.error("No file found. Upload a CSV or place 'final_threat_dataset.csv' in the directory.")
    st.stop()

# Sidebar filters
st.sidebar.title("Threat Filter")
threat_type = st.sidebar.selectbox("Select Threat Type", threat_columns)
timeframe = st.sidebar.selectbox("Group by Timeframe", ['hour', '12_hour', '24_hour'])

# Title and Metrics
st.title("Network Threat Detection Dashboard")
st.subheader("Threat Overview")

# Safe metrics
if 'is_intrusion' in df.columns:
    st.metric("Total Intrusions", int(df['is_intrusion'].sum()))
if 'malware_like' in df.columns:
    st.metric("Total Malware", int(df['malware_like'].sum()))
if 'is_spike' in df.columns:
    st.metric("Total Spikes", int(df['is_spike'].sum()))
if 'rare_ip' in df.columns:
    st.metric("Rare IP Events", int(df['rare_ip'].sum()))

# Bar chart
st.subheader(f"{threat_type.replace('_', ' ').title()} Over Time ({timeframe})")
summary = df.groupby(df[timeframe])[threat_type].sum()
fig, ax = plt.subplots()
summary.plot(kind='bar', ax=ax, color='steelblue')
ax.set_ylabel("Count")
ax.set_xlabel("Time")
ax.set_title(f"{threat_type.replace('_', ' ').title()} per {timeframe}")
st.pyplot(fig)

# Logs Table
st.subheader("Detailed Logs")
st.dataframe(df[df[threat_type] == 1].sort_values(by='timestamp', ascending=False).head(100))

# Optional download button
st.subheader("Download Dataset")
csv = df.to_csv(index=False).encode('utf-8')
st.download_button(
    label="Download final_threat_dataset.csv",
    data=csv,
    file_name="final_threat_dataset.csv",
    mime="text/csv"
)
