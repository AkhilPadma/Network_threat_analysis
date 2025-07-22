import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

# File uploader in sidebar (optional)
st.sidebar.title("Upload CSV (optional)")
uploaded_file = st.sidebar.file_uploader("Upload threat dataset CSV", type="csv")

# Function to load and validate data
@st.cache_data
def load_data(file_path):
    try:
        df = pd.read_csv("final_threat_dataset.csv")
        
        # Basic validation
        if df.empty or df.shape[1] == 0:
            st.error("The CSV file is empty or has no columns.")
            st.stop()

        required_columns = {'timestamp', 'is_intrusion', 'malware_like', 'is_spike', 'rare_ip'}
        if not required_columns.issubset(df.columns):
            missing = required_columns - set(df.columns)
            st.error(f"Missing columns in dataset: {missing}")
            st.stop()

        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df.dropna(subset=['timestamp'], inplace=True)
        df['hour'] = df['timestamp'].dt.floor('H')
        df['12_hour'] = df['timestamp'].dt.floor('12H')
        df['24_hour'] = df['timestamp'].dt.floor('24H')

        return df

    except pd.errors.EmptyDataError:
        st.error("The file is completely empty.")
        st.stop()
    except Exception as e:
        st.error(f"Error reading file: {e}")
        st.stop()

# Decide whether to use uploaded file or default
default_path = "final_threat_dataset.csv"
if uploaded_file is not None:
    df = load_data(uploaded_file)
elif os.path.exists(default_path):
    df = load_data(default_path)
else:
    st.error("No file found. Please upload a valid 'final_threat_dataset.csv' or place it in the app directory.")
    st.stop()

# Sidebar filters
st.sidebar.title("Threat Filter")
threat_type = st.sidebar.selectbox("Select Threat Type", ['is_intrusion', 'malware_like', 'is_spike', 'rare_ip'])
timeframe = st.sidebar.selectbox("Group by Timeframe", ['hour', '12_hour', '24_hour'])

# Title and metrics
st.title("Network Threat Detection Dashboard")
st.subheader("Threat Overview")
st.metric("Total Intrusions", int(df['is_intrusion'].sum()))
st.metric("Total Malware", int(df['malware_like'].sum()))
st.metric("Total Spikes", int(df['is_spike'].sum()))
st.metric("Rare IP Events", int(df['rare_ip'].sum()))

# Bar chart of threat type over time
st.subheader(f"{threat_type.replace('_', ' ').title()} Over Time ({timeframe})")
summary = df.groupby(df[timeframe])[threat_type].sum()
fig, ax = plt.subplots()
summary.plot(kind='bar', ax=ax, color='steelblue')
ax.set_ylabel("Count")
ax.set_xlabel("Time")
ax.set_title(f"{threat_type.replace('_', ' ').title()} per {timeframe}")
st.pyplot(fig)

# Detailed logs table
st.subheader("Detailed Logs")
st.dataframe(df[df[threat_type] == 1].sort_values(by='timestamp', ascending=False).head(100))
