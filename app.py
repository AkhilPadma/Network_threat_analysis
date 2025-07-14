import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

# Load final dataset
@st.cache_data
def load_data():
    df = pd.read_csv("final_threat_dataset.csv")
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.floor('H')
    df['12_hour'] = df['timestamp'].dt.floor('12H')
    df['24_hour'] = df['timestamp'].dt.floor('24H')
    return df

df = load_data()

# Sidebar filter
st.sidebar.title("Threat Filter")
threat_type = st.sidebar.selectbox("Select Threat Type", ['is_intrusion', 'malware_like', 'is_spike', 'rare_ip'])
timeframe = st.sidebar.selectbox("Group by", ['hour', '12_hour', '24_hour'])

# Metric Cards
st.title(" Network Threat Detection Dashboard")
st.subheader("Threat Overview")
st.metric("Total Intrusions", df['is_intrusion'].sum())
st.metric("Total Malware", df['malware_like'].sum())
st.metric("Total Spikes", df['is_spike'].sum())
st.metric("Rare IP Events", df['rare_ip'].sum())

# Grouped chart
st.subheader(f" {threat_type.replace('_',' ').title()} Over Time ({timeframe})")
summary = df.groupby(df[timeframe])[threat_type].sum()
fig, ax = plt.subplots()
summary.plot(kind='bar', ax=ax)
ax.set_ylabel("Count")
ax.set_xlabel("Time")
ax.set_title(f"{threat_type.replace('_',' ').title()} per {timeframe}")
st.pyplot(fig)

# View Raw Logs for filtered type
st.subheader(" Detailed Logs")
st.dataframe(df[df[threat_type] == 1].sort_values(by='timestamp', ascending=False).head(100))
