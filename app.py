import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import socket
import random
import scapy.all as scapy
from datetime import datetime
import speedtest
import plotly.graph_objects as go

# Function to generate random traffic data
def generate_traffic_data():
    data = {
        'timestamp': pd.date_range(start='1/1/2024', periods=100, freq='T'),
        'ingress_ping': [random.uniform(10, 100) for _ in range(100)],
        'egress_ping': [random.uniform(10, 100) for _ in range(100)],
        'latency': [random.uniform(1, 10) for _ in range(100)],
        'ip_address': [socket.gethostbyname(socket.gethostname()) for _ in range(100)]
    }
    return pd.DataFrame(data)

# Function to capture real-time traffic data
def capture_traffic_data(duration=60):
    packets = scapy.sniff(timeout=duration)
    data = {
        'timestamp': [],
        'ingress_ping': [],
        'egress_ping': [],
        'latency': [],
        'ip_address': []
    }
    for packet in packets:
        data['timestamp'].append(datetime.now())
        data['ingress_ping'].append(random.uniform(10, 100))
        data['egress_ping'].append(random.uniform(10, 100))
        data['latency'].append(random.uniform(1, 10))
        data['ip_address'].append(packet[scapy.IP].src if scapy.IP in packet else 'N/A')
    return pd.DataFrame(data)

# Function to check internet speed
def check_internet_speed():
    st = speedtest.Speedtest()
    st.download()
    st.upload()
    return st.results.dict()

# Function to create speedometer
def create_speedometer(speed):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=speed,
        title={'text': "Internet Speed (Mbps)"},
        gauge={'axis': {'range': [None, 100]},
               'bar': {'color': "darkblue"},
               'steps': [
                   {'range': [0, 50], 'color': "lightgray"},
                   {'range': [50, 100], 'color': "gray"}],
               'threshold': {'line': {'color': "red", 'width': 4}, 'thickness': 0.75, 'value': 90}}))
    return fig

# Set up Streamlit page
st.set_page_config(layout="wide")
st.title("Network Traffic Analyzer")

# Sidebar for navigation
st.sidebar.title("Navigation")
sections = ["Overview", "Ingress Ping", "Egress Ping", "Latency", "IP Addresses", "Real-Time Capture", "Internet Speed"]
selected_section = st.sidebar.radio("Go to", sections)

# Generate or capture traffic data
if selected_section == "Real-Time Capture":
    st.header("Real-Time Traffic Capture")
    duration = st.sidebar.slider("Capture Duration (seconds)", 10, 120, 60)
    if st.sidebar.button("Start Capture"):
        df = capture_traffic_data(duration)
else:
    df = generate_traffic_data()

# Overview Section
if selected_section == "Overview":
    st.header("Overview")
    st.line_chart(df.set_index('timestamp')[['ingress_ping', 'egress_ping', 'latency']])
    st.write("This section provides an overview of the network traffic.")
    st.write(f"**Average Ingress Ping:** {df['ingress_ping'].mean():.2f} ms")
    st.write(f"**Average Egress Ping:** {df['egress_ping'].mean():.2f} ms")
    st.write(f"**Average Latency:** {df['latency'].mean():.2f} ms")

# Ingress Ping Section
elif selected_section == "Ingress Ping":
    st.header("Ingress Ping")
    st.line_chart(df.set_index('timestamp')['ingress_ping'])
    st.write(f"**Average Ingress Ping:** {df['ingress_ping'].mean():.2f} ms")

# Egress Ping Section
elif selected_section == "Egress Ping":
    st.header("Egress Ping")
    st.line_chart(df.set_index('timestamp')['egress_ping'])
    st.write(f"**Average Egress Ping:** {df['egress_ping'].mean():.2f} ms")

# Latency Section
elif selected_section == "Latency":
    st.header("Latency")
    st.line_chart(df.set_index('timestamp')['latency'])
    st.write(f"**Average Latency:** {df['latency'].mean():.2f} ms")

# IP Addresses Section
elif selected_section == "IP Addresses":
    st.header("IP Addresses")
    ip_filter = st.sidebar.text_input("Filter by IP Address")
    if ip_filter:
        df_filtered = df[df['ip_address'] == ip_filter]
        st.dataframe(df_filtered[['timestamp', 'ip_address']])
    else:
        st.dataframe(df[['timestamp', 'ip_address']])
    st.write("This section lists the IP addresses involved in the traffic.")

# Internet Speed Section
elif selected_section == "Internet Speed":
    st.header("Internet Speed Checker")
    if st.sidebar.button("Check Speed"):
        speed_results = check_internet_speed()
        download_speed = speed_results['download'] / 1e6  # Convert to Mbps
        upload_speed = speed_results['upload'] / 1e6  # Convert to Mbps
        st.write(f"**Download Speed:** {download_speed:.2f} Mbps")
        st.write(f"**Upload Speed:** {upload_speed:.2f} Mbps")
        st.plotly_chart(create_speedometer(download_speed))

# Export Data Section
if st.sidebar.button("Export Data"):
    df.to_csv('network_traffic_data.csv')
    st.sidebar.write("Data exported to network_traffic_data.csv")

# Customizing the UI
sns.set(style="whitegrid")
palette = sns.color_palette("viridis", as_cmap=True)

# Footer
st.markdown("<footer><p>Developed by [Your Name]</p></footer>", unsafe_allow_html=True)