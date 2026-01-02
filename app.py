"""
Cipher Aegis - Dashboard UI
Real-time network intrusion detection dashboard built with Streamlit.
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from datetime import datetime
import time
from typing import List, Dict, Any

from db_manager import get_db

# Page configuration
st.set_page_config(
    page_title="Cipher Aegis - IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for styling
st.markdown("""
    <style>
    /* Main container */
    .main {
        background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
    }
    
    /* Metrics */
    [data-testid="stMetricValue"] {
        font-size: 2rem;
        font-weight: bold;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #16213e 0%, #0f3460 100%);
    }
    
    /* Headers */
    h1, h2, h3 {
        color: #00d9ff;
        font-family: 'Courier New', monospace;
        text-shadow: 0 0 10px rgba(0, 217, 255, 0.5);
    }
    
    /* Metric labels */
    [data-testid="stMetricLabel"] {
        color: #a8dadc;
        font-weight: 600;
    }
    
    /* Dataframe */
    .dataframe {
        font-size: 0.9rem;
    }
    
    /* Alert badges */
    .alert-high {
        background: #ff006e;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-weight: bold;
        display: inline-block;
    }
    
    .alert-medium {
        background: #fb8500;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-weight: bold;
        display: inline-block;
    }
    
    .alert-low {
        background: #4cc9f0;
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-weight: bold;
        display: inline-block;
    }
    </style>
""", unsafe_allow_html=True)


def get_threat_color(threat_level: str) -> str:
    """Get color based on threat level."""
    colors = {
        "HIGH": "#ff006e",
        "MEDIUM": "#fb8500",
        "LOW": "#4cc9f0",
    }
    return colors.get(threat_level, "#4cc9f0")


def format_timestamp(timestamp: float) -> str:
    """Format Unix timestamp to readable string."""
    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")


def create_traffic_chart(timeline_data: List[Dict[str, Any]]) -> go.Figure:
    """
    Create dual-axis chart for traffic volume and anomaly scores.
    
    Args:
        timeline_data: List of timeline data points.
    
    Returns:
        Plotly figure object.
    """
    if not timeline_data:
        # Return empty chart
        fig = go.Figure()
        fig.add_annotation(
            text="No data available yet. Start capturing traffic!",
            xref="paper", yref="paper",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(size=16, color="#a8dadc")
        )
        fig.update_layout(
            height=400,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0.2)",
        )
        return fig
    
    # Convert to DataFrame and reverse (oldest first for chart)
    df = pd.DataFrame(timeline_data).iloc[::-1]
    
    # Format timestamps
    df['time_str'] = df['timestamp'].apply(format_timestamp)
    
    # Create figure with secondary y-axis
    fig = make_subplots(
        rows=1, cols=1,
        specs=[[{"secondary_y": True}]],
    )
    
    # Traffic volume (bar chart)
    fig.add_trace(
        go.Bar(
            x=df['time_str'],
            y=df['traffic_volume'],
            name="Traffic Volume",
            marker=dict(
                color='#4cc9f0',
                opacity=0.7,
            ),
            hovertemplate="<b>Packets:</b> %{y}<br><extra></extra>",
        ),
        secondary_y=False,
    )
    
    # Anomaly score (line chart)
    # Color points based on whether they're anomalies
    colors = ['#ff006e' if is_anom else '#00ff88' 
              for is_anom in df['is_anomaly']]
    
    fig.add_trace(
        go.Scatter(
            x=df['time_str'],
            y=df['anomaly_score'],
            name="Anomaly Score",
            mode='lines+markers',
            line=dict(color='#ff006e', width=2),
            marker=dict(
                size=8,
                color=colors,
                line=dict(color='white', width=1),
            ),
            hovertemplate="<b>Score:</b> %{y:.4f}<br><extra></extra>",
        ),
        secondary_y=True,
    )
    
    # Update axes
    fig.update_xaxes(
        title_text="Time",
        showgrid=True,
        gridcolor="rgba(255,255,255,0.1)",
        color="#a8dadc",
    )
    
    fig.update_yaxes(
        title_text="<b>Packets</b>",
        secondary_y=False,
        showgrid=True,
        gridcolor="rgba(255,255,255,0.1)",
        color="#4cc9f0",
    )
    
    fig.update_yaxes(
        title_text="<b>Anomaly Score</b>",
        secondary_y=True,
        showgrid=False,
        color="#ff006e",
    )
    
    # Update layout
    fig.update_layout(
        height=400,
        hovermode='x unified',
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0.2)",
        font=dict(color="#a8dadc", size=12),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            bgcolor="rgba(0,0,0,0.5)",
            font=dict(color="#a8dadc"),
        ),
        margin=dict(l=20, r=20, t=40, b=20),
    )
    
    return fig


def render_anomaly_table(anomalies: List[Dict[str, Any]]) -> None:
    """
    Render the anomalies table with custom styling.
    
    Args:
        anomalies: List of anomaly records.
    """
    if not anomalies:
        st.info("🎉 No anomalies detected yet. System is secure!")
        return
    
    # Convert to DataFrame
    df = pd.DataFrame(anomalies)
    
    # Format timestamp
    df['Time'] = df['timestamp'].apply(
        lambda x: datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S")
    )
    
    # Select and rename columns
    display_df = df[[
        'Time', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'protocol', 'anomaly_score', 'threat_level', 'description'
    ]].copy()
    
    display_df.columns = [
        'Timestamp', 'Source IP', 'Dest IP', 'Src Port', 'Dst Port',
        'Protocol', 'Anomaly Score', 'Threat', 'Description'
    ]
    
    # Format anomaly score
    display_df['Anomaly Score'] = display_df['Anomaly Score'].apply(
        lambda x: f"{x:.4f}"
    )
    
    # Apply styling
    def highlight_threat(row):
        if row['Threat'] == 'HIGH':
            return ['background-color: rgba(255, 0, 110, 0.2)'] * len(row)
        elif row['Threat'] == 'MEDIUM':
            return ['background-color: rgba(251, 133, 0, 0.2)'] * len(row)
        else:
            return ['background-color: rgba(76, 201, 240, 0.1)'] * len(row)
    
    styled_df = display_df.style.apply(highlight_threat, axis=1)
    
    st.dataframe(
        styled_df,
        use_container_width=True,
        height=400,
    )


def render_system_logs(logs: List[Dict[str, Any]]) -> None:
    """
    Render system logs in sidebar.
    
    Args:
        logs: List of log records.
    """
    st.sidebar.markdown("### 📋 System Logs")
    st.sidebar.markdown("---")
    
    if not logs:
        st.sidebar.info("No logs available")
        return
    
    for log in logs[:20]:  # Show latest 20
        timestamp = datetime.fromtimestamp(log['timestamp']).strftime("%H:%M:%S")
        level = log['level']
        message = log['message']
        
        # Color code by level
        if level == "ERROR":
            icon = "🔴"
            color = "#ff006e"
        elif level == "WARNING":
            icon = "⚠️"
            color = "#fb8500"
        else:
            icon = "ℹ️"
            color = "#4cc9f0"
        
        st.sidebar.markdown(
            f"""
            <div style='
                padding: 8px;
                margin: 4px 0;
                border-left: 3px solid {color};
                background: rgba(0,0,0,0.3);
                border-radius: 4px;
            '>
                <small style='color: #a8dadc;'>{timestamp}</small><br>
                <span style='color: {color};'>{icon} <strong>{level}</strong></span><br>
                <span style='color: #f1f1f1; font-size: 0.85rem;'>{message}</span>
            </div>
            """,
            unsafe_allow_html=True
        )


def main():
    """Main dashboard application."""
    
    # Header
    st.markdown("""
        <h1 style='text-align: center; font-size: 3rem;'>
            🛡️ CIPHER AEGIS
        </h1>
        <p style='text-align: center; color: #a8dadc; font-size: 1.2rem;'>
            Next-Generation Intrusion Detection System
        </p>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Initialize database
    db = get_db()
    
    # Sidebar controls
    st.sidebar.markdown("## ⚙️ Dashboard Controls")
    
    auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh", value=True)
    refresh_interval = st.sidebar.slider(
        "Refresh Interval (seconds)",
        min_value=1,
        max_value=30,
        value=5,
        disabled=not auto_refresh
    )
    
    st.sidebar.markdown("---")
    
    # Fetch data
    stats = db.get_statistics()
    anomalies = db.get_anomalies(limit=10)
    timeline = db.get_traffic_timeline(limit=100)
    logs = db.get_system_logs(limit=50)
    
    # === METRICS ROW ===
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric(
            label="📊 Total Packets",
            value=f"{stats['total_packets']:,}",
            delta=f"{stats['total_flows']} flows",
        )
    
    with col2:
        st.metric(
            label="🚨 Anomalies Detected",
            value=f"{stats['total_anomalies']:,}",
            delta=f"{len(anomalies)} recent",
            delta_color="inverse",
        )
    
    with col3:
        threat_level = stats['current_threat_level']
        threat_color = get_threat_color(threat_level)
        
        st.markdown(
            f"""
            <div style='text-align: center;'>
                <p style='color: #a8dadc; font-size: 0.875rem; font-weight: 600; margin-bottom: 0.5rem;'>
                    🎯 Current Threat Level
                </p>
                <p style='
                    font-size: 2rem;
                    font-weight: bold;
                    color: {threat_color};
                    margin: 0;
                    text-shadow: 0 0 10px {threat_color};
                '>
                    {threat_level}
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
    
    st.markdown("---")
    
    # === TRAFFIC CHART ===
    st.markdown("### 📈 Real-Time Traffic Analysis")
    
    chart = create_traffic_chart(timeline)
    st.plotly_chart(chart, use_container_width=True)
    
    st.markdown("---")
    
    # === ANOMALIES TABLE ===
    st.markdown("### 🔴 Recent Red Alerts (Latest 10 Anomalies)")
    
    render_anomaly_table(anomalies)
    
    # === SYSTEM LOGS (Sidebar) ===
    render_system_logs(logs)
    
    # Sidebar statistics
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 System Statistics")
    
    db_size = db.get_database_size()
    st.sidebar.metric("Database Size", f"{db_size / 1024:.2f} KB")
    st.sidebar.metric("Total Flows", f"{stats['total_flows']:,}")
    
    if stats['threat_levels']:
        st.sidebar.markdown("#### Threat Distribution")
        for level, count in stats['threat_levels'].items():
            color = get_threat_color(level)
            st.sidebar.markdown(
                f"<span style='color: {color};'>⬤</span> {level}: {count}",
                unsafe_allow_html=True
            )
    
    # Auto-refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()
