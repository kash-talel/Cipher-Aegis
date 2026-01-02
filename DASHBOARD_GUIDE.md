# 🎯 Cipher Aegis Dashboard - Quick Start Guide

## Running the Complete System

The Cipher Aegis system consists of two components:

1. **Sentinel (Backend)** - Captures packets and stores in database
2. **Dashboard (Frontend)** - Visualizes data in real-time

### Step 1: Install Dependencies

```bash
cd c:\Users\kash_talel\OneDrive\Desktop\gang\CipherAegis
pip install -r requirements.txt
```

### Step 2: Start the Sentinel (Terminal 1)

**⚠️ Requires Administrator privileges!**

```powershell
# Run PowerShell as Administrator
python sentinel_integrated.py
```

This will:
- ✅ Capture network packets
- ✅ Extract flow features
- ✅ Detect anomalies (simulated ML)
- ✅ Store data in SQLite database
- ✅ Generate system logs

You should see:
```
⏱️  Packets: 523 (Dropped: 0) | Active Flows: 12 | Processed: 45 | Anomalies: 3
```

### Step 3: Start the Dashboard (Terminal 2)

In a **separate terminal** (no admin needed):

```bash
streamlit run app.py
```

The dashboard will open automatically in your browser at:
```
http://localhost:8501
```

---

## Dashboard Features

### 📊 Metrics Row
- **Total Packets**: Cumulative packet count across all flows
- **Anomalies Detected**: Number of red alerts triggered
- **Current Threat Level**: HIGH / MEDIUM / LOW based on recent activity

### 📈 Traffic Chart
- **Blue Bars**: Traffic volume (packets per flow)
- **Red Line**: Anomaly scores over time
- **Red Markers**: Confirmed anomalies
- **Green Markers**: Normal traffic

### 🔴 Red Alerts Table
- Latest 10 anomalies with:
  - Timestamp
  - Source/Destination IPs and ports
  - Protocol (TCP/UDP/ICMP)
  - Anomaly score
  - Threat level
  - Description

### 📋 System Logs (Sidebar)
- Real-time event stream
- Color-coded by severity:
  - 🔴 **ERROR**: Critical issues
  - ⚠️ **WARNING**: Anomaly detections
  - ℹ️ **INFO**: Normal operations

### ⚙️ Controls (Sidebar)
- **Auto-refresh**: Toggle automatic data refresh
- **Refresh Interval**: 1-30 seconds
- **System Statistics**: Database size, flow counts, threat distribution

---

## Testing Without Live Capture

If you don't have admin privileges or want to test with sample data:

### Generate Test Data

```python
python -c "
from db_manager import get_db
from datetime import datetime
import random

db = get_db()

# Generate 50 sample flows
for i in range(50):
    flow = {
        'timestamp': datetime.now().timestamp() - (50-i)*60,
        'src_ip': f'192.168.1.{random.randint(1,254)}',
        'dst_ip': f'93.184.{random.randint(1,254)}.{random.randint(1,254)}',
        'src_port': random.randint(1024, 65535),
        'dst_port': random.choice([80, 443, 22, 3389, 8080]),
        'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
        'flow_duration': random.uniform(1, 300),
        'total_fwd_packets': random.randint(5, 100),
        'total_bwd_packets': random.randint(5, 100),
        'total_packets': random.randint(10, 200),
        'packet_length_mean': random.uniform(100, 1400),
        'packet_length_std': random.uniform(50, 500),
        'fwd_packet_length_mean': random.uniform(100, 1400),
        'fwd_packet_length_std': random.uniform(50, 500),
        'bwd_packet_length_mean': random.uniform(100, 1400),
        'bwd_packet_length_std': random.uniform(50, 500),
        'iat_mean': random.uniform(0.001, 0.1),
        'iat_std': random.uniform(0.0001, 0.05),
        'fwd_iat_mean': random.uniform(0.001, 0.1),
        'fwd_iat_std': random.uniform(0.0001, 0.05),
        'bwd_iat_mean': random.uniform(0.001, 0.1),
        'bwd_iat_std': random.uniform(0.0001, 0.05),
        'is_anomaly': 1 if random.random() > 0.85 else 0,
        'anomaly_score': random.uniform(0, 1),
    }
    
    flow_id = db.insert_flow(flow)
    
    # Add anomaly if detected
    if flow['is_anomaly']:
        db.insert_anomaly({
            'flow_id': flow_id,
            'timestamp': flow['timestamp'],
            'src_ip': flow['src_ip'],
            'dst_ip': flow['dst_ip'],
            'src_port': flow['src_port'],
            'dst_port': flow['dst_port'],
            'protocol': flow['protocol'],
            'anomaly_score': flow['anomaly_score'],
            'threat_level': 'HIGH' if flow['anomaly_score'] > 0.8 else 'MEDIUM',
            'description': 'Test anomaly',
        })

db.log_event('INFO', 'Generated 50 test flows')
print('✅ Test data generated!')
"
```

Then run just the dashboard:
```bash
streamlit run app.py
```

---

## Troubleshooting

### Dashboard shows "No data available"
**Cause**: Sentinel hasn't captured any flows yet

**Solutions**:
1. Generate some network traffic (browse web, ping, etc.)
2. Wait for flow timeout (60 seconds by default)
3. Use test data generation script above

### "Permission denied" when starting Sentinel
**Cause**: Packet capture requires admin privileges

**Solutions**:
- **Windows**: Right-click PowerShell → "Run as Administrator"
- **Linux/Mac**: `sudo python sentinel_integrated.py`

### Dashboard not updating
**Cause**: Auto-refresh disabled

**Solution**: 
1. Check "🔄 Auto-refresh" in sidebar
2. Adjust refresh interval if needed

### Database getting too large
**Cause**: Long-running capture with no cleanup

**Solution**:
```python
from db_manager import get_db
db = get_db()
db.clear_old_data(days=1)  # Keep only last 24 hours
```

---

## Architecture Overview

```
┌─────────────────┐
│  Network        │
│  Interface      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌──────────────┐
│ NetworkSentinel │────▶ │ SQLite DB    │
│  (Backend)      │      │ (events.db)  │
└─────────────────┘      └──────┬───────┘
                                │
                                ▼
                         ┌──────────────┐
                         │  Streamlit   │
                         │  Dashboard   │
                         │  (Frontend)  │
                         └──────────────┘
```

**Data Flow**:
1. Sentinel captures packets → Extracts features → Detects anomalies
2. Data stored in SQLite database
3. Dashboard queries database every N seconds
4. UI updates with new data

**Process Isolation**:
- Backend and frontend run independently
- Communication via shared SQLite database
- No direct IPC or sockets needed

---

## Advanced Configuration

### Custom Flow Timeout

Edit `sentinel_integrated.py`:
```python
integration = SentinelIntegration(
    flow_timeout=30.0,  # 30 seconds instead of 60
)
```

### Custom BPF Filter

Edit `sentinel_integrated.py`, modify the NetworkSentinel initialization:
```python
self.sentinel = NetworkSentinel(
    filter_bpf="tcp port 80 or tcp port 443",  # HTTP/HTTPS only
)
```

### Dashboard Refresh Rate

Use the sidebar slider or edit `app.py`:
```python
refresh_interval = st.sidebar.slider(
    "Refresh Interval (seconds)",
    min_value=1,
    max_value=30,
    value=2,  # Default to 2 seconds instead of 5
)
```

---

## Next Steps

1. **Run the system** and generate traffic
2. **Observe anomalies** in the dashboard
3. **Wait for ML module** to replace simulated detection
4. **Integrate PCAP replay** for offline testing

---

## Need Help?

Check the main README.md for:
- Full API documentation
- Architecture details
- Performance tuning
- Contributing guidelines

**Happy Hunting! 🛡️**
