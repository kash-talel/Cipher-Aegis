# 🚀 Cipher Aegis - Complete Startup Guide

## Quick Start (3 Steps)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. First-Time Training (One-Time)
```powershell
# Run as Administrator (Windows) or with sudo (Linux/Mac)
python main.py
```

When prompted, select **"yes"** for training mode.
- Browse the web normally
- Make some DNS queries
- Wait 60 seconds
- Model will be saved automatically

### 3. Run Protection Mode
```powershell
# Terminal 1: Run Cipher Aegis (as Administrator)
python main.py

# Terminal 2: Run Dashboard (no admin needed)
streamlit run app.py
```

---

## Detailed Walkthrough

### Prerequisites

- **Python 3.11+**
- **Administrator/Root privileges** (for packet capture)
- **Active network interface**

### Installation

1. **Navigate to project directory:**
```bash
cd c:\Users\kash_talel\OneDrive\Desktop\gang\CipherAegis
```

2. **Create virtual environment (recommended):**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

---

## First Run - Training Mode

### What is Training Mode?

Training mode creates a baseline ML model by observing **normal network traffic**. The model learns what "normal" looks like so it can detect anomalies later.

### Starting Training

```powershell
# Run as Administrator (Windows PowerShell)
python main.py
```

You'll see:
```
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║    ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗      █████╗ ███████╗       ║
║   ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝       ║
║   ██║     ██║██████╔╝███████║█████╗  ██████╔╝    ███████║█████╗         ║
║   ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗    ██╔══██║██╔══╝         ║
║   ╚██████╗██║██║     ██║  ██║███████╗██║  ██║    ██║  ██║███████╗       ║
║    ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝       ║
...

⚠️  No trained model found

Start training mode? (yes/no):
```

### During Training (60 seconds)

**DO:**
- ✅ Browse websites normally
- ✅ Check email
- ✅ Use messaging apps
- ✅ Make DNS queries (ping google.com)
- ✅ Download small files

**DON'T:**
- ❌ Run attacks or scans
- ❌ Generate anomalous traffic
- ❌ Use VPN/Tor during training
- ❌ Run penetration testing tools

### After Training

You'll see:
```
✅ TRAINING COMPLETE

Model saved to: data/models/aegis_brain.pkl
Training samples: 45

You can now run Cipher Aegis in protection mode:
  python main.py
```

---

## Regular Operation - Protection Mode

### Starting Protection Mode

```powershell
# Terminal 1: Start Cipher Aegis (as Administrator)
python main.py
```

Output:
```
🛡️  PROTECTION MODE ACTIVE

Cipher Aegis is now protecting your network!

📊 Dashboard: Run 'streamlit run app.py' in another terminal
⏹️  Stop: Press Ctrl+C

⏱️  Runtime: 45s | Packets: 1,523 | Flows: 42 | Anomalies: 3 | Active: 5
```

### Starting the Dashboard

In a **separate terminal** (no admin needed):

```bash
streamlit run app.py
```

Browser will open automatically at: **http://localhost:8501**

---

## Command-Line Options

### Basic Usage
```bash
python main.py
```

### Custom Network Interface
```bash
# Windows
python main.py -i "Wi-Fi"

# Linux
python main.py -i eth0
```

### Custom Training Duration
```bash
python main.py -t 120  # Train for 120 seconds
```

### Custom Flow Timeout
```bash
python main.py -f 30  # 30-second flow timeout
```

### Combined Options
```bash
python main.py -i eth0 -t 120 -f 30
```

---

## System Architecture

```
┌─────────────────────┐
│   main.py           │  Main orchestrator
│   (Entry Point)     │
└──────────┬──────────┘
           │
           ├─────► NetworkSentinel (packet capture)
           │
           ├─────► FeatureExtractor (flow aggregation)
           │
           ├─────► AegisBrain (ML model)
           │
           ├─────► DatabaseManager (SQLite)
           │
           └─────► AnomalyDetector (threat classification)
```

---

## Operational Modes

### Mode 1: Training Mode
- **Purpose**: Create baseline ML model
- **Duration**: 60 seconds (configurable)
- **Requirements**: Admin privileges
- **Traffic**: Normal traffic only
- **Output**: Trained model saved to `data/models/`

### Mode 2: Protection Mode
- **Purpose**: Detect anomalies in real-time
- **Duration**: Continuous (until stopped)
- **Requirements**: Admin privileges
- **Traffic**: All traffic (normal and anomalous)
- **Output**: Anomalies logged to database

---

## Directory Structure After First Run

```
CipherAegis/
├── data/
│   ├── events.db          # ✅ Created automatically
│   └── models/
│       └── aegis_brain.pkl  # ✅ Created during training
│
├── logs/
│   └── cipher_aegis.log   # ✅ Created automatically
│
└── ... (other files)
```

---

## Monitoring

### Real-Time Console Output

**Training Mode:**
```
Training: 45s / 60s (32 flows captured)
```

**Protection Mode:**
```
⏱️  Runtime: 120s | Packets: 3,456 | Flows: 89 | Anomalies: 7 | Active: 12
```

### Dashboard Monitoring

Open **http://localhost:8501** to see:
- Total Packets
- Anomalies Detected
- Current Threat Level
- Traffic chart
- Red alerts table
- System logs

### Log Files

```bash
# View logs
cat logs/cipher_aegis.log

# Real-time monitoring (Linux/Mac)
tail -f logs/cipher_aegis.log

# Real-time monitoring (Windows)
Get-Content logs/cipher_aegis.log -Wait
```

---

## Stopping Cipher Aegis

Press **Ctrl+C** in the terminal running `main.py`.

You'll see:
```
🛑 Shutting down Cipher Aegis...
🔄 Finalizing flows...
✅ Cipher Aegis stopped successfully
```

This ensures:
- All active flows are finalized
- Remaining flows are analyzed
- Database is properly closed
- Logs are flushed

---

## Troubleshooting

### "Permission denied" error

**Cause:** Packet capture requires admin/root privileges

**Solution:**
```powershell
# Windows: Run PowerShell as Administrator, then:
python main.py

# Linux/Mac:
sudo python main.py
```

### "No trained model found" (on second run)

**Cause:** Model file was deleted or corrupted

**Solution:** Run training mode again (say "yes" when prompted)

### "Not enough flows for training"

**Cause:** Insufficient network activity during training

**Solution:**
- Generate more traffic (browse web, ping servers)
- Increase training duration: `python main.py -t 120`

### Dashboard shows "No data available"

**Cause:** Database is empty

**Solutions:**
1. Ensure `main.py` is running
2. Wait for flows to complete (60-second timeout)
3. Generate test data: `python generate_test_data.py`

### High false positive rate

**Cause:** Training data not representative

**Solution:** Retrain with more diverse normal traffic:
1. Delete `data/models/aegis_brain.pkl`
2. Run `python main.py`
3. Generate varied traffic during training

---

## Best Practices

### Training
- ✅ Train during typical usage hours
- ✅ Include all common applications
- ✅ Generate diverse protocols (HTTP, DNS, etc.)
- ✅ Use at least 60 seconds (more is better)
- ❌ Don't train during attacks
- ❌ Don't train with VPN/Proxy active

### Operation
- ✅ Run dashboard in separate terminal
- ✅ Monitor logs regularly
- ✅ Check dashboard for alerts
- ✅ Investigate HIGH threats immediately
- ✅ Retrain periodically (e.g., monthly)

### Maintenance
- ✅ Clean old database entries: `db.clear_old_data(days=7)`
- ✅ Backup model files regularly
- ✅ Archive log files periodically
- ✅ Monitor disk space

---

## Example Session

```powershell
# 1. First time - Training
PS C:\...\CipherAegis> python main.py
# ... banner appears ...
# ... "No model found" message ...
Start training mode? (yes/no): yes
# ... browse web for 60 seconds ...
# ✅ Training complete

# 2. Regular operation
PS C:\...\CipherAegis> python main.py
# ... protection mode starts ...

# 3. In another terminal (no admin)
PS C:\...\CipherAegis> streamlit run app.py
# ... dashboard opens in browser ...

# 4. Stop when done
# Press Ctrl+C in main.py terminal
# ✅ Shutdown complete
```

---

## Next Steps

Once running, you can:
1. **Monitor Dashboard**: View real-time metrics
2. **Check Logs**: Review detected anomalies
3. **Generate Traffic**: Test detection with various scenarios
4. **Tune Parameters**: Adjust contamination, thresholds
5. **Retrain**: Update model with new baseline

---

**🛡️ Cipher Aegis is now protecting your network!**
