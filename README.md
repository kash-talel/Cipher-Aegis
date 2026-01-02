# Cipher Aegis

**A Next-Generation Network Intrusion Detection System**

Cipher Aegis is a modular, machine learning-powered intrusion detection system designed to identify zero-day attacks and anomalous network behavior in real-time. Built on Python 3.11+, the system employs unsupervised learning techniques to establish baseline network behavior and detect deviations indicative of potential security threats.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [System Components](#system-components)
- [Machine Learning Pipeline](#machine-learning-pipeline)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Performance Metrics](#performance-metrics)
- [Development Roadmap](#development-roadmap)
- [Contributing](#contributing)
- [License](#license)

## Overview

### Design Philosophy

Cipher Aegis is built on three core principles:

1. **Modularity**: Each component (packet capture, feature extraction, ML detection, visualization) operates independently with well-defined interfaces
2. **Type Safety**: Full type hinting throughout the codebase ensures maintainability and reduces runtime errors
3. **Real-Time Processing**: Asynchronous packet capture and threaded processing enable real-time analysis without blocking

### Technical Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Packet Capture | Scapy 2.5+ | Raw packet sniffing and parsing |
| Feature Extraction | NumPy, Pandas | Flow aggregation and statistical analysis |
| ML Detection | scikit-learn (Isolation Forest) | Unsupervised anomaly detection |
| Persistence | SQLite | Flow and anomaly storage |
| Visualization | Streamlit, Plotly | Real-time dashboard |
| Type System | Python 3.11+ Type Hints | Static type checking |

### Use Cases

- **Network Security Monitoring**: Continuous monitoring of enterprise networks
- **Intrusion Detection**: Identification of unauthorized access attempts
- **Anomaly Detection**: Detection of zero-day attacks without signature databases
- **Threat Intelligence**: Collecting and analyzing network flow data
- **Security Research**: Testing and validating security hypotheses

## Architecture

### High-Level Architecture

```
┌──────────────┐
│   Network    │
│  Interface   │
└──────┬───────┘
       │ Raw Packets
       ▼
┌──────────────────────┐
│  NetworkSentinel     │  Async packet capture (Scapy)
│  (core/sniffer.py)   │  BPF filtering, protocol parsing
└──────┬───────────────┘
       │ PacketInfo objects
       ▼
┌──────────────────────┐
│  FeatureExtractor    │  Flow aggregation (5-tuple)
│  (core/features.py)  │  Bidirectional tracking
└──────┬───────────────┘
       │ FlowFeatures (16 dimensions)
       ▼
┌──────────────────────┐
│   AegisBrain         │  Isolation Forest ML
│   (ml/model.py)      │  Anomaly scoring
└──────┬───────────────┘
       │ Predictions + Threat Classification
       ▼
┌──────────────────────┐
│  DatabaseManager     │  SQLite persistence
│  (db_manager.py)     │  Flow/anomaly storage
└──────┬───────────────┘
       │
       ▼
┌──────────────────────┐
│  Streamlit Dashboard │  Real-time visualization
│  (app.py)            │  Metrics, charts, alerts
└──────────────────────┘
```

### Data Flow Pipeline

```
Raw Packet → PacketInfo → FlowStats → FlowFeatures → ML Prediction → Database → Dashboard
     |            |           |            |              |              |          |
     |            |           |            |              |              |          |
   5-tuple    Metadata   Aggregation   16D Vector    Anomaly Score    Storage   Display
```

### Threading Model

The system employs a multi-threaded architecture for non-blocking operation:

- **Main Thread**: System orchestration and user interaction
- **Sentinel Thread**: Packet capture daemon (Scapy async sniffer)
- **Processing Callbacks**: Feature extraction executed in sentinel thread context
- **Database Thread Pool**: SQLite connection pooling for concurrent writes

Thread safety is ensured through:
- `threading.Lock()` on shared state modifications
- Immutable dataclass objects for inter-thread communication
- Thread-safe queue implementations for packet buffering

## Features

### Network Capture Module

**File**: `core/sniffer.py`

- Asynchronous packet sniffing using Scapy
- Berkeley Packet Filter (BPF) support for efficient filtering
- Protocol parsing: TCP, UDP, ICMP
- Dual-mode operation: callback-based or queue-based
- Packet drop detection and statistics
- Graceful thread termination

**Supported Protocols**:
- TCP with flag extraction (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
- UDP with payload size tracking
- ICMP with type/code extraction

### Feature Extraction Module

**File**: `core/features.py`

Implements bidirectional flow tracking using 5-tuple identification:
- Source IP and Port
- Destination IP and Port
- Protocol

**Statistical Features** (16 dimensions per flow):

| Category | Features | Description |
|----------|----------|-------------|
| Temporal | flow_duration | Time between first and last packet |
| Volume | total_fwd_packets, total_bwd_packets | Packet counts per direction |
| Packet Size | packet_length_mean, packet_length_std | Size statistics (overall, forward, backward) |
| Inter-Arrival Time | iat_mean, iat_std | Timing statistics (overall, forward, backward) |

**Flow Timeout Management**:
- Configurable inactivity timeout (default: 60 seconds)
- Automatic cleanup of stale flows
- Flow finalization on system shutdown

### Machine Learning Module

**File**: `ml/model.py`

**Algorithm**: Isolation Forest (IF)

Isolation Forest is an unsupervised anomaly detection algorithm particularly suited for network intrusion detection due to:
- Linear time complexity: O(n log n)
- No requirement for labeled training data
- Effective handling of high-dimensional data
- Robustness to noise and outliers

**Model Parameters**:
```python
contamination = 0.1      # Expected anomaly proportion (10%)
n_estimators = 100       # Number of isolation trees
max_samples = 256        # Samples per tree
random_state = 42        # Reproducibility seed
```

**Training Process**:
1. Capture baseline traffic (default: 60 seconds)
2. Extract 16-dimensional feature vectors
3. Apply StandardScaler normalization
4. Fit Isolation Forest model
5. Serialize model to disk (pickle format)

**Prediction Process**:
1. Extract features from new flow
2. Apply trained scaler transformation
3. Compute anomaly score via decision_function()
4. Normalize score to [0, 1] range
5. Classify threat level (LOW/MEDIUM/HIGH)

### Real-Time Dashboard

**File**: `app.py`

Interactive Streamlit-based web interface featuring:

**Metrics Panel**:
- Total packet count across all flows
- Anomaly detection count
- Current threat level indicator

**Traffic Visualization**:
- Dual-axis time-series chart
- Bar plot: Traffic volume (packets per flow)
- Line plot: Anomaly scores over time
- Color-coded anomaly markers

**Anomaly Table**:
- Latest 10 detected anomalies
- Timestamp, IP addresses, ports, protocol
- Anomaly score and threat classification
- Human-readable threat descriptions

**System Logs**:
- Real-time event stream
- Color-coded severity levels (INFO, WARNING, ERROR)
- Scrollable history

**Controls**:
- Auto-refresh toggle (1-30 second intervals)
- Manual refresh capability
- System statistics display

### Database Schema

**File**: `db_manager.py`

**SQLite Database**: `data/events.db`

**Tables**:

1. **flows**: All captured network flows
   - Flow identifiers (IPs, ports, protocol)
   - 16 ML feature values
   - Anomaly flag and score
   - Indexed on timestamp and is_anomaly

2. **anomalies**: Detected anomalies only
   - Foreign key reference to flows
   - Threat level classification
   - Human-readable description
   - Indexed on timestamp

3. **system_logs**: Application event log
   - Timestamp, severity level, message
   - Indexed on timestamp

4. **statistics**: Aggregate metrics
   - Time-series performance data
   - Extensible schema for custom metrics

## Installation

### Prerequisites

- Python 3.11 or higher
- Administrator/root privileges (required for raw packet capture)
- Active network interface
- 500MB disk space (for database growth)
- 2GB RAM minimum

### System Requirements

**Supported Operating Systems**:
- Windows 10/11 (with Npcap or WinPcap)
- Linux (kernel 2.6+)
- macOS 10.14+

**Network Requirements**:
- Promiscuous mode support on network interface
- No VPN/proxy interference during training

### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CipherAegis.git
cd CipherAegis
```

2. Create and activate virtual environment (recommended):
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Verify installation:
```bash
python -c "import scapy; import sklearn; import streamlit; print('Installation successful')"
```

### Dependency List

```
scapy>=2.5.0              # Packet manipulation
scikit-learn>=1.3.0       # Machine learning
pandas>=2.0.0             # Data manipulation
numpy>=1.24.0             # Numerical computing
streamlit>=1.28.0         # Web dashboard
plotly>=5.17.0            # Interactive visualizations
matplotlib>=3.7.0         # Static plotting
seaborn>=0.12.0           # Statistical visualization
python-dotenv>=1.0.0      # Environment management
```

## Quick Start

### Initial Setup (First-Time Training)

The system requires an initial training phase to learn baseline network behavior:

```bash
# Run with administrator privileges
python main.py
```

When prompted, confirm training mode:
```
Start training mode? (yes/no): yes
```

**During Training** (60 seconds):
- Browse websites normally
- Use email and messaging applications
- Perform routine network operations
- Avoid anomalous or attack traffic

**Training Output**:
```
Training complete
Model saved to: data/models/aegis_brain.pkl
Training samples: 45
```

### Running the Complete System

**Terminal 1** (Administrator privileges required):
```bash
python main.py
```

**Terminal 2** (No elevated privileges needed):
```bash
streamlit run app.py
```

Access dashboard at: `http://localhost:8501`

### Command-Line Options

```bash
# Specify network interface
python main.py -i eth0                    # Linux
python main.py -i "Wi-Fi"                 # Windows

# Custom training duration
python main.py -t 120                     # Train for 120 seconds

# Custom flow timeout
python main.py -f 30                      # 30-second flow timeout

# Combined options
python main.py -i eth0 -t 120 -f 30
```

### Demo Mode (No Administrator Access)

Generate test data for dashboard demonstration:

```bash
# Generate 100 flows with 15% anomaly rate
python generate_test_data.py 100 0.15

# Launch dashboard
streamlit run app.py
```

## System Components

### Core Module (`core/`)

**models.py**:
- `Protocol`: Enum for network protocols
- `FlowKey`: Immutable 5-tuple flow identifier
- `PacketInfo`: Single packet metadata
- `FlowStats`: Accumulated flow statistics
- `FlowFeatures`: ML-ready feature vectors

**sniffer.py**:
- `NetworkSentinel`: Main packet capture class
  - Methods: `start()`, `stop()`, `get_statistics()`
  - Callback or queue-based packet delivery
  - Configurable BPF filters

**features.py**:
- `FeatureExtractor`: Flow aggregation engine
  - Methods: `process_packet()`, `finalize_all_flows()`
  - Bidirectional flow tracking
  - Statistical feature computation

### Machine Learning Module (`ml/`)

**model.py**:
- `AegisBrain`: Isolation Forest wrapper
  - Methods: `train()`, `predict()`, `save()`, `load()`
  - StandardScaler integration
  - Score normalization

**detector.py**:
- `AnomalyDetector`: Threat classification layer
  - Methods: `analyze_flow()`, `get_description()`
  - Threat level determination
  - Description generation

### Main Entry Point (`main.py`)

**CipherAegis** class:
- Orchestrates all system components
- Manages operational modes (training/protection)
- Handles graceful shutdown
- Provides command-line interface

**Operational Modes**:

1. **Training Mode**:
   - Captures baseline traffic
   - Trains Isolation Forest model
   - Saves model to disk
   - Exits after completion

2. **Protection Mode**:
   - Loads trained model
   - Performs real-time detection
   - Stores anomalies in database
   - Runs continuously until stopped

## Machine Learning Pipeline

### Feature Engineering

The system extracts 16 features per network flow, categorized as follows:

**Temporal Features**:
- `flow_duration`: Total duration from first to last packet (seconds)

**Volume Features**:
- `total_fwd_packets`: Count of forward direction packets
- `total_bwd_packets`: Count of backward direction packets
- `total_packets`: Sum of both directions

**Packet Length Features**:
- `packet_length_mean`: Average packet size (bytes)
- `packet_length_std`: Standard deviation of packet sizes
- `fwd_packet_length_mean`: Forward direction average
- `fwd_packet_length_std`: Forward direction standard deviation
- `bwd_packet_length_mean`: Backward direction average
- `bwd_packet_length_std`: Backward direction standard deviation

**Inter-Arrival Time Features**:
- `iat_mean`: Average time between packets (seconds)
- `iat_std`: Standard deviation of inter-arrival times
- `fwd_iat_mean`: Forward direction average IAT
- `fwd_iat_std`: Forward direction IAT standard deviation
- `bwd_iat_mean`: Backward direction average IAT
- `bwd_iat_std`: Backward direction IAT standard deviation

### Isolation Forest Implementation

**Mathematical Foundation**:

Isolation Forest assigns anomaly scores based on path length in isolation trees. Given a data point x:

```
s(x, n) = 2^(-E(h(x)) / c(n))
```

Where:
- `E(h(x))`: Expected path length for point x
- `c(n)`: Average path length for n samples
- `s(x, n)`: Anomaly score ∈ [0, 1]

**Score Interpretation**:
- s → 1: High likelihood of anomaly
- s ≈ 0.5: Normal behavior
- s → 0: Potential outlier in normal distribution

**Normalization Process**:
```python
normalized_score = (0.5 - raw_decision_score) / 1.0
clipped_score = clip(normalized_score, 0.0, 1.0)
```

### Threat Classification

Anomaly scores are mapped to threat levels:

| Score Range | Threat Level | Action |
|-------------|--------------|--------|
| 0.80 - 1.00 | HIGH | Immediate investigation |
| 0.60 - 0.79 | MEDIUM | Monitoring and logging |
| 0.00 - 0.59 | LOW | Logged for analysis |

### Model Persistence

Trained models are serialized using Python's pickle module:

```python
model_data = {
    'model': IsolationForest(),
    'scaler': StandardScaler(),
    'contamination': float,
    'n_estimators': int,
    'training_timestamp': float,
    'training_samples': int
}
```

Storage location: `data/models/aegis_brain.pkl`

## Configuration

### Berkeley Packet Filter Syntax

Customize packet capture using BPF expressions:

```python
# HTTP/HTTPS only
filter_bpf = "tcp port 80 or tcp port 443"

# Exclude SSH traffic
filter_bpf = "tcp and not port 22"

# Specific host monitoring
filter_bpf = "host 192.168.1.100"

# Protocol-specific
filter_bpf = "icmp"
filter_bpf = "udp port 53"  # DNS only
```

### Flow Timeout Configuration

Adjust flow completion criteria in `main.py`:

```python
aegis = CipherAegis(
    flow_timeout=30.0,      # Complete flow after 30s inactivity
    training_duration=120   # Train for 120 seconds
)
```

Or via command line:
```bash
python main.py -f 30 -t 120
```

### Model Hyperparameters

Tune Isolation Forest parameters in `ml/model.py`:

```python
brain = AegisBrain(
    contamination=0.15,     # 15% expected anomaly rate
    n_estimators=200,       # 200 isolation trees
    max_samples=512         # More samples per tree
)
```

### Database Configuration

Modify database path in `db_manager.py`:

```python
db = DatabaseManager(db_path="custom/path/events.db")
```

## API Documentation

### NetworkSentinel API

```python
from core.sniffer import NetworkSentinel
from core.models import PacketInfo

def packet_handler(packet: PacketInfo) -> None:
    print(f"{packet.src_ip} -> {packet.dst_ip}")

sentinel = NetworkSentinel(
    interface="eth0",                    # Network interface
    packet_callback=packet_handler,     # Callback function
    filter_bpf="tcp or udp",            # BPF filter
    packet_count=0,                      # 0 = infinite
    queue_size=10000                     # Buffer size
)

sentinel.start()                         # Begin capture
stats = sentinel.get_statistics()        # Get metrics
sentinel.stop(timeout=5.0)              # Stop capture
```

**Methods**:
- `start()`: Initialize packet capture thread
- `stop(timeout: float)`: Graceful shutdown with timeout
- `get_statistics() -> dict`: Return capture metrics
- `get_packet(block: bool, timeout: float) -> PacketInfo`: Queue-mode packet retrieval

### FeatureExtractor API

```python
from core.features import FeatureExtractor
from core.models import PacketInfo, FlowFeatures

extractor = FeatureExtractor(
    flow_timeout=60.0,       # Flow timeout (seconds)
    cleanup_interval=30.0    # Cleanup frequency
)

# Process single packet
features = extractor.process_packet(packet)

# Finalize all active flows
remaining = extractor.finalize_all_flows()

# Get statistics
stats = extractor.get_statistics()
```

**Methods**:
- `process_packet(packet: PacketInfo) -> Optional[FlowFeatures]`
- `finalize_all_flows() -> List[FlowFeatures]`
- `get_statistics() -> dict`

### AegisBrain API

```python
from ml.model import AegisBrain
from core.models import FlowFeatures

brain = AegisBrain(
    contamination=0.1,
    n_estimators=100,
    model_path="data/models/aegis_brain.pkl"
)

# Train on benign traffic
brain.train(flow_features_list)

# Make predictions
is_anomaly, score = brain.predict(flow_features)

# Persistence
brain.save()
brain.load()

# Model metadata
info = brain.get_model_info()
```

**Methods**:
- `train(features_list: List[FlowFeatures]) -> None`
- `predict(features: FlowFeatures) -> Tuple[bool, float]`
- `save(path: str) -> None`
- `load(path: str) -> bool`
- `get_model_info() -> dict`

### DatabaseManager API

```python
from db_manager import get_db

db = get_db()  # Singleton instance

# Insert flow
flow_id = db.insert_flow(flow_dict)

# Insert anomaly
anomaly_id = db.insert_anomaly(anomaly_dict)

# Log event
db.log_event("INFO", "System started")

# Query data
flows = db.get_recent_flows(limit=100)
anomalies = db.get_anomalies(limit=10)
logs = db.get_system_logs(limit=50)
stats = db.get_statistics()

# Maintenance
db.clear_old_data(days=7)
```

## Performance Metrics

### Benchmark Configuration

- **Hardware**: Intel Core i5-8250U, 16GB RAM
- **OS**: Ubuntu 22.04 LTS
- **Python**: 3.11.5
- **Network**: 1Gbps Ethernet

### Throughput Metrics

| Metric | Value | Notes |
|--------|-------|-------|
| Packet Capture Rate | 5,000 pkt/s | With callback processing |
| Flow Processing Rate | 1,000 flows/s | Feature extraction |
| ML Prediction Rate | 500 predictions/s | Single-threaded |
| Database Write Rate | 2,000 inserts/s | SQLite, indexed |

### Resource Utilization

| Resource | Usage | Configuration |
|----------|-------|---------------|
| CPU | 15-25% | 4 cores |
| Memory | 80-120 MB | 10,000 active flows |
| Disk I/O | 2-5 MB/s | Continuous write |
| Network | Passive | Promiscuous mode |

### Latency Metrics

| Operation | Latency | Percentile |
|-----------|---------|------------|
| Packet → PacketInfo | <1 ms | p99 |
| Flow aggregation | <5 ms | p99 |
| ML prediction | 10-20 ms | p95 |
| Database insert | 5-15 ms | p95 |
| End-to-end (packet → DB) | 30-50 ms | p95 |

### Scalability

**Active Flow Capacity**:
- 10,000 flows: 50 MB RAM
- 100,000 flows: 450 MB RAM
- Linear memory scaling: ~5 KB per flow

**Database Growth**:
- 1,000 flows/hour: ~150 KB/hour
- 24-hour operation: ~3.6 MB/day
- Cleanup recommended after 7 days

## Development Roadmap

### Completed Phases

**Phase 1: Network Capture Module**
- Asynchronous packet sniffing
- Protocol parsing (TCP/UDP/ICMP)
- Flow aggregation engine
- Feature extraction pipeline
- Thread-safe architecture

**Phase 2: Dashboard & Persistence**
- Real-time Streamlit dashboard
- SQLite database integration
- Traffic visualization
- Anomaly alerting
- System logging

**Phase 3: Machine Learning Integration**
- Isolation Forest implementation
- Training mode workflow
- Model persistence
- Threat classification
- Main orchestrator

### Planned Features

**Phase 4: PCAP Simulation**
- Offline PCAP file replay
- Batch processing capability
- Dataset integration (CICIDS2017, NSL-KDD)
- Forensic analysis mode
- Performance benchmarking

**Phase 5: Advanced Analytics**
- Multi-interface capture support
- GeoIP integration for IP geolocation
- Protocol-specific analyzers (HTTP, DNS, TLS)
- Advanced statistical features
- Ensemble ML models

**Phase 6: Production Hardening**
- Comprehensive unit test suite
- Integration testing framework
- Performance optimization
- Docker containerization
- Distributed deployment support
- Horizontal scaling capabilities

**Phase 7: Alerting & Integration**
- Email notification system
- Webhook integration (Slack, Discord, Teams)
- SIEM integration (Splunk, ELK)
- Custom alert rules engine
- Time-based alerting policies

**Phase 8: Reporting & Export**
- PDF report generation
- CSV/JSON export functionality
- Scheduled reporting
- Executive dashboards
- Compliance reporting (PCI-DSS, HIPAA)

## Contributing

Contributions are welcome. Please follow these guidelines:

### Code Standards

- Python 3.11+ with full type hints
- PEP 8 style compliance
- Docstrings for all public APIs (Google style)
- Maximum line length: 100 characters
- Use Black formatter with default settings

### Development Workflow

1. Fork the repository
2. Create feature branch: `git checkout -b feature/description`
3. Implement changes with tests
4. Run test suite: `pytest tests/`
5. Run linter: `flake8 .`
6. Run type checker: `mypy .`
7. Commit with descriptive message
8. Push to fork and create pull request

### Testing Requirements

- Unit tests for all new functions
- Integration tests for component interactions
- Minimum 80% code coverage
- Performance regression tests for critical paths

### Documentation Requirements

- Update README for significant changes
- Add docstrings to new functions
- Include usage examples
- Document API changes

## License

This project is licensed under the MIT License - see LICENSE file for details.

## Citation

If you use Cipher Aegis in academic research, please cite:

```bibtex
@software{cipher_aegis,
  title={Cipher Aegis: Machine Learning-Based Network Intrusion Detection},
  author={Your Name},
  year={2026},
  url={https://github.com/yourusername/CipherAegis}
}
```

## Acknowledgments

This project builds upon research and technologies from:
- scikit-learn machine learning library
- Scapy packet manipulation framework
- Isolation Forest algorithm (Liu et al., 2008)
- Network flow analysis methodologies

## Contact

For questions, issues, or collaboration inquiries:
- GitHub Issues: [Project Issues](https://github.com/yourusername/CipherAegis/issues)
- Email: your.email@example.com

## Disclaimer

This software is provided for educational and research purposes. Users are responsible for ensuring compliance with applicable laws and regulations regarding network monitoring in their jurisdiction. Unauthorized network monitoring may be illegal.
