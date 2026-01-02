"""
Cipher Aegis - Architecture Documentation
Visual representation of the Sentinel Module architecture.
"""

ARCHITECTURE_ASCII = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                        CIPHER AEGIS - SENTINEL MODULE                        ║
╚══════════════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────────────┐
│                          NETWORK TRAFFIC FLOW                                │
└─────────────────────────────────────────────────────────────────────────────┘

    Network Interface
          │
          │ Raw Packets (TCP/UDP/ICMP)
          ▼
    ┌─────────────────┐
    │ NetworkSentinel │ ◄─── Threaded Capture (Scapy)
    │   (sniffer.py)  │
    └─────────────────┘
          │
          │ PacketInfo Objects
          │ (timestamp, IPs, ports, protocol, length, flags)
          ▼
    ┌──────────────────┐
    │ FeatureExtractor │ ◄─── Flow Aggregation Engine
    │  (features.py)   │
    └──────────────────┘
          │
          │ Bidirectional Flow Tracking
          │ • Forward/Backward packet counts
          │ • Packet length statistics
          │ • Inter-arrival times
          │ • Flow duration
          ▼
    ┌──────────────────┐
    │  FlowFeatures    │ ◄─── ML-Ready Feature Vectors
    │   (models.py)    │
    └──────────────────┘
          │
          │ 16-Dimensional Feature Vector
          ▼
    ┌──────────────────┐
    │   ML Model       │ ◄─── [NEXT PHASE: Isolation Forest]
    │  (model.py)      │
    └──────────────────┘
          │
          │ Anomaly Scores
          ▼
    ┌──────────────────┐
    │   Dashboard      │ ◄─── [NEXT PHASE: Streamlit UI]
    │ (dashboard.py)   │
    └──────────────────┘


┌─────────────────────────────────────────────────────────────────────────────┐
│                          DATA MODEL HIERARCHY                                │
└─────────────────────────────────────────────────────────────────────────────┘

PacketInfo (Individual Packet)
  ├─ timestamp: float
  ├─ src_ip: str
  ├─ dst_ip: str
  ├─ src_port: int
  ├─ dst_port: int
  ├─ protocol: Protocol (TCP/UDP/ICMP)
  ├─ length: int
  ├─ flags: str | None
  └─ payload_size: int

        ↓ Aggregation by FlowKey (5-tuple)

FlowKey (Immutable Flow Identifier)
  ├─ src_ip: str
  ├─ dst_ip: str
  ├─ src_port: int
  ├─ dst_port: int
  └─ protocol: Protocol

        ↓ Accumulate Statistics

FlowStats (Raw Flow Metrics)
  ├─ flow_key: FlowKey
  ├─ first_timestamp: float
  ├─ last_timestamp: float
  ├─ fwd_packet_count: int
  ├─ bwd_packet_count: int
  ├─ fwd_packet_lengths: list[int]
  ├─ bwd_packet_lengths: list[int]
  ├─ fwd_iat: list[float]
  ├─ bwd_iat: list[float]
  └─ tcp_flags: list[str]

        ↓ Feature Engineering

FlowFeatures (ML-Ready Features)
  ├─ flow_duration: float
  ├─ total_fwd_packets: int
  ├─ total_bwd_packets: int
  ├─ total_packets: int
  ├─ packet_length_mean: float
  ├─ packet_length_std: float
  ├─ fwd_packet_length_mean: float
  ├─ fwd_packet_length_std: float
  ├─ bwd_packet_length_mean: float
  ├─ bwd_packet_length_std: float
  ├─ iat_mean: float
  ├─ iat_std: float
  ├─ fwd_iat_mean: float
  ├─ fwd_iat_std: float
  ├─ bwd_iat_mean: float
  └─ bwd_iat_std: float

        ↓ Convert to Vector

Feature Vector: [16 numerical values]


┌─────────────────────────────────────────────────────────────────────────────┐
│                          THREADING MODEL                                     │
└─────────────────────────────────────────────────────────────────────────────┘

Main Thread
  │
  ├─► NetworkSentinel Thread (Daemon)
  │     │
  │     ├─► Scapy Sniff Loop
  │     │     │
  │     │     └─► _packet_handler()
  │     │           │
  │     │           ├─► _parse_packet() → PacketInfo
  │     │           │
  │     │           └─► packet_callback(PacketInfo)
  │     │                 │
  │     │                 └─► FeatureExtractor.process_packet()
  │     │                       │
  │     │                       ├─► Update FlowStats (thread-safe)
  │     │                       └─► Return FlowFeatures (if timeout)
  │     │
  │     └─► Statistics Tracking (thread-safe)
  │
  └─► Main Processing Loop
        │
        └─► Display/Store FlowFeatures


┌─────────────────────────────────────────────────────────────────────────────┐
│                        THREAD SAFETY MECHANISMS                              │
└─────────────────────────────────────────────────────────────────────────────┘

NetworkSentinel
  ├─ _lock: threading.Lock()
  │   └─ Protects: _packets_captured, _packets_dropped
  │
  ├─ _stop_event: threading.Event()
  │   └─ Signals thread termination
  │
  └─ packet_queue: Queue (thread-safe)
      └─ Bounded buffer (configurable size)

FeatureExtractor
  └─ _lock: threading.Lock()
      └─ Protects: _flows dict, statistics


┌─────────────────────────────────────────────────────────────────────────────┐
│                          PERFORMANCE OPTIMIZATIONS                           │
└─────────────────────────────────────────────────────────────────────────────┘

1. Zero-Copy Packet Processing
   └─ Scapy sniff with store=False (no memory accumulation)

2. Callback Mode (Default)
   └─ Direct processing without queue overhead

3. Bounded Queue Mode (Optional)
   └─ Prevents memory exhaustion under high load
   └─ Drops packets when queue is full (tracked in metrics)

4. Flow Timeout Management
   └─ Automatic cleanup of stale flows
   └─ Configurable timeout and cleanup intervals

5. Efficient Statistics
   └─ O(1) mean/std calculation using statistics module
   └─ Lazy evaluation (only on flow completion)

6. Bidirectional Flow Tracking
   └─ Single FlowStats for both directions
   └─ Uses FlowKey.reverse() for lookup


┌─────────────────────────────────────────────────────────────────────────────┐
│                          ERROR HANDLING                                      │
└─────────────────────────────────────────────────────────────────────────────┘

├─ Permission Errors
│   └─ Caught and logged (requires root/admin)
│
├─ Packet Parsing Errors
│   └─ Gracefully skipped with debug logging
│
├─ Queue Overflow
│   └─ Packets dropped, counter incremented
│
├─ Thread Termination
│   └─ Graceful shutdown with timeout
│
└─ Flow Finalization
    └─ All active flows finalized on stop()

"""

def print_architecture():
    """Print the architecture diagram."""
    print(ARCHITECTURE_ASCII)


if __name__ == "__main__":
    print_architecture()
