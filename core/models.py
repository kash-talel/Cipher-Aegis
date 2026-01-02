"""
Cipher Aegis - Data Models
Type-safe dataclasses for packet and flow representation.
"""

from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Protocol(Enum):
    """Supported network protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


@dataclass(frozen=True)
class FlowKey:
    """
    Immutable identifier for a network flow.
    Uses 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol).
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol

    def reverse(self) -> 'FlowKey':
        """Returns the reverse flow key (for bidirectional flow tracking)."""
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol
        )


@dataclass
class PacketInfo:
    """
    Extracted information from a single packet.
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    length: int  # Packet size in bytes
    flags: Optional[str] = None  # TCP flags (e.g., "SYN", "ACK")
    payload_size: int = 0  # Payload bytes (excluding headers)


@dataclass
class FlowStats:
    """
    Aggregated statistics for a single network flow.
    Tracks both forward (fwd) and backward (bwd) directions.
    """
    flow_key: FlowKey
    first_timestamp: float
    last_timestamp: float
    
    # Packet counts
    fwd_packet_count: int = 0
    bwd_packet_count: int = 0
    
    # Packet lengths (bytes)
    fwd_packet_lengths: list[int] = field(default_factory=list)
    bwd_packet_lengths: list[int] = field(default_factory=list)
    
    # Inter-arrival times (seconds)
    fwd_iat: list[float] = field(default_factory=list)
    bwd_iat: list[float] = field(default_factory=list)
    
    # TCP-specific
    tcp_flags: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Flow duration in seconds."""
        return max(self.last_timestamp - self.first_timestamp, 0.0)

    @property
    def total_packets(self) -> int:
        """Total packets in both directions."""
        return self.fwd_packet_count + self.bwd_packet_count


@dataclass
class FlowFeatures:
    """
    Engineered features for machine learning.
    Calculated from FlowStats for anomaly detection.
    """
    flow_key: FlowKey
    
    # Temporal features
    flow_duration: float
    
    # Volume features
    total_fwd_packets: int
    total_bwd_packets: int
    total_packets: int
    
    # Packet length statistics
    fwd_packet_length_mean: float
    fwd_packet_length_std: float
    bwd_packet_length_mean: float
    bwd_packet_length_std: float
    packet_length_mean: float
    packet_length_std: float
    
    # Inter-arrival time statistics
    fwd_iat_mean: float
    fwd_iat_std: float
    bwd_iat_mean: float
    bwd_iat_std: float
    iat_mean: float
    iat_std: float
    
    # Flow metadata
    timestamp: float  # Flow start time
    protocol: Protocol

    def to_vector(self) -> list[float]:
        """
        Converts features to a numerical vector for ML models.
        Returns a flat list of all feature values.
        """
        return [
            self.flow_duration,
            float(self.total_fwd_packets),
            float(self.total_bwd_packets),
            float(self.total_packets),
            self.fwd_packet_length_mean,
            self.fwd_packet_length_std,
            self.bwd_packet_length_mean,
            self.bwd_packet_length_std,
            self.packet_length_mean,
            self.packet_length_std,
            self.fwd_iat_mean,
            self.fwd_iat_std,
            self.bwd_iat_mean,
            self.bwd_iat_std,
            self.iat_mean,
            self.iat_std,
        ]

    @staticmethod
    def feature_names() -> list[str]:
        """Returns feature names for vector representation."""
        return [
            "flow_duration",
            "total_fwd_packets",
            "total_bwd_packets",
            "total_packets",
            "fwd_packet_length_mean",
            "fwd_packet_length_std",
            "bwd_packet_length_mean",
            "bwd_packet_length_std",
            "packet_length_mean",
            "packet_length_std",
            "fwd_iat_mean",
            "fwd_iat_std",
            "bwd_iat_mean",
            "bwd_iat_std",
            "iat_mean",
            "iat_std",
        ]
