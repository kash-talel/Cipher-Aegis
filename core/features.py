"""
Cipher Aegis - Feature Extractor
Aggregates packets into flows and calculates ML-ready features.
"""

import logging
import time
import statistics
from typing import Optional
from collections import defaultdict
from threading import Lock

from .models import PacketInfo, FlowKey, FlowStats, FlowFeatures, Protocol

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Aggregates packets into bidirectional flows and calculates statistical features.
    Thread-safe for concurrent packet processing.
    """

    def __init__(
        self,
        flow_timeout: float = 120.0,  # 2 minutes
        cleanup_interval: float = 60.0,  # 1 minute
    ):
        """
        Initialize the Feature Extractor.

        Args:
            flow_timeout: Seconds of inactivity before a flow is considered complete.
            cleanup_interval: Seconds between flow cleanup cycles.
        """
        self.flow_timeout = flow_timeout
        self.cleanup_interval = cleanup_interval

        # Flow storage: FlowKey -> FlowStats
        self._flows: dict[FlowKey, FlowStats] = {}
        self._lock = Lock()

        # Tracking
        self._last_cleanup = time.time()
        self._total_flows_created = 0
        self._total_flows_completed = 0

    def process_packet(self, packet: PacketInfo) -> Optional[FlowFeatures]:
        """
        Process a single packet and update flow statistics.
        Returns FlowFeatures if a flow is completed, otherwise None.

        Args:
            packet: Parsed packet information.

        Returns:
            FlowFeatures if flow timeout is reached, else None.
        """
        flow_key = self._create_flow_key(packet)
        
        with self._lock:
            # Check if this is a reverse flow (bidirectional)
            reverse_key = flow_key.reverse()
            
            # Use existing flow or create new one
            if flow_key in self._flows:
                flow_stats = self._flows[flow_key]
                is_forward = True
            elif reverse_key in self._flows:
                flow_stats = self._flows[reverse_key]
                is_forward = False
            else:
                # Create new flow
                flow_stats = FlowStats(
                    flow_key=flow_key,
                    first_timestamp=packet.timestamp,
                    last_timestamp=packet.timestamp,
                )
                self._flows[flow_key] = flow_stats
                self._total_flows_created += 1
                is_forward = True

            # Update flow statistics
            self._update_flow_stats(flow_stats, packet, is_forward)

            # Check for flow timeout
            if self._is_flow_complete(flow_stats, packet.timestamp):
                features = self._extract_features(flow_stats)
                del self._flows[flow_stats.flow_key]
                self._total_flows_completed += 1
                return features

            # Periodic cleanup of stale flows
            if time.time() - self._last_cleanup > self.cleanup_interval:
                completed_features = self._cleanup_stale_flows(packet.timestamp)
                self._last_cleanup = time.time()
                # Return first completed flow if any (in production, use a queue)
                if completed_features:
                    return completed_features[0]

        return None

    def _create_flow_key(self, packet: PacketInfo) -> FlowKey:
        """Create a flow key from packet information."""
        return FlowKey(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol,
        )

    def _update_flow_stats(
        self,
        flow_stats: FlowStats,
        packet: PacketInfo,
        is_forward: bool,
    ) -> None:
        """
        Update flow statistics with new packet information.

        Args:
            flow_stats: Flow statistics object to update.
            packet: Incoming packet information.
            is_forward: True if packet is in forward direction, False if backward.
        """
        # Update timestamp
        flow_stats.last_timestamp = packet.timestamp

        if is_forward:
            # Forward direction
            flow_stats.fwd_packet_count += 1
            flow_stats.fwd_packet_lengths.append(packet.length)

            # Calculate inter-arrival time
            if len(flow_stats.fwd_packet_lengths) > 1:
                # Use the last timestamp from this direction
                if flow_stats.fwd_iat:
                    last_time = flow_stats.first_timestamp + sum(flow_stats.fwd_iat)
                    iat = packet.timestamp - last_time
                else:
                    iat = packet.timestamp - flow_stats.first_timestamp
                flow_stats.fwd_iat.append(max(iat, 0.0))

        else:
            # Backward direction
            flow_stats.bwd_packet_count += 1
            flow_stats.bwd_packet_lengths.append(packet.length)

            # Calculate inter-arrival time
            if len(flow_stats.bwd_packet_lengths) > 1:
                if flow_stats.bwd_iat:
                    last_time = flow_stats.first_timestamp + sum(flow_stats.bwd_iat)
                    iat = packet.timestamp - last_time
                else:
                    iat = packet.timestamp - flow_stats.first_timestamp
                flow_stats.bwd_iat.append(max(iat, 0.0))

        # TCP flags
        if packet.flags:
            flow_stats.tcp_flags.append(packet.flags)

    def _is_flow_complete(self, flow_stats: FlowStats, current_time: float) -> bool:
        """
        Determine if a flow is complete based on timeout.

        Args:
            flow_stats: Flow statistics to check.
            current_time: Current timestamp.

        Returns:
            True if flow should be finalized.
        """
        time_since_last_packet = current_time - flow_stats.last_timestamp
        return time_since_last_packet >= self.flow_timeout

    def _extract_features(self, flow_stats: FlowStats) -> FlowFeatures:
        """
        Calculate ML features from flow statistics.

        Args:
            flow_stats: Completed flow statistics.

        Returns:
            FlowFeatures object with calculated metrics.
        """
        # Combine forward and backward packet lengths
        all_lengths = flow_stats.fwd_packet_lengths + flow_stats.bwd_packet_lengths
        all_iats = flow_stats.fwd_iat + flow_stats.bwd_iat

        return FlowFeatures(
            flow_key=flow_stats.flow_key,
            flow_duration=flow_stats.duration,
            total_fwd_packets=flow_stats.fwd_packet_count,
            total_bwd_packets=flow_stats.bwd_packet_count,
            total_packets=flow_stats.total_packets,
            
            # Packet length statistics
            fwd_packet_length_mean=self._safe_mean(flow_stats.fwd_packet_lengths),
            fwd_packet_length_std=self._safe_std(flow_stats.fwd_packet_lengths),
            bwd_packet_length_mean=self._safe_mean(flow_stats.bwd_packet_lengths),
            bwd_packet_length_std=self._safe_std(flow_stats.bwd_packet_lengths),
            packet_length_mean=self._safe_mean(all_lengths),
            packet_length_std=self._safe_std(all_lengths),
            
            # Inter-arrival time statistics
            fwd_iat_mean=self._safe_mean(flow_stats.fwd_iat),
            fwd_iat_std=self._safe_std(flow_stats.fwd_iat),
            bwd_iat_mean=self._safe_mean(flow_stats.bwd_iat),
            bwd_iat_std=self._safe_std(flow_stats.bwd_iat),
            iat_mean=self._safe_mean(all_iats),
            iat_std=self._safe_std(all_iats),
            
            timestamp=flow_stats.first_timestamp,
            protocol=flow_stats.flow_key.protocol,
        )

    @staticmethod
    def _safe_mean(values: list[float | int]) -> float:
        """Calculate mean, returning 0.0 for empty lists."""
        return float(statistics.mean(values)) if values else 0.0

    @staticmethod
    def _safe_std(values: list[float | int]) -> float:
        """Calculate standard deviation, returning 0.0 for insufficient data."""
        return float(statistics.stdev(values)) if len(values) > 1 else 0.0

    def _cleanup_stale_flows(self, current_time: float) -> list[FlowFeatures]:
        """
        Remove and finalize flows that have exceeded timeout.

        Args:
            current_time: Current timestamp.

        Returns:
            List of FlowFeatures from completed flows.
        """
        completed_features = []
        flows_to_remove = []

        for flow_key, flow_stats in self._flows.items():
            if self._is_flow_complete(flow_stats, current_time):
                flows_to_remove.append(flow_key)
                completed_features.append(self._extract_features(flow_stats))

        for flow_key in flows_to_remove:
            del self._flows[flow_key]
            self._total_flows_completed += 1

        if flows_to_remove:
            logger.debug(f"Cleaned up {len(flows_to_remove)} stale flows")

        return completed_features

    def finalize_all_flows(self) -> list[FlowFeatures]:
        """
        Finalize all active flows (useful when stopping capture).

        Returns:
            List of FlowFeatures from all active flows.
        """
        with self._lock:
            features = [self._extract_features(fs) for fs in self._flows.values()]
            self._total_flows_completed += len(self._flows)
            self._flows.clear()
            logger.info(f"Finalized {len(features)} active flows")
            return features

    def get_statistics(self) -> dict[str, int]:
        """Get feature extraction statistics."""
        with self._lock:
            return {
                "active_flows": len(self._flows),
                "total_flows_created": self._total_flows_created,
                "total_flows_completed": self._total_flows_completed,
            }

    def get_active_flow_count(self) -> int:
        """Get current number of active flows."""
        with self._lock:
            return len(self._flows)


# Example usage
if __name__ == "__main__":
    from .sniffer import NetworkSentinel
    
    extractor = FeatureExtractor(flow_timeout=30.0)
    
    def handle_packet(packet: PacketInfo) -> None:
        features = extractor.process_packet(packet)
        if features:
            print("=" * 80)
            print(f"Flow Completed: {features.flow_key.src_ip} -> {features.flow_key.dst_ip}")
            print(f"  Duration: {features.flow_duration:.2f}s")
            print(f"  Fwd Packets: {features.total_fwd_packets}, Bwd Packets: {features.total_bwd_packets}")
            print(f"  Avg Packet Length: {features.packet_length_mean:.2f} ± {features.packet_length_std:.2f}")
            print(f"  Avg IAT: {features.iat_mean:.6f}s ± {features.iat_std:.6f}")
            print("=" * 80)
    
    sentinel = NetworkSentinel(packet_callback=handle_packet)
    
    try:
        sentinel.start()
        print("Capturing and extracting features... Press Ctrl+C to stop.")
        while sentinel.is_running:
            time.sleep(1)
            stats = extractor.get_statistics()
            print(f"\rActive Flows: {stats['active_flows']} | "
                  f"Completed: {stats['total_flows_completed']}", end="")
    except KeyboardInterrupt:
        print("\n\nStopping...")
    finally:
        sentinel.stop()
        final_features = extractor.finalize_all_flows()
        print(f"\nFinalized {len(final_features)} remaining flows.")
        print("Final Statistics:", extractor.get_statistics())
