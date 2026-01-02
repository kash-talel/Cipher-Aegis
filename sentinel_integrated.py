"""
Cipher Aegis - Sentinel Integration
Connects NetworkSentinel and FeatureExtractor to the database.
"""

import time
import logging
from datetime import datetime
from typing import Optional
import random  # For simulated anomaly detection (until ML is ready)

from core.sniffer import NetworkSentinel
from core.features import FeatureExtractor
from core.models import PacketInfo, FlowFeatures
from db_manager import get_db

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SentinelIntegration:
    """
    Integration layer between Sentinel and Database.
    Handles packet capture, feature extraction, and database persistence.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        flow_timeout: float = 60.0,
        enable_ml: bool = False,  # ML not implemented yet
    ):
        """
        Initialize Sentinel Integration.

        Args:
            interface: Network interface to capture on.
            flow_timeout: Flow timeout in seconds.
            enable_ml: Enable ML-based anomaly detection (not implemented yet).
        """
        self.interface = interface
        self.flow_timeout = flow_timeout
        self.enable_ml = enable_ml

        # Initialize components
        self.db = get_db()
        self.extractor = FeatureExtractor(
            flow_timeout=flow_timeout,
            cleanup_interval=flow_timeout / 2,
        )
        self.sentinel: Optional[NetworkSentinel] = None

        # Statistics
        self.flows_processed = 0
        self.anomalies_detected = 0

        logger.info("Sentinel Integration initialized")
        self.db.log_event("INFO", "Sentinel Integration started")

    def _simulate_anomaly_detection(self, features: FlowFeatures) -> tuple[bool, float]:
        """
        Simulate ML anomaly detection (placeholder until ML is implemented).
        
        In production, this would call: model.predict([features.to_vector()])
        
        Args:
            features: Flow features to analyze.
        
        Returns:
            Tuple of (is_anomaly, anomaly_score).
        """
        # Simple heuristic: flag flows with unusual characteristics
        score = 0.0
        
        # High packet count
        if features.total_packets > 100:
            score += 0.3
        
        # Very short or very long duration
        if features.flow_duration < 1.0 or features.flow_duration > 300:
            score += 0.2
        
        # Unusual packet sizes
        if features.packet_length_mean > 1400 or features.packet_length_mean < 50:
            score += 0.2
        
        # High standard deviation (erratic behavior)
        if features.packet_length_std > 500:
            score += 0.15
        
        # Add some randomness to simulate real ML
        score += random.uniform(0, 0.15)
        
        # Threshold for anomaly
        is_anomaly = score > 0.6
        
        return is_anomaly, score

    def _determine_threat_level(self, anomaly_score: float) -> str:
        """
        Determine threat level based on anomaly score.
        
        Args:
            anomaly_score: Anomaly score (0-1).
        
        Returns:
            Threat level string.
        """
        if anomaly_score >= 0.8:
            return "HIGH"
        elif anomaly_score >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"

    def _handle_flow_features(self, features: FlowFeatures) -> None:
        """
        Process completed flow features.
        
        Args:
            features: Completed flow features.
        """
        try:
            # Detect anomalies (simulated for now)
            is_anomaly, anomaly_score = self._simulate_anomaly_detection(features)
            
            # Prepare flow data for database
            flow_data = {
                'timestamp': features.timestamp,
                'src_ip': features.flow_key.src_ip,
                'dst_ip': features.flow_key.dst_ip,
                'src_port': features.flow_key.src_port,
                'dst_port': features.flow_key.dst_port,
                'protocol': features.protocol.value,
                'flow_duration': features.flow_duration,
                'total_fwd_packets': features.total_fwd_packets,
                'total_bwd_packets': features.total_bwd_packets,
                'total_packets': features.total_packets,
                'packet_length_mean': features.packet_length_mean,
                'packet_length_std': features.packet_length_std,
                'fwd_packet_length_mean': features.fwd_packet_length_mean,
                'fwd_packet_length_std': features.fwd_packet_length_std,
                'bwd_packet_length_mean': features.bwd_packet_length_mean,
                'bwd_packet_length_std': features.bwd_packet_length_std,
                'iat_mean': features.iat_mean,
                'iat_std': features.iat_std,
                'fwd_iat_mean': features.fwd_iat_mean,
                'fwd_iat_std': features.fwd_iat_std,
                'bwd_iat_mean': features.bwd_iat_mean,
                'bwd_iat_std': features.bwd_iat_std,
                'is_anomaly': 1 if is_anomaly else 0,
                'anomaly_score': anomaly_score,
            }
            
            # Insert flow into database
            flow_id = self.db.insert_flow(flow_data)
            self.flows_processed += 1
            
            # If anomaly, insert into anomalies table
            if is_anomaly:
                threat_level = self._determine_threat_level(anomaly_score)
                
                anomaly_data = {
                    'flow_id': flow_id,
                    'timestamp': features.timestamp,
                    'src_ip': features.flow_key.src_ip,
                    'dst_ip': features.flow_key.dst_ip,
                    'src_port': features.flow_key.src_port,
                    'dst_port': features.flow_key.dst_port,
                    'protocol': features.protocol.value,
                    'anomaly_score': anomaly_score,
                    'threat_level': threat_level,
                    'description': f"Anomalous {features.protocol.value} traffic detected "
                                 f"({features.total_packets} packets, score: {anomaly_score:.3f})",
                }
                
                self.db.insert_anomaly(anomaly_data)
                self.anomalies_detected += 1
                
                # Log anomaly
                log_msg = (f"🚨 ANOMALY DETECTED: {features.flow_key.src_ip} → "
                          f"{features.flow_key.dst_ip} (Score: {anomaly_score:.3f}, "
                          f"Threat: {threat_level})")
                logger.warning(log_msg)
                self.db.log_event("WARNING", log_msg, features.timestamp)
            
            # Log every 10 flows
            if self.flows_processed % 10 == 0:
                log_msg = f"Processed {self.flows_processed} flows ({self.anomalies_detected} anomalies)"
                logger.info(log_msg)
                self.db.log_event("INFO", log_msg)
        
        except Exception as e:
            logger.error(f"Error handling flow features: {e}", exc_info=True)
            self.db.log_event("ERROR", f"Flow processing error: {str(e)}")

    def _packet_callback(self, packet: PacketInfo) -> None:
        """
        Callback for each captured packet.
        
        Args:
            packet: Captured packet information.
        """
        # Process packet through feature extractor
        features = self.extractor.process_packet(packet)
        
        # If flow completed, handle features
        if features:
            self._handle_flow_features(features)

    def start(self) -> None:
        """Start packet capture and processing."""
        logger.info("Starting Cipher Aegis Sentinel...")
        self.db.log_event("INFO", "Cipher Aegis Sentinel started")
        
        # Initialize sentinel
        self.sentinel = NetworkSentinel(
            interface=self.interface,
            packet_callback=self._packet_callback,
            filter_bpf="tcp or udp or icmp",
            packet_count=0,  # Infinite
            queue_size=10000,
        )
        
        # Start capture
        self.sentinel.start()
        logger.info("Sentinel is now capturing packets...")

    def stop(self) -> None:
        """Stop packet capture and finalize."""
        logger.info("Stopping Cipher Aegis Sentinel...")
        
        if self.sentinel:
            self.sentinel.stop()
        
        # Finalize remaining flows
        remaining_features = self.extractor.finalize_all_flows()
        logger.info(f"Finalizing {len(remaining_features)} remaining flows...")
        
        for features in remaining_features:
            self._handle_flow_features(features)
        
        # Log final statistics
        log_msg = (f"Sentinel stopped. Total flows: {self.flows_processed}, "
                  f"Anomalies: {self.anomalies_detected}")
        logger.info(log_msg)
        self.db.log_event("INFO", log_msg)

    def get_statistics(self) -> dict:
        """Get current statistics."""
        sentinel_stats = self.sentinel.get_statistics() if self.sentinel else {}
        extractor_stats = self.extractor.get_statistics()
        
        return {
            "flows_processed": self.flows_processed,
            "anomalies_detected": self.anomalies_detected,
            "packets_captured": sentinel_stats.get("packets_captured", 0),
            "packets_dropped": sentinel_stats.get("packets_dropped", 0),
            "active_flows": extractor_stats.get("active_flows", 0),
        }


def main():
    """Main entry point for integrated capture."""
    print("=" * 80)
    print("CIPHER AEGIS - INTEGRATED CAPTURE MODE")
    print("=" * 80)
    print()
    print("This mode captures packets and stores them in the database.")
    print("Open the dashboard in another terminal to view real-time data:")
    print("  > streamlit run app.py")
    print()
    print("⚠️  Requires administrator/root privileges")
    print()
    print("Press Ctrl+C to stop.")
    print("=" * 80)
    print()

    integration = SentinelIntegration(
        interface=None,  # Default interface
        flow_timeout=60.0,
    )

    try:
        integration.start()
        
        # Monitor statistics
        while integration.sentinel and integration.sentinel.is_running:
            time.sleep(5)
            stats = integration.get_statistics()
            
            print(f"\r⏱️  Packets: {stats['packets_captured']} "
                  f"(Dropped: {stats['packets_dropped']}) | "
                  f"Active Flows: {stats['active_flows']} | "
                  f"Processed: {stats['flows_processed']} | "
                  f"Anomalies: {stats['anomalies_detected']}", 
                  end="", flush=True)
    
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping Sentinel...")
    
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        integration.stop()
        print("\n✅ Sentinel stopped successfully!")


if __name__ == "__main__":
    main()
