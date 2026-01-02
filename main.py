"""
Cipher Aegis - Main Entry Point
Next-Generation Intrusion Detection System
"""

import sys
import time
import logging
from datetime import datetime
from pathlib import Path

from core.sniffer import NetworkSentinel
from core.features import FeatureExtractor
from core.models import PacketInfo, FlowFeatures
from ml.model import AegisBrain
from ml.detector import AnomalyDetector
from db_manager import get_db

# ASCII Art Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║    ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗      █████╗ ███████╗       ║
║   ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝       ║
║   ██║     ██║██████╔╝███████║█████╗  ██████╔╝    ███████║█████╗         ║
║   ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗    ██╔══██║██╔══╝         ║
║   ╚██████╗██║██║     ██║  ██║███████╗██║  ██║    ██║  ██║███████╗       ║
║    ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚══════╝       ║
║                                                                           ║
║              ███╗   ██╗██╗███████╗██████╗ ███████╗██╗   ██╗              ║
║              ████╗  ██║██║██╔════╝██╔══██╗██╔════╝██║   ██║              ║
║              ██╔██╗ ██║██║███████╗██████╔╝█████╗  ██║   ██║              ║
║              ██║╚██╗██║██║╚════██║██╔══██╗██╔══╝  ██║   ██║              ║
║              ██║ ╚████║██║███████║██████╔╝███████╗╚██████╔╝              ║
║              ╚═╝  ╚═══╝╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝               ║
║                                                                           ║
║                   Next-Generation Intrusion Detection                     ║
║                         Powered by Machine Learning                       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/cipher_aegis.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class CipherAegis:
    """
    Main orchestrator for Cipher Aegis IDS.
    Coordinates Sentinel, AegisBrain, and database components.
    """

    def __init__(
        self,
        interface: str = None,
        flow_timeout: float = 60.0,
        training_duration: int = 60,
    ):
        """
        Initialize Cipher Aegis.

        Args:
            interface: Network interface to capture on.
            flow_timeout: Flow timeout in seconds.
            training_duration: Duration for training mode (seconds).
        """
        self.interface = interface
        self.flow_timeout = flow_timeout
        self.training_duration = training_duration

        # Components (initialized in startup)
        self.db = None
        self.brain = None
        self.detector = None
        self.extractor = None
        self.sentinel = None

        # Statistics
        self.flows_processed = 0
        self.anomalies_detected = 0
        self.training_mode = False

    def startup(self) -> None:
        """Initialize all components and check model status."""
        print(BANNER)
        print()
        print("═" * 79)
        print("CIPHER AEGIS - STARTUP SEQUENCE")
        print("═" * 79)
        print()

        # Create logs directory
        Path("logs").mkdir(exist_ok=True)

        # Step 1: Initialize Database
        print("🔧 [1/4] Initializing Database...")
        self.db = get_db()
        self.db.log_event("INFO", "Cipher Aegis startup initiated")
        print("     ✅ Database ready")
        print()

        # Step 2: Check for trained model
        print("🧠 [2/4] Checking ML Model Status...")
        self.brain = AegisBrain()
        
        model_exists = self.brain.load()
        
        if model_exists:
            model_info = self.brain.get_model_info()
            training_date = datetime.fromtimestamp(model_info['training_timestamp'])
            print(f"     ✅ Model found: {model_info['model_path']}")
            print(f"     📅 Trained: {training_date.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"     📊 Samples: {model_info['training_samples']}")
            print()
        else:
            print("     ⚠️  No trained model found")
            print()
            print("=" * 79)
            print("TRAINING MODE REQUIRED")
            print("=" * 79)
            print()
            print("Cipher Aegis needs to learn baseline network behavior.")
            print(f"This will capture traffic for {self.training_duration} seconds.")
            print()
            print("⚠️  IMPORTANT:")
            print("   - Ensure only NORMAL traffic during training")
            print("   - Avoid running attacks or anomalous traffic")
            print("   - Browse normally, make some DNS queries, etc.")
            print()
            
            response = input("Start training mode? (yes/no): ").strip().lower()
            
            if response in ['yes', 'y']:
                self.training_mode = True
                print()
                print("✅ Training mode enabled")
            else:
                print()
                print("❌ Training declined. Exiting...")
                sys.exit(0)
            
            print()

        # Step 3: Initialize Feature Extractor
        print("📊 [3/4] Initializing Feature Extractor...")
        self.extractor = FeatureExtractor(
            flow_timeout=self.flow_timeout,
            cleanup_interval=self.flow_timeout / 2,
        )
        print("     ✅ Feature Extractor ready")
        print()

        # Step 4: Initialize Network Sentinel
        print("📡 [4/4] Initializing Network Sentinel...")
        self.sentinel = NetworkSentinel(
            interface=self.interface,
            packet_callback=self._packet_handler,
            filter_bpf="tcp or udp or icmp",
            packet_count=0,
        )
        print(f"     ✅ Sentinel ready (interface: {self.interface or 'default'})")
        print()

        print("=" * 79)
        if self.training_mode:
            print("🎓 TRAINING MODE ACTIVE")
        else:
            print("🛡️  PROTECTION MODE ACTIVE")
        print("=" * 79)
        print()

    def run(self) -> None:
        """Main execution loop."""
        if self.training_mode:
            self._run_training_mode()
        else:
            self._run_protection_mode()

    def _run_training_mode(self) -> None:
        """Run in training mode to create baseline model."""
        print(f"⏱️  Training for {self.training_duration} seconds...")
        print("   Generate normal network traffic (browse, ping, etc.)")
        print()

        training_features = []
        start_time = time.time()

        # Start capturing
        self.sentinel.start()
        self.db.log_event("INFO", "Training mode started")

        try:
            while time.time() - start_time < self.training_duration:
                elapsed = time.time() - start_time
                remaining = self.training_duration - elapsed
                
                print(f"\r   Training: {elapsed:.0f}s / {self.training_duration}s "
                      f"({len(training_features)} flows captured) ", end="", flush=True)
                
                time.sleep(0.5)

            print("\n")
            
            # Stop capturing
            self.sentinel.stop()
            
            # Finalize remaining flows
            print("🔄 Finalizing flows...")
            remaining_flows = self.extractor.finalize_all_flows()
            training_features.extend(remaining_flows)

            print(f"✅ Captured {len(training_features)} flows")
            print()

            if len(training_features) < 10:
                print("❌ ERROR: Not enough flows for training (need at least 10)")
                print("   Try generating more traffic and run training again.")
                self.db.log_event("ERROR", "Insufficient training data")
                return

            # Train the model
            print("🧠 Training AegisBrain...")
            self.brain.train(training_features)
            
            # Save the model
            print("💾 Saving model...")
            self.brain.save()
            
            print()
            print("=" * 79)
            print("✅ TRAINING COMPLETE")
            print("=" * 79)
            print()
            print(f"Model saved to: {self.brain.model_path}")
            print(f"Training samples: {len(training_features)}")
            print()
            print("You can now run Cipher Aegis in protection mode:")
            print("  python main.py")
            print()

            self.db.log_event("INFO", f"Training completed with {len(training_features)} samples")

        except KeyboardInterrupt:
            print("\n\n⚠️  Training interrupted")
            self.sentinel.stop()
            self.db.log_event("WARNING", "Training interrupted by user")

    def _run_protection_mode(self) -> None:
        """Run in protection mode with active anomaly detection."""
        # Initialize detector
        self.detector = AnomalyDetector(self.brain)
        
        print("🚀 Starting Network Sentinel...")
        self.sentinel.start()
        self.db.log_event("INFO", "Protection mode started")
        
        print()
        print("=" * 79)
        print("Cipher Aegis is now protecting your network!")
        print()
        print("📊 Dashboard: Run 'streamlit run app.py' in another terminal")
        print("⏹️  Stop: Press Ctrl+C")
        print("=" * 79)
        print()

        try:
            # Main monitoring loop
            while self.sentinel.is_running:
                time.sleep(2)
                
                # Display statistics
                sentinel_stats = self.sentinel.get_statistics()
                extractor_stats = self.extractor.get_statistics()
                
                print(f"\r⏱️  Runtime: {time.time():.0f}s | "
                      f"Packets: {sentinel_stats['packets_captured']} "
                      f"(Dropped: {sentinel_stats['packets_dropped']}) | "
                      f"Flows: {self.flows_processed} | "
                      f"Anomalies: {self.anomalies_detected} | "
                      f"Active: {extractor_stats['active_flows']}", 
                      end="", flush=True)

        except KeyboardInterrupt:
            print("\n\n🛑 Shutting down Cipher Aegis...")
            self._shutdown()

    def _packet_handler(self, packet: PacketInfo) -> None:
        """
        Handle each captured packet.

        Args:
            packet: Captured packet information.
        """
        # Extract features
        features = self.extractor.process_packet(packet)
        
        if features:
            if self.training_mode:
                # In training mode, just collect features
                # (stored in extractor, will be finalized at end)
                pass
            else:
                # In protection mode, analyze with ML
                self._analyze_flow(features)

    def _analyze_flow(self, features: FlowFeatures) -> None:
        """
        Analyze a completed flow with ML.

        Args:
            features: Flow features to analyze.
        """
        try:
            # Detect anomaly
            is_anomaly, anomaly_score, threat_level = self.detector.analyze_flow(features)
            
            # Prepare flow data
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
            
            # Insert into database
            flow_id = self.db.insert_flow(flow_data)
            self.flows_processed += 1
            
            # If anomaly, create alert
            if is_anomaly:
                description = self.detector.get_description(features, anomaly_score, threat_level)
                
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
                    'description': description,
                }
                
                self.db.insert_anomaly(anomaly_data)
                self.anomalies_detected += 1
                
                # Log to console and DB
                log_msg = (f"🚨 ANOMALY: {features.flow_key.src_ip} → "
                          f"{features.flow_key.dst_ip} | "
                          f"Score: {anomaly_score:.3f} | {threat_level}")
                logger.warning(log_msg)
                self.db.log_event("WARNING", log_msg, features.timestamp)

        except Exception as e:
            logger.error(f"Error analyzing flow: {e}", exc_info=True)
            self.db.log_event("ERROR", f"Flow analysis error: {str(e)}")

    def _shutdown(self) -> None:
        """Graceful shutdown."""
        if self.sentinel:
            self.sentinel.stop()
        
        if self.extractor and not self.training_mode:
            # Finalize remaining flows in protection mode
            remaining = self.extractor.finalize_all_flows()
            for features in remaining:
                self._analyze_flow(features)
        
        # Log shutdown
        if self.db:
            self.db.log_event("INFO", "Cipher Aegis shutdown complete")
        
        print("\n✅ Cipher Aegis stopped successfully")
        print()


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Cipher Aegis - Next-Generation Intrusion Detection System"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (default: auto-detect)",
        default=None,
    )
    parser.add_argument(
        "-t", "--training-duration",
        help="Duration for training mode in seconds (default: 60)",
        type=int,
        default=60,
    )
    parser.add_argument(
        "-f", "--flow-timeout",
        help="Flow timeout in seconds (default: 60)",
        type=float,
        default=60.0,
    )

    args = parser.parse_args()

    # Create and run Cipher Aegis
    aegis = CipherAegis(
        interface=args.interface,
        flow_timeout=args.flow_timeout,
        training_duration=args.training_duration,
    )

    try:
        aegis.startup()
        aegis.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
