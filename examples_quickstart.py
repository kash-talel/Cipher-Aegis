"""
Cipher Aegis - Quick Start Example
Minimal example showing how to use the Sentinel Module.
"""

from core.sniffer import NetworkSentinel
from core.features import FeatureExtractor
from core.models import PacketInfo, FlowFeatures
import time


def simple_example():
    """Simplest possible usage example."""
    print("Starting packet capture for 30 seconds...")
    
    # Create feature extractor
    extractor = FeatureExtractor(flow_timeout=10.0)
    
    # Create packet handler
    def on_packet(packet: PacketInfo):
        features = extractor.process_packet(packet)
        if features:
            print(f"Flow: {features.flow_key.src_ip} -> {features.flow_key.dst_ip} "
                  f"({features.total_packets} packets)")
    
    # Create and start sentinel
    sentinel = NetworkSentinel(packet_callback=on_packet)
    sentinel.start()
    
    # Capture for 30 seconds
    time.sleep(30)
    
    # Stop and cleanup
    sentinel.stop()
    print("\nDone!")


def advanced_example():
    """More advanced usage with custom configuration."""
    print("Advanced Sentinel Configuration Example")
    print("=" * 60)
    
    # Custom feature extractor
    extractor = FeatureExtractor(
        flow_timeout=60.0,      # 1 minute timeout
        cleanup_interval=30.0,  # Cleanup every 30 seconds
    )
    
    flow_count = 0
    
    def on_packet(packet: PacketInfo):
        nonlocal flow_count
        
        # Process packet
        features = extractor.process_packet(packet)
        
        if features:
            flow_count += 1
            
            # Convert to ML vector
            feature_vector = features.to_vector()
            
            print(f"\n[Flow #{flow_count}]")
            print(f"Source: {features.flow_key.src_ip}:{features.flow_key.src_port}")
            print(f"Destination: {features.flow_key.dst_ip}:{features.flow_key.dst_port}")
            print(f"Protocol: {features.protocol.value}")
            print(f"Feature Vector (16 dimensions): {feature_vector[:4]}... (truncated)")
            
            # This is where you would feed to ML model:
            # prediction = model.predict([feature_vector])
            # if prediction == -1:
            #     print("⚠️  ANOMALY DETECTED!")
    
    # Configure sentinel with custom BPF filter
    sentinel = NetworkSentinel(
        interface=None,                    # Default interface
        packet_callback=on_packet,
        filter_bpf="tcp or udp or icmp",  # Capture TCP, UDP, ICMP
        packet_count=0,                    # Infinite
        queue_size=10000,                  # Buffer size
    )
    
    try:
        sentinel.start()
        print("\nCapturing... Press Ctrl+C to stop.\n")
        
        # Monitor statistics
        while sentinel.is_running:
            time.sleep(5)
            stats = sentinel.get_statistics()
            ext_stats = extractor.get_statistics()
            
            print(f"[Stats] Packets: {stats['packets_captured']} | "
                  f"Active Flows: {ext_stats['active_flows']} | "
                  f"Flows Completed: {flow_count}")
    
    except KeyboardInterrupt:
        print("\nStopping...")
    
    finally:
        sentinel.stop()
        remaining = extractor.finalize_all_flows()
        print(f"\nFinalized {len(remaining)} remaining flows.")


def queue_mode_example():
    """Example using queue mode instead of callbacks."""
    print("Queue Mode Example")
    print("=" * 60)
    
    # Create sentinel WITHOUT callback (uses queue)
    sentinel = NetworkSentinel(
        filter_bpf="tcp port 80 or tcp port 443",  # HTTP/HTTPS only
        queue_size=1000,
    )
    
    sentinel.start()
    
    try:
        print("Capturing packets... Press Ctrl+C to stop.\n")
        
        # Pull packets from queue
        while True:
            packet = sentinel.get_packet(block=True, timeout=1.0)
            if packet:
                print(f"[{packet.protocol.value}] {packet.src_ip}:{packet.src_port} -> "
                      f"{packet.dst_ip}:{packet.dst_port} ({packet.length} bytes)")
    
    except KeyboardInterrupt:
        print("\nStopping...")
    
    finally:
        sentinel.stop()


if __name__ == "__main__":
    import sys
    
    print("Cipher Aegis - Quick Start Examples")
    print("=" * 60)
    print()
    print("Choose an example:")
    print("  1. Simple Example (basic usage)")
    print("  2. Advanced Example (custom config + ML-ready)")
    print("  3. Queue Mode Example (pull-based packet retrieval)")
    print()
    
    choice = input("Enter choice (1-3): ").strip()
    print()
    
    if choice == "1":
        simple_example()
    elif choice == "2":
        advanced_example()
    elif choice == "3":
        queue_mode_example()
    else:
        print("Invalid choice. Running simple example...")
        simple_example()
