"""
Cipher Aegis - Sentinel Module Test
Demonstrates NetworkSentinel and FeatureExtractor integration.
"""

import time
import sys
from core.sniffer import NetworkSentinel
from core.features import FeatureExtractor
from core.models import PacketInfo


def main():
    """Run the Sentinel Module test."""
    print("=" * 80)
    print("CIPHER AEGIS - SENTINEL MODULE TEST")
    print("=" * 80)
    print()
    print("This test will capture network packets and extract flow-based features.")
    print("Capturing TCP, UDP, and ICMP traffic...")
    print()
    print("⚠️  NOTE: Requires administrator/root privileges for live capture.")
    print("   On Windows: Run PowerShell as Administrator")
    print("   On Linux/Mac: Run with sudo")
    print()
    print("Press Ctrl+C to stop.")
    print("=" * 80)
    print()

    # Initialize feature extractor
    extractor = FeatureExtractor(
        flow_timeout=30.0,  # 30 seconds timeout
        cleanup_interval=15.0,
    )

    feature_count = 0

    def handle_packet(packet: PacketInfo) -> None:
        """Callback for each captured packet."""
        nonlocal feature_count
        
        # Process packet and extract features
        features = extractor.process_packet(packet)
        
        if features:
            feature_count += 1
            print()
            print("🔍 FLOW DETECTED")
            print("-" * 80)
            print(f"Flow #{feature_count}")
            print(f"  Direction: {features.flow_key.src_ip}:{features.flow_key.src_port} → "
                  f"{features.flow_key.dst_ip}:{features.flow_key.dst_port}")
            print(f"  Protocol: {features.protocol.value}")
            print(f"  Duration: {features.flow_duration:.3f} seconds")
            print()
            print("  📊 STATISTICS:")
            print(f"    Forward Packets:  {features.total_fwd_packets}")
            print(f"    Backward Packets: {features.total_bwd_packets}")
            print(f"    Total Packets:    {features.total_packets}")
            print()
            print(f"    Avg Packet Length: {features.packet_length_mean:.2f} ± {features.packet_length_std:.2f} bytes")
            print(f"    Fwd Packet Length: {features.fwd_packet_length_mean:.2f} ± {features.fwd_packet_length_std:.2f} bytes")
            print(f"    Bwd Packet Length: {features.bwd_packet_length_mean:.2f} ± {features.bwd_packet_length_std:.2f} bytes")
            print()
            print(f"    Avg IAT: {features.iat_mean:.6f} ± {features.iat_std:.6f} seconds")
            print(f"    Fwd IAT: {features.fwd_iat_mean:.6f} ± {features.fwd_iat_std:.6f} seconds")
            print(f"    Bwd IAT: {features.bwd_iat_mean:.6f} ± {features.bwd_iat_std:.6f} seconds")
            print("-" * 80)

    # Initialize sentinel
    sentinel = NetworkSentinel(
        interface=None,  # Use default interface
        packet_callback=handle_packet,
        filter_bpf="tcp or udp or icmp",
        packet_count=0,  # Infinite
    )

    try:
        sentinel.start()
        
        # Monitor statistics
        start_time = time.time()
        while sentinel.is_running:
            time.sleep(2)
            
            # Display stats every 2 seconds
            elapsed = time.time() - start_time
            sentinel_stats = sentinel.get_statistics()
            extractor_stats = extractor.get_statistics()
            
            print(f"\r⏱️  Runtime: {elapsed:.0f}s | "
                  f"Packets: {sentinel_stats['packets_captured']} "
                  f"(Dropped: {sentinel_stats['packets_dropped']}) | "
                  f"Active Flows: {extractor_stats['active_flows']} | "
                  f"Completed Flows: {extractor_stats['total_flows_completed']}", 
                  end="", flush=True)

    except KeyboardInterrupt:
        print("\n\n🛑 Stopping Sentinel...")
    
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Graceful shutdown
        sentinel.stop()
        
        # Finalize remaining flows
        print("\n\n🔄 Finalizing remaining flows...")
        remaining_features = extractor.finalize_all_flows()
        print(f"✅ Finalized {len(remaining_features)} flows")
        
        # Final statistics
        print("\n" + "=" * 80)
        print("FINAL STATISTICS")
        print("=" * 80)
        
        sentinel_stats = sentinel.get_statistics()
        extractor_stats = extractor.get_statistics()
        
        print("\n📡 Network Sentinel:")
        print(f"  Packets Captured: {sentinel_stats['packets_captured']}")
        print(f"  Packets Dropped:  {sentinel_stats['packets_dropped']}")
        
        print("\n🔬 Feature Extractor:")
        print(f"  Total Flows Created:   {extractor_stats['total_flows_created']}")
        print(f"  Total Flows Completed: {extractor_stats['total_flows_completed']}")
        print(f"  Active Flows:          {extractor_stats['active_flows']}")
        
        print("\n" + "=" * 80)
        print("Test completed successfully! ✅")
        print("=" * 80)


if __name__ == "__main__":
    main()
