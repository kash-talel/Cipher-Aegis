"""
Cipher Aegis - Test Data Generator
Populates the database with sample flows and anomalies for testing the dashboard.
"""

import random
from datetime import datetime, timedelta
from db_manager import get_db


def generate_test_data(num_flows: int = 50, anomaly_rate: float = 0.15):
    """
    Generate test data for the dashboard.
    
    Args:
        num_flows: Number of flows to generate.
        anomaly_rate: Percentage of flows that should be anomalies (0-1).
    """
    print("=" * 80)
    print("CIPHER AEGIS - TEST DATA GENERATOR")
    print("=" * 80)
    print()
    print(f"Generating {num_flows} test flows ({int(anomaly_rate*100)}% anomalies)...")
    print()
    
    db = get_db()
    
    # Common IP addresses for variety
    internal_ips = [f"192.168.1.{i}" for i in range(1, 50)]
    external_ips = [
        "93.184.216.34",    # example.com
        "8.8.8.8",          # Google DNS
        "1.1.1.1",          # Cloudflare DNS
        "142.250.185.46",   # Google
        "104.244.42.65",    # Twitter
        "157.240.22.35",    # Facebook
        "13.107.42.14",     # Microsoft
    ]
    
    # Common ports
    ports = {
        "web": [80, 443, 8080, 8443],
        "mail": [25, 110, 143, 587, 993, 995],
        "remote": [22, 3389, 5900],
        "database": [1433, 3306, 5432, 27017],
        "other": [53, 123, 161, 514],
    }
    
    all_ports = [p for category in ports.values() for p in category]
    
    protocols = ["TCP", "UDP", "ICMP"]
    
    flows_created = 0
    anomalies_created = 0
    
    # Generate flows over the last hour
    now = datetime.now()
    
    for i in range(num_flows):
        # Random timestamp within last hour
        timestamp = (now - timedelta(minutes=random.randint(0, 60))).timestamp()
        
        # Random IPs
        src_ip = random.choice(internal_ips)
        dst_ip = random.choice(external_ips + [random.choice(internal_ips)])
        
        # Random ports
        protocol = random.choice(protocols)
        if protocol == "ICMP":
            src_port = random.randint(0, 255)  # ICMP type
            dst_port = random.randint(0, 255)  # ICMP code
        else:
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(all_ports)
        
        # Generate realistic flow metrics
        is_anomaly = random.random() < anomaly_rate
        
        if is_anomaly:
            # Anomalous flows have unusual characteristics
            flow_duration = random.choice([
                random.uniform(0.1, 0.5),      # Very short
                random.uniform(300, 600),      # Very long
            ])
            total_fwd_packets = random.randint(100, 500)  # High volume
            total_bwd_packets = random.randint(50, 250)
            packet_length_mean = random.choice([
                random.uniform(20, 60),        # Very small
                random.uniform(1400, 1500),    # Very large
            ])
        else:
            # Normal flows
            flow_duration = random.uniform(5, 120)
            total_fwd_packets = random.randint(5, 50)
            total_bwd_packets = random.randint(5, 50)
            packet_length_mean = random.uniform(200, 800)
        
        total_packets = total_fwd_packets + total_bwd_packets
        
        # Other statistics
        packet_length_std = random.uniform(50, packet_length_mean * 0.5)
        fwd_packet_length_mean = random.uniform(
            packet_length_mean * 0.8,
            packet_length_mean * 1.2
        )
        fwd_packet_length_std = random.uniform(30, fwd_packet_length_mean * 0.3)
        bwd_packet_length_mean = random.uniform(
            packet_length_mean * 0.7,
            packet_length_mean * 1.3
        )
        bwd_packet_length_std = random.uniform(30, bwd_packet_length_mean * 0.3)
        
        iat_mean = flow_duration / max(total_packets - 1, 1)
        iat_std = iat_mean * random.uniform(0.1, 0.5)
        fwd_iat_mean = iat_mean * random.uniform(0.8, 1.2)
        fwd_iat_std = fwd_iat_mean * random.uniform(0.1, 0.4)
        bwd_iat_mean = iat_mean * random.uniform(0.8, 1.2)
        bwd_iat_std = bwd_iat_mean * random.uniform(0.1, 0.4)
        
        # Anomaly score
        if is_anomaly:
            anomaly_score = random.uniform(0.6, 1.0)
        else:
            anomaly_score = random.uniform(0.0, 0.5)
        
        # Create flow data
        flow = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'flow_duration': flow_duration,
            'total_fwd_packets': total_fwd_packets,
            'total_bwd_packets': total_bwd_packets,
            'total_packets': total_packets,
            'packet_length_mean': packet_length_mean,
            'packet_length_std': packet_length_std,
            'fwd_packet_length_mean': fwd_packet_length_mean,
            'fwd_packet_length_std': fwd_packet_length_std,
            'bwd_packet_length_mean': bwd_packet_length_mean,
            'bwd_packet_length_std': bwd_packet_length_std,
            'iat_mean': iat_mean,
            'iat_std': iat_std,
            'fwd_iat_mean': fwd_iat_mean,
            'fwd_iat_std': fwd_iat_std,
            'bwd_iat_mean': bwd_iat_mean,
            'bwd_iat_std': bwd_iat_std,
            'is_anomaly': 1 if is_anomaly else 0,
            'anomaly_score': anomaly_score,
        }
        
        # Insert flow
        flow_id = db.insert_flow(flow)
        flows_created += 1
        
        # Add anomaly if detected
        if is_anomaly:
            # Determine threat level
            if anomaly_score >= 0.8:
                threat_level = "HIGH"
            elif anomaly_score >= 0.6:
                threat_level = "MEDIUM"
            else:
                threat_level = "LOW"
            
            # Random description
            descriptions = [
                f"Suspicious {protocol} traffic pattern detected",
                f"Unusual packet volume from {src_ip}",
                f"Abnormal flow duration ({flow_duration:.1f}s)",
                f"Potential port scan to {dst_ip}:{dst_port}",
                f"Anomalous packet size distribution",
                f"Irregular inter-arrival times detected",
            ]
            
            db.insert_anomaly({
                'flow_id': flow_id,
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'anomaly_score': anomaly_score,
                'threat_level': threat_level,
                'description': random.choice(descriptions),
            })
            anomalies_created += 1
        
        # Progress indicator
        if (i + 1) % 10 == 0:
            print(f"  Generated {i + 1}/{num_flows} flows...")
    
    # Add system logs
    db.log_event("INFO", f"Test data generation started ({num_flows} flows)")
    db.log_event("INFO", f"Generated {flows_created} flows")
    db.log_event("WARNING", f"Detected {anomalies_created} anomalies")
    db.log_event("INFO", "Test data generation completed successfully")
    
    print()
    print("=" * 80)
    print("GENERATION COMPLETE")
    print("=" * 80)
    print(f"✅ Created {flows_created} flows")
    print(f"🚨 Created {anomalies_created} anomalies ({int(anomalies_created/flows_created*100)}%)")
    print()
    print("You can now run the dashboard:")
    print("  > streamlit run app.py")
    print()
    print("=" * 80)


if __name__ == "__main__":
    import sys
    
    # Parse arguments
    num_flows = 50
    anomaly_rate = 0.15
    
    if len(sys.argv) > 1:
        try:
            num_flows = int(sys.argv[1])
        except ValueError:
            print("Usage: python generate_test_data.py [num_flows] [anomaly_rate]")
            sys.exit(1)
    
    if len(sys.argv) > 2:
        try:
            anomaly_rate = float(sys.argv[2])
            if not 0 <= anomaly_rate <= 1:
                raise ValueError
        except ValueError:
            print("Anomaly rate must be between 0 and 1")
            sys.exit(1)
    
    generate_test_data(num_flows, anomaly_rate)
