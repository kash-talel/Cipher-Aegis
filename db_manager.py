"""
Cipher Aegis - Database Manager
SQLite persistence layer for flows, anomalies, and system logs.
"""

import sqlite3
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
from pathlib import Path
from contextlib import contextmanager
from threading import Lock

logger = logging.getLogger(__name__)


class DatabaseManager:
    """
    Thread-safe SQLite database manager for Cipher Aegis.
    Handles flows, anomalies, and system logs.
    """

    def __init__(self, db_path: str = "data/events.db"):
        """
        Initialize database manager.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._lock = Lock()
        self._init_database()
        logger.info(f"Database initialized at: {self.db_path}")

    @contextmanager
    def _get_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        try:
            yield conn
        finally:
            conn.close()

    def _init_database(self) -> None:
        """Create database tables if they don't exist."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()

            # Flows table (all captured flows)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    
                    -- Flow metrics
                    flow_duration REAL,
                    total_fwd_packets INTEGER,
                    total_bwd_packets INTEGER,
                    total_packets INTEGER,
                    
                    -- Packet length stats
                    packet_length_mean REAL,
                    packet_length_std REAL,
                    fwd_packet_length_mean REAL,
                    fwd_packet_length_std REAL,
                    bwd_packet_length_mean REAL,
                    bwd_packet_length_std REAL,
                    
                    -- IAT stats
                    iat_mean REAL,
                    iat_std REAL,
                    fwd_iat_mean REAL,
                    fwd_iat_std REAL,
                    bwd_iat_mean REAL,
                    bwd_iat_std REAL,
                    
                    -- ML prediction
                    is_anomaly INTEGER DEFAULT 0,
                    anomaly_score REAL DEFAULT 0.0,
                    
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Anomalies table (red alerts only)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    flow_id INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    
                    anomaly_score REAL NOT NULL,
                    threat_level TEXT NOT NULL,  -- LOW, MEDIUM, HIGH
                    
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    
                    FOREIGN KEY (flow_id) REFERENCES flows (id)
                )
            """)

            # System logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    level TEXT NOT NULL,  -- INFO, WARNING, ERROR
                    message TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Statistics table (aggregated metrics)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    timestamp REAL NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_flows_timestamp 
                ON flows(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_flows_anomaly 
                ON flows(is_anomaly, timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp 
                ON anomalies(timestamp DESC)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_logs_timestamp 
                ON system_logs(timestamp DESC)
            """)

            conn.commit()
            logger.info("Database schema initialized successfully")

    def insert_flow(self, flow_features: Dict[str, Any]) -> int:
        """
        Insert a flow into the database.

        Args:
            flow_features: Dictionary containing flow features.

        Returns:
            ID of inserted flow.
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO flows (
                    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                    flow_duration, total_fwd_packets, total_bwd_packets, total_packets,
                    packet_length_mean, packet_length_std,
                    fwd_packet_length_mean, fwd_packet_length_std,
                    bwd_packet_length_mean, bwd_packet_length_std,
                    iat_mean, iat_std,
                    fwd_iat_mean, fwd_iat_std,
                    bwd_iat_mean, bwd_iat_std,
                    is_anomaly, anomaly_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                flow_features.get('timestamp'),
                flow_features.get('src_ip'),
                flow_features.get('dst_ip'),
                flow_features.get('src_port'),
                flow_features.get('dst_port'),
                flow_features.get('protocol'),
                flow_features.get('flow_duration'),
                flow_features.get('total_fwd_packets'),
                flow_features.get('total_bwd_packets'),
                flow_features.get('total_packets'),
                flow_features.get('packet_length_mean'),
                flow_features.get('packet_length_std'),
                flow_features.get('fwd_packet_length_mean'),
                flow_features.get('fwd_packet_length_std'),
                flow_features.get('bwd_packet_length_mean'),
                flow_features.get('bwd_packet_length_std'),
                flow_features.get('iat_mean'),
                flow_features.get('iat_std'),
                flow_features.get('fwd_iat_mean'),
                flow_features.get('fwd_iat_std'),
                flow_features.get('bwd_iat_mean'),
                flow_features.get('bwd_iat_std'),
                flow_features.get('is_anomaly', 0),
                flow_features.get('anomaly_score', 0.0),
            ))
            
            conn.commit()
            return cursor.lastrowid

    def insert_anomaly(self, anomaly_data: Dict[str, Any]) -> int:
        """
        Insert an anomaly (red alert) into the database.

        Args:
            anomaly_data: Dictionary containing anomaly information.

        Returns:
            ID of inserted anomaly.
        """
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO anomalies (
                    flow_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                    protocol, anomaly_score, threat_level, description
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                anomaly_data.get('flow_id'),
                anomaly_data.get('timestamp'),
                anomaly_data.get('src_ip'),
                anomaly_data.get('dst_ip'),
                anomaly_data.get('src_port'),
                anomaly_data.get('dst_port'),
                anomaly_data.get('protocol'),
                anomaly_data.get('anomaly_score'),
                anomaly_data.get('threat_level', 'MEDIUM'),
                anomaly_data.get('description', 'Anomalous network behavior detected'),
            ))
            
            conn.commit()
            return cursor.lastrowid

    def log_event(self, level: str, message: str, timestamp: Optional[float] = None) -> None:
        """
        Log a system event.

        Args:
            level: Log level (INFO, WARNING, ERROR).
            message: Log message.
            timestamp: Event timestamp (defaults to current time).
        """
        if timestamp is None:
            timestamp = datetime.now().timestamp()

        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO system_logs (timestamp, level, message)
                VALUES (?, ?, ?)
            """, (timestamp, level, message))
            conn.commit()

    def get_recent_flows(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent flows."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM flows
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent anomalies (red alerts)."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM anomalies
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_system_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent system logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM system_logs
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregated statistics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total packets (sum of all flow packets)
            cursor.execute("SELECT COALESCE(SUM(total_packets), 0) FROM flows")
            total_packets = cursor.fetchone()[0]
            
            # Total flows
            cursor.execute("SELECT COUNT(*) FROM flows")
            total_flows = cursor.fetchone()[0]
            
            # Anomalies count
            cursor.execute("SELECT COUNT(*) FROM anomalies")
            total_anomalies = cursor.fetchone()[0]
            
            # Threat level distribution
            cursor.execute("""
                SELECT threat_level, COUNT(*) 
                FROM anomalies 
                GROUP BY threat_level
            """)
            threat_levels = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Current threat level (based on recent anomalies)
            cursor.execute("""
                SELECT threat_level 
                FROM anomalies 
                ORDER BY timestamp DESC 
                LIMIT 1
            """)
            result = cursor.fetchone()
            current_threat = result[0] if result else "LOW"
            
            return {
                "total_packets": total_packets,
                "total_flows": total_flows,
                "total_anomalies": total_anomalies,
                "threat_levels": threat_levels,
                "current_threat_level": current_threat,
            }

    def get_traffic_timeline(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get traffic volume and anomaly scores over time.
        
        Returns:
            List of dictionaries with timestamp, traffic_volume, anomaly_score.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT 
                    timestamp,
                    total_packets as traffic_volume,
                    anomaly_score,
                    is_anomaly
                FROM flows
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]

    def clear_old_data(self, days: int = 7) -> None:
        """
        Clear data older than specified days.
        
        Args:
            days: Number of days to retain.
        """
        cutoff_timestamp = (datetime.now().timestamp() - (days * 24 * 60 * 60))
        
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM flows WHERE timestamp < ?", (cutoff_timestamp,))
            flows_deleted = cursor.rowcount
            
            cursor.execute("DELETE FROM anomalies WHERE timestamp < ?", (cutoff_timestamp,))
            anomalies_deleted = cursor.rowcount
            
            cursor.execute("DELETE FROM system_logs WHERE timestamp < ?", (cutoff_timestamp,))
            logs_deleted = cursor.rowcount
            
            conn.commit()
            
            logger.info(f"Cleanup: Deleted {flows_deleted} flows, {anomalies_deleted} anomalies, {logs_deleted} logs")

    def get_database_size(self) -> int:
        """Get database file size in bytes."""
        return self.db_path.stat().st_size if self.db_path.exists() else 0


# Singleton instance
_db_instance: Optional[DatabaseManager] = None
_db_lock = Lock()


def get_db() -> DatabaseManager:
    """Get or create singleton database instance."""
    global _db_instance
    
    if _db_instance is None:
        with _db_lock:
            if _db_instance is None:
                _db_instance = DatabaseManager()
    
    return _db_instance


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    db = get_db()
    
    # Test insert flow
    flow = {
        'timestamp': datetime.now().timestamp(),
        'src_ip': '192.168.1.100',
        'dst_ip': '93.184.216.34',
        'src_port': 54321,
        'dst_port': 443,
        'protocol': 'TCP',
        'flow_duration': 30.5,
        'total_fwd_packets': 15,
        'total_bwd_packets': 12,
        'total_packets': 27,
        'packet_length_mean': 645.33,
        'packet_length_std': 234.12,
        'fwd_packet_length_mean': 523.20,
        'fwd_packet_length_std': 189.45,
        'bwd_packet_length_mean': 789.67,
        'bwd_packet_length_std': 298.76,
        'iat_mean': 0.001243,
        'iat_std': 0.000567,
        'fwd_iat_mean': 0.001456,
        'fwd_iat_std': 0.000678,
        'bwd_iat_mean': 0.001012,
        'bwd_iat_std': 0.000423,
        'is_anomaly': 0,
        'anomaly_score': 0.05,
    }
    
    flow_id = db.insert_flow(flow)
    print(f"Inserted flow with ID: {flow_id}")
    
    # Test log
    db.log_event("INFO", "Database test completed successfully")
    
    # Get statistics
    stats = db.get_statistics()
    print("\nStatistics:", stats)
