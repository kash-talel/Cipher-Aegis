"""
Cipher Aegis - Network Sentinel
Threaded packet capture engine using Scapy.
"""

import threading
import logging
from typing import Callable, Optional
from queue import Queue
import time

try:
    from scapy.all import sniff, Packet, IP, TCP, UDP, ICMP
    from scapy.layers.inet import IP as IPLayer
except ImportError:
    raise ImportError(
        "Scapy is required. Install with: pip install scapy"
    )

from .models import PacketInfo, Protocol

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class NetworkSentinel:
    """
    High-performance packet sniffer running on a separate thread.
    Captures TCP, UDP, and ICMP packets and converts them to PacketInfo objects.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        packet_callback: Optional[Callable[[PacketInfo], None]] = None,
        filter_bpf: str = "tcp or udp or icmp",
        packet_count: int = 0,  # 0 = infinite
        queue_size: int = 10000,
    ):
        """
        Initialize the Network Sentinel.

        Args:
            interface: Network interface to sniff on (e.g., "eth0", "wlan0").
                      None uses default interface.
            packet_callback: Callback function to process each PacketInfo.
                            If None, packets are queued.
            filter_bpf: BPF filter string for packet capture.
            packet_count: Number of packets to capture (0 = infinite).
            queue_size: Maximum queue size for buffering packets.
        """
        self.interface = interface
        self.packet_callback = packet_callback
        self.filter_bpf = filter_bpf
        self.packet_count = packet_count
        self.queue_size = queue_size

        # Thread control
        self._sniff_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._is_running = False

        # Packet queue (if no callback is provided)
        self.packet_queue: Queue[PacketInfo] = Queue(maxsize=queue_size)

        # Statistics
        self._packets_captured = 0
        self._packets_dropped = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start packet capture in a separate thread."""
        if self._is_running:
            logger.warning("Sentinel is already running.")
            return

        logger.info(f"Starting Network Sentinel on interface: {self.interface or 'default'}")
        logger.info(f"BPF Filter: {self.filter_bpf}")

        self._stop_event.clear()
        self._is_running = True

        self._sniff_thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True,
            name="NetworkSentinel-SniffThread"
        )
        self._sniff_thread.start()
        logger.info("Network Sentinel started successfully.")

    def stop(self, timeout: float = 5.0) -> None:
        """
        Stop packet capture gracefully.

        Args:
            timeout: Maximum time to wait for thread termination (seconds).
        """
        if not self._is_running:
            logger.warning("Sentinel is not running.")
            return

        logger.info("Stopping Network Sentinel...")
        self._stop_event.set()
        self._is_running = False

        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=timeout)
            if self._sniff_thread.is_alive():
                logger.warning("Sniff thread did not terminate gracefully.")
            else:
                logger.info("Sniff thread terminated successfully.")

        self._log_statistics()

    def _sniff_loop(self) -> None:
        """Main sniffing loop (runs in separate thread)."""
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_bpf,
                prn=self._packet_handler,
                store=False,  # Don't store packets in memory
                count=self.packet_count,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            logger.error(
                "Permission denied. Run with administrator/root privileges "
                "or use simulation mode."
            )
        except Exception as e:
            logger.error(f"Sniffing error: {e}", exc_info=True)
        finally:
            self._is_running = False
            logger.info("Sniff loop terminated.")

    def _packet_handler(self, packet: Packet) -> None:
        """
        Process a single captured packet.

        Args:
            packet: Raw Scapy packet object.
        """
        try:
            packet_info = self._parse_packet(packet)
            if packet_info:
                with self._lock:
                    self._packets_captured += 1

                # Use callback if provided, otherwise queue
                if self.packet_callback:
                    self.packet_callback(packet_info)
                else:
                    try:
                        self.packet_queue.put_nowait(packet_info)
                    except Exception:
                        # Queue is full, drop packet
                        with self._lock:
                            self._packets_dropped += 1

        except Exception as e:
            logger.debug(f"Error parsing packet: {e}")

    def _parse_packet(self, packet: Packet) -> Optional[PacketInfo]:
        """
        Extract PacketInfo from a Scapy packet.

        Args:
            packet: Raw Scapy packet.

        Returns:
            PacketInfo object or None if packet cannot be parsed.
        """
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        timestamp = float(packet.time)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = len(packet)

        # Default values
        src_port = 0
        dst_port = 0
        protocol = Protocol.OTHER
        flags = None
        payload_size = 0

        # Parse TCP
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol = Protocol.TCP
            flags = self._get_tcp_flags(tcp_layer)
            payload_size = len(tcp_layer.payload) if tcp_layer.payload else 0

        # Parse UDP
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol = Protocol.UDP
            payload_size = len(udp_layer.payload) if udp_layer.payload else 0

        # Parse ICMP
        elif packet.haslayer(ICMP):
            protocol = Protocol.ICMP
            icmp_layer = packet[ICMP]
            # ICMP doesn't have ports, use type/code instead
            src_port = icmp_layer.type if hasattr(icmp_layer, 'type') else 0
            dst_port = icmp_layer.code if hasattr(icmp_layer, 'code') else 0
            payload_size = len(icmp_layer.payload) if icmp_layer.payload else 0

        return PacketInfo(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=length,
            flags=flags,
            payload_size=payload_size,
        )

    @staticmethod
    def _get_tcp_flags(tcp_layer) -> str:
        """Extract TCP flags as a string."""
        flags = []
        if tcp_layer.flags.F: flags.append("FIN")
        if tcp_layer.flags.S: flags.append("SYN")
        if tcp_layer.flags.R: flags.append("RST")
        if tcp_layer.flags.P: flags.append("PSH")
        if tcp_layer.flags.A: flags.append("ACK")
        if tcp_layer.flags.U: flags.append("URG")
        if tcp_layer.flags.E: flags.append("ECE")
        if tcp_layer.flags.C: flags.append("CWR")
        return "|".join(flags) if flags else "NONE"

    def get_packet(self, block: bool = True, timeout: Optional[float] = None) -> Optional[PacketInfo]:
        """
        Retrieve a packet from the queue (if not using callback mode).

        Args:
            block: Whether to block until a packet is available.
            timeout: Maximum time to wait (seconds).

        Returns:
            PacketInfo or None if queue is empty or timeout.
        """
        try:
            return self.packet_queue.get(block=block, timeout=timeout)
        except Exception:
            return None

    def get_statistics(self) -> dict[str, int]:
        """Get capture statistics."""
        with self._lock:
            return {
                "packets_captured": self._packets_captured,
                "packets_dropped": self._packets_dropped,
                "queue_size": self.packet_queue.qsize(),
            }

    def _log_statistics(self) -> None:
        """Log final capture statistics."""
        stats = self.get_statistics()
        logger.info("=" * 60)
        logger.info("Network Sentinel Statistics:")
        logger.info(f"  Packets Captured: {stats['packets_captured']}")
        logger.info(f"  Packets Dropped:  {stats['packets_dropped']}")
        logger.info(f"  Queue Size:       {stats['queue_size']}")
        logger.info("=" * 60)

    @property
    def is_running(self) -> bool:
        """Check if the sentinel is currently running."""
        return self._is_running


# Example usage
if __name__ == "__main__":
    def print_packet(pkt: PacketInfo) -> None:
        print(f"[{pkt.protocol.value}] {pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port} ({pkt.length} bytes)")

    sentinel = NetworkSentinel(packet_callback=print_packet)
    
    try:
        sentinel.start()
        print("Capturing packets... Press Ctrl+C to stop.")
        while sentinel.is_running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        sentinel.stop()
