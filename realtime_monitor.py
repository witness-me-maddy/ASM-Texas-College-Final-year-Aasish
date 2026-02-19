"""
Real-time Monitoring System for Attack Surface Management
Monitors network traffic, system logs, and security events in real-time
"""

import asyncio
import time
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Callable, Any
import threading
import queue
import json
import socket
import struct
from scapy.all import sniff, IP, TCP, UDP
import psutil
import os


@dataclass
class NetworkEvent:
    """Represents a network event"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_transferred: int
    alert: bool = False
    alert_reason: str = ""


@dataclass
class SystemEvent:
    """Represents a system event"""
    timestamp: float
    event_type: str
    pid: int
    process_name: str
    details: Dict[str, Any]


@dataclass
class SecurityAlert:
    """Represents a security alert"""
    timestamp: float
    alert_type: str
    severity: str
    description: str
    source: str
    target: str
    confidence: float


class NetworkMonitor:
    """Monitors network traffic in real-time"""
    
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.running = False
        self.alert_callbacks = []
        self.monitor_thread = None
        
        # Known malicious IPs (simplified for demo)
        self.malicious_ips = {
            '192.168.1.100',  # Example malicious IP
            '10.0.0.200'      # Another example
        }
        
        # Suspicious ports
        self.suspicious_ports = {22, 23, 3389, 445, 1433, 3306, 5432}  # SSH, Telnet, RDP, SMB, DB ports
    
    def register_alert_callback(self, callback: Callable[[NetworkEvent], None]):
        """Register a callback for network alerts"""
        self.alert_callbacks.append(callback)
    
    def packet_handler(self, packet):
        """Handle incoming packets"""
        if IP in packet:
            ip_layer = packet[IP]
            
            # Determine protocol
            protocol = "TCP" if TCP in packet else ("UDP" if UDP in packet else "OTHER")
            
            # Get ports if available
            src_port = 0
            dst_port = 0
            if TCP in packet:
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
            elif UDP in packet:
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            
            # Calculate bytes transferred
            bytes_transferred = len(packet)
            
            # Create network event
            event = NetworkEvent(
                timestamp=time.time(),
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                bytes_transferred=bytes_transferred
            )
            
            # Check for suspicious activity
            if self.is_suspicious_traffic(event):
                event.alert = True
                event.alert_reason = self.get_alert_reason(event)
                
                # Trigger callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(event)
                    except Exception as e:
                        print(f"[ERROR] Alert callback failed: {str(e)}")
            
            # Add to queue
            self.packet_queue.put(event)
    
    def is_suspicious_traffic(self, event: NetworkEvent) -> bool:
        """Check if traffic is suspicious"""
        # Check for known malicious IPs
        if event.src_ip in self.malicious_ips or event.dst_ip in self.malicious_ips:
            return True
        
        # Check for suspicious ports
        if event.dst_port in self.suspicious_ports:
            return True
        
        # Check for unusual large data transfers
        if event.bytes_transferred > 100000:  # More than 100KB
            return True
        
        # Check for connection to private IPs from external
        if self.is_private_ip(event.src_ip) and not self.is_private_ip(event.dst_ip):
            # Internal to external is usually OK
            pass
        elif not self.is_private_ip(event.src_ip) and self.is_private_ip(event.dst_ip):
            # External to internal might be suspicious
            if event.dst_port in self.suspicious_ports:
                return True
        
        return False
    
    def get_alert_reason(self, event: NetworkEvent) -> str:
        """Get reason for alert"""
        reasons = []
        
        if event.src_ip in self.malicious_ips or event.dst_ip in self.malicious_ips:
            reasons.append("Known malicious IP")
        
        if event.dst_port in self.suspicious_ports:
            port_services = {
                22: "SSH",
                23: "Telnet", 
                3389: "RDP",
                445: "SMB",
                1433: "MSSQL",
                3306: "MySQL",
                5432: "PostgreSQL"
            }
            service = port_services.get(event.dst_port, f"Port {event.dst_port}")
            reasons.append(f"Connection to suspicious {service} port")
        
        if event.bytes_transferred > 100000:
            reasons.append(f"Large data transfer ({event.bytes_transferred} bytes)")
        
        return "; ".join(reasons) if reasons else "Suspicious activity detected"
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        try:
            ip_obj = socket.inet_aton(ip)
            ip_int = struct.unpack("!I", ip_obj)[0]
            
            # Private IP ranges
            private_ranges = [
                (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0 - 10.255.255.255
                (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0 - 172.31.255.255
                (0xC0A80000, 0xC0A8FFFF)   # 192.168.0.0 - 192.168.255.255
            ]
            
            for start, end in private_ranges:
                if start <= ip_int <= end:
                    return True
            return False
        except:
            return False
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.running:
            return
        
        self.running = True
        
        def monitor_loop():
            sniff(iface=self.interface, prn=self.packet_handler, store=0, stop_filter=lambda x: not self.running)
        
        self.monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self.monitor_thread.start()
        print("[INFO] Network monitoring started")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("[INFO] Network monitoring stopped")


class SystemMonitor:
    """Monitors system processes and resources"""
    
    def __init__(self):
        self.process_history = {}  # pid -> [process_info]
        self.running = False
        self.alert_callbacks = []
        self.monitor_thread = None
    
    def register_alert_callback(self, callback: Callable[[SystemEvent], None]):
        """Register a callback for system alerts"""
        self.alert_callbacks.append(callback)
    
    def is_suspicious_process(self, proc_info: Dict) -> bool:
        """Check if process is suspicious"""
        # Check for suspicious process names
        suspicious_names = [
            'nc', 'netcat', 'ncat', 'socat',  # Network tools
            'plink', 'pscp',  # PuTTY tools
            'psexec', 'wmic',  # Remote execution
            'powershell', 'cmd', 'bash'  # Shells
        ]
        
        proc_name = proc_info['name'].lower()
        if any(susp_name in proc_name for susp_name in suspicious_names):
            # Only alert if connecting to external IPs
            connections = proc_info.get('connections', [])
            for conn in connections:
                if not self.is_private_ip(conn.laddr.ip if conn.laddr else '') or \
                   not self.is_private_ip(conn.raddr.ip if conn.raddr else ''):
                    return True
        
        # Check for high resource usage
        if proc_info.get('cpu_percent', 0) > 80 or proc_info.get('memory_percent', 0) > 80:
            return True
        
        return False
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        if not ip or ':' in ip:  # Skip IPv6 for simplicity
            return False
        
        try:
            ip_obj = socket.inet_aton(ip)
            ip_int = struct.unpack("!I", ip_obj)[0]
            
            # Private IP ranges
            private_ranges = [
                (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0 - 10.255.255.255
                (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0 - 172.31.255.255
                (0xC0A80000, 0xC0A8FFFF)   # 192.168.0.0 - 192.168.255.255
            ]
            
            for start, end in private_ranges:
                if start <= ip_int <= end:
                    return True
            return False
        except:
            return False
    
    def get_process_info(self, proc) -> Dict:
        """Get detailed process information"""
        try:
            return {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe(),
                'cmdline': proc.cmdline(),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'connections': proc.connections(kind='inet'),
                'create_time': proc.create_time(),
                'status': proc.status()
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {}
    
    def monitor_system(self):
        """Monitor system processes"""
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        proc_info = self.get_process_info(proc)
                        if not proc_info:
                            continue
                        
                        # Check if process is suspicious
                        if self.is_suspicious_process(proc_info):
                            event = SystemEvent(
                                timestamp=time.time(),
                                event_type="suspicious_process",
                                pid=proc_info['pid'],
                                process_name=proc_info['name'],
                                details=proc_info
                            )
                            
                            # Trigger callbacks
                            for callback in self.alert_callbacks:
                                try:
                                    callback(event)
                                except Exception as e:
                                    print(f"[ERROR] System alert callback failed: {str(e)}")
                        
                        # Store process info for history
                        pid = proc_info['pid']
                        if pid not in self.process_history:
                            self.process_history[pid] = []
                        self.process_history[pid].append(proc_info)
                        
                        # Keep only last 10 entries per process
                        if len(self.process_history[pid]) > 10:
                            self.process_history[pid] = self.process_history[pid][-10:]
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                # Sleep to avoid excessive CPU usage
                time.sleep(2)
                
            except Exception as e:
                print(f"[ERROR] System monitoring failed: {str(e)}")
                time.sleep(5)
    
    def start_monitoring(self):
        """Start system monitoring"""
        if self.running:
            return
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_system, daemon=True)
        self.monitor_thread.start()
        print("[INFO] System monitoring started")
    
    def stop_monitoring(self):
        """Stop system monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("[INFO] System monitoring stopped")


class RealTimeMonitor:
    """Main real-time monitoring system"""
    
    def __init__(self):
        self.network_monitor = NetworkMonitor()
        self.system_monitor = SystemMonitor()
        self.alerts = []
        self.alert_callbacks = []
        
        # Register internal alert handlers
        self.network_monitor.register_alert_callback(self.handle_network_alert)
        self.system_monitor.register_alert_callback(self.handle_system_alert)
    
    def register_alert_callback(self, callback: Callable[[SecurityAlert], None]):
        """Register a callback for security alerts"""
        self.alert_callbacks.append(callback)
    
    def handle_network_alert(self, event: NetworkEvent):
        """Handle network alert"""
        alert = SecurityAlert(
            timestamp=event.timestamp,
            alert_type="network_threat",
            severity="high" if "malicious" in event.alert_reason.lower() else "medium",
            description=f"Network threat detected: {event.alert_reason}",
            source=event.src_ip,
            target=event.dst_ip,
            confidence=0.8
        )
        
        self.alerts.append(alert)
        self.trigger_alert_callbacks(alert)
    
    def handle_system_alert(self, event: SystemEvent):
        """Handle system alert"""
        alert = SecurityAlert(
            timestamp=event.timestamp,
            alert_type="system_threat",
            severity="high" if "suspicious" in event.event_type else "medium",
            description=f"Suspicious process detected: {event.process_name}",
            source=f"PID:{event.pid}",
            target=event.process_name,
            confidence=0.7
        )
        
        self.alerts.append(alert)
        self.trigger_alert_callbacks(alert)
    
    def trigger_alert_callbacks(self, alert: SecurityAlert):
        """Trigger all registered alert callbacks"""
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"[ERROR] Alert callback failed: {str(e)}")
    
    def start_monitoring(self):
        """Start all monitoring components"""
        print("[INFO] Starting real-time monitoring...")
        self.network_monitor.start_monitoring()
        self.system_monitor.start_monitoring()
    
    def stop_monitoring(self):
        """Stop all monitoring components"""
        print("[INFO] Stopping real-time monitoring...")
        self.network_monitor.stop_monitoring()
        self.system_monitor.stop_monitoring()
    
    def get_recent_alerts(self, minutes: int = 5) -> List[SecurityAlert]:
        """Get recent alerts within specified minutes"""
        current_time = time.time()
        threshold = current_time - (minutes * 60)
        
        recent_alerts = [
            alert for alert in self.alerts 
            if alert.timestamp >= threshold
        ]
        
        return sorted(recent_alerts, key=lambda x: x.timestamp, reverse=True)
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        current_time = time.time()
        hour_ago = current_time - 3600
        
        total_alerts = len(self.alerts)
        recent_alerts = len([a for a in self.alerts if a.timestamp >= hour_ago])
        
        # Count by type
        type_counts = {}
        severity_counts = {}
        
        for alert in self.alerts[-100:]:  # Last 100 alerts
            alert_type = alert.alert_type
            severity = alert.severity
            
            type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_alerts': total_alerts,
            'recent_alerts': recent_alerts,
            'alerts_by_type': type_counts,
            'alerts_by_severity': severity_counts,
            'active_monitors': 2  # network and system
        }


# Example usage and integration with other components
def example_usage():
    """Example of how to use the real-time monitor"""
    
    def alert_handler(alert: SecurityAlert):
        """Example alert handler"""
        print(f"[ALERT] {alert.alert_type.upper()} - {alert.severity.upper()}: {alert.description}")
        print(f"  Time: {datetime.fromtimestamp(alert.timestamp)}")
        print(f"  Source: {alert.source} -> Target: {alert.target}")
        print(f"  Confidence: {alert.confidence}")
        print("-" * 50)
    
    # Create monitor
    monitor = RealTimeMonitor()
    
    # Register alert handler
    monitor.register_alert_callback(alert_handler)
    
    # Start monitoring
    monitor.start_monitoring()
    
    try:
        # Let it run for a while to collect data
        for i in range(10):
            stats = monitor.get_statistics()
            print(f"[STATS] Total alerts: {stats['total_alerts']}, Recent: {stats['recent_alerts']}")
            
            time.sleep(30)
    except KeyboardInterrupt:
        print("\nStopping monitoring...")
    finally:
        monitor.stop_monitoring()


if __name__ == "__main__":
    example_usage()