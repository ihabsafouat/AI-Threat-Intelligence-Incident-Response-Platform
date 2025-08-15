#!/usr/bin/env python3
"""
System Performance Monitor
Monitors CPU, memory, disk, and network usage during stress tests.
"""

import psutil
import time
import json
import argparse
import logging
from datetime import datetime
from typing import Dict, List, Any
import threading
import signal
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SystemMonitor:
    """System performance monitor"""
    
    def __init__(self, output_file: str = None, interval: float = 1.0):
        self.output_file = output_file
        self.interval = interval
        self.running = False
        self.metrics = []
        self.start_time = None
        
    def get_cpu_metrics(self) -> Dict[str, Any]:
        """Get CPU metrics"""
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()
        
        return {
            "cpu_percent": cpu_percent,
            "cpu_count": cpu_count,
            "cpu_freq_current": cpu_freq.current if cpu_freq else None,
            "cpu_freq_max": cpu_freq.max if cpu_freq else None,
            "load_average": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
        }
    
    def get_memory_metrics(self) -> Dict[str, Any]:
        """Get memory metrics"""
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            "memory_total": memory.total,
            "memory_available": memory.available,
            "memory_used": memory.used,
            "memory_percent": memory.percent,
            "swap_total": swap.total,
            "swap_used": swap.used,
            "swap_percent": swap.percent
        }
    
    def get_disk_metrics(self) -> Dict[str, Any]:
        """Get disk metrics"""
        disk_usage = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        return {
            "disk_total": disk_usage.total,
            "disk_used": disk_usage.used,
            "disk_free": disk_usage.free,
            "disk_percent": disk_usage.percent,
            "disk_read_bytes": disk_io.read_bytes if disk_io else 0,
            "disk_write_bytes": disk_io.write_bytes if disk_io else 0,
            "disk_read_count": disk_io.read_count if disk_io else 0,
            "disk_write_count": disk_io.write_count if disk_io else 0
        }
    
    def get_network_metrics(self) -> Dict[str, Any]:
        """Get network metrics"""
        network_io = psutil.net_io_counters()
        network_connections = len(psutil.net_connections())
        
        return {
            "network_bytes_sent": network_io.bytes_sent,
            "network_bytes_recv": network_io.bytes_recv,
            "network_packets_sent": network_io.packets_sent,
            "network_packets_recv": network_io.packets_recv,
            "network_connections": network_connections
        }
    
    def get_process_metrics(self) -> Dict[str, Any]:
        """Get process metrics for specific processes"""
        processes = []
        
        # Look for common processes that might be relevant
        target_processes = ['python', 'node', 'java', 'postgres', 'redis', 'nginx']
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                if any(target in proc.info['name'].lower() for target in target_processes):
                    processes.append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "cpu_percent": proc.info['cpu_percent'],
                        "memory_percent": proc.info['memory_percent']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return {"processes": processes}
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect all system metrics"""
        timestamp = datetime.now().isoformat()
        
        metrics = {
            "timestamp": timestamp,
            "cpu": self.get_cpu_metrics(),
            "memory": self.get_memory_metrics(),
            "disk": self.get_disk_metrics(),
            "network": self.get_network_metrics(),
            "processes": self.get_process_metrics()
        }
        
        return metrics
    
    def monitor_loop(self):
        """Main monitoring loop"""
        logger.info(f"Starting system monitoring (interval: {self.interval}s)")
        
        while self.running:
            try:
                metrics = self.collect_metrics()
                self.metrics.append(metrics)
                
                # Log current status
                cpu_percent = metrics['cpu']['cpu_percent']
                memory_percent = metrics['memory']['memory_percent']
                logger.info(f"CPU: {cpu_percent:.1f}%, Memory: {memory_percent:.1f}%")
                
                time.sleep(self.interval)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
                time.sleep(self.interval)
    
    def start(self):
        """Start monitoring"""
        self.running = True
        self.start_time = datetime.now()
        self.monitor_thread = threading.Thread(target=self.monitor_loop)
        self.monitor_thread.start()
        logger.info("System monitoring started")
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join()
        
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds() if self.start_time else 0
        
        logger.info(f"System monitoring stopped (duration: {duration:.1f}s)")
        
        # Save metrics to file
        if self.output_file and self.metrics:
            self.save_metrics()
    
    def save_metrics(self):
        """Save collected metrics to file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump({
                    "monitoring_info": {
                        "start_time": self.start_time.isoformat() if self.start_time else None,
                        "end_time": datetime.now().isoformat(),
                        "duration_seconds": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
                        "interval_seconds": self.interval,
                        "total_samples": len(self.metrics)
                    },
                    "metrics": self.metrics
                }, f, indent=2)
            
            logger.info(f"Metrics saved to {self.output_file}")
            
        except Exception as e:
            logger.error(f"Error saving metrics: {e}")
    
    def generate_summary(self) -> Dict[str, Any]:
        """Generate summary statistics"""
        if not self.metrics:
            return {}
        
        # Extract time series data
        timestamps = [m['timestamp'] for m in self.metrics]
        cpu_percentages = [m['cpu']['cpu_percent'] for m in self.metrics]
        memory_percentages = [m['memory']['memory_percent'] for m in self.metrics]
        
        # Calculate statistics
        def calculate_stats(values):
            if not values:
                return {}
            return {
                "min": min(values),
                "max": max(values),
                "avg": sum(values) / len(values),
                "count": len(values)
            }
        
        return {
            "cpu_stats": calculate_stats(cpu_percentages),
            "memory_stats": calculate_stats(memory_percentages),
            "monitoring_duration": len(self.metrics) * self.interval,
            "total_samples": len(self.metrics)
        }

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    logger.info("Received interrupt signal, stopping monitoring...")
    if hasattr(signal_handler, 'monitor'):
        signal_handler.monitor.stop()
    sys.exit(0)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='System Performance Monitor')
    parser.add_argument('--output', '-o', default='system_metrics.json', 
                       help='Output file for metrics (default: system_metrics.json)')
    parser.add_argument('--interval', '-i', type=float, default=1.0,
                       help='Monitoring interval in seconds (default: 1.0)')
    parser.add_argument('--duration', '-d', type=int,
                       help='Monitoring duration in seconds (optional)')
    parser.add_argument('--summary', '-s', action='store_true',
                       help='Generate summary statistics')
    
    args = parser.parse_args()
    
    # Create monitor
    monitor = SystemMonitor(output_file=args.output, interval=args.interval)
    
    # Set up signal handler
    signal_handler.monitor = monitor
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Start monitoring
        monitor.start()
        
        # Run for specified duration or until interrupted
        if args.duration:
            logger.info(f"Monitoring for {args.duration} seconds...")
            time.sleep(args.duration)
            monitor.stop()
        else:
            logger.info("Monitoring started. Press Ctrl+C to stop.")
            # Keep running until interrupted
            while True:
                time.sleep(1)
                
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    finally:
        monitor.stop()
        
        # Generate summary if requested
        if args.summary:
            summary = monitor.generate_summary()
            print("\n" + "="*50)
            print("SYSTEM MONITORING SUMMARY")
            print("="*50)
            print(f"Monitoring Duration: {summary.get('monitoring_duration', 0):.1f} seconds")
            print(f"Total Samples: {summary.get('total_samples', 0)}")
            
            cpu_stats = summary.get('cpu_stats', {})
            if cpu_stats:
                print(f"\nCPU Usage:")
                print(f"  Average: {cpu_stats.get('avg', 0):.1f}%")
                print(f"  Minimum: {cpu_stats.get('min', 0):.1f}%")
                print(f"  Maximum: {cpu_stats.get('max', 0):.1f}%")
            
            memory_stats = summary.get('memory_stats', {})
            if memory_stats:
                print(f"\nMemory Usage:")
                print(f"  Average: {memory_stats.get('avg', 0):.1f}%")
                print(f"  Minimum: {memory_stats.get('min', 0):.1f}%")
                print(f"  Maximum: {memory_stats.get('max', 0):.1f}%")
            
            print("="*50)

if __name__ == "__main__":
    main() 