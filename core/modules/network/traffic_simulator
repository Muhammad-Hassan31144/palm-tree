# shikra/core/modules/network/traffic_simulator.py
# Purpose: Simulates realistic network traffic to blend malware analysis activities

import os
import time
import random
import threading
import logging
import json
import urllib.request
import urllib.parse
import socket
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import queue

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    requests = None

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None

logger = logging.getLogger(__name__)

class TrafficSimulator:
    """
    Network traffic simulator that generates realistic background traffic
    to blend malware analysis activities and evade network-based detection.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize traffic simulator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.is_running = False
        self.simulator_threads = []
        
        # Traffic patterns configuration
        self.traffic_patterns = self._load_traffic_patterns()
        
        # Statistics tracking
        self.stats = {
            "start_time": None,
            "requests_sent": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections_made": 0,
            "errors": 0,
            "patterns_executed": defaultdict(int)
        }
        
        # Request queue for coordinated traffic
        self.request_queue = queue.Queue()
        
        logger.info("Traffic simulator initialized")
    
    def _load_traffic_patterns(self) -> Dict:
        """Load traffic simulation patterns."""
        patterns_file = self.config.get('patterns_file', 'config/network/traffic_patterns.json')
        
        try:
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    patterns = json.load(f)
                logger.info(f"Loaded traffic patterns from {patterns_file}")
                return patterns
        except Exception as e:
            logger.error(f"Failed to load traffic patterns: {e}")
        
        return self._get_default_patterns()
    
    def _get_default_patterns(self) -> Dict:
        """Default traffic simulation patterns."""
        return {
            "web_browsing": {
                "enabled": True,
                "weight": 40,  # Relative frequency
                "sites": [
                    "https://www.google.com",
                    "https://www.microsoft.com", 
                    "https://www.github.com",
                    "https://stackoverflow.com",
                    "https://news.ycombinator.com",
                    "https://www.reddit.com",
                    "https://en.wikipedia.org",
                    "https://www.youtube.com"
                ],
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                ],
                "interval_range": [5, 30],  # seconds between requests
                "follow_links": True,
                "max_redirects": 3
            },
            
            "social_media": {
                "enabled": True,
                "weight": 20,
                "sites": [
                    "https://www.facebook.com",
                    "https://www.twitter.com", 
                    "https://www.instagram.com",
                    "https://www.linkedin.com"
                ],
                "interval_range": [10, 60],
                "simulate_scrolling": True
            },
            
            "software_updates": {
                "enabled": True,
                "weight": 15,
                "sites": [
                    "https://update.microsoft.com",
                    "https://download.windowsupdate.com",
                    "https://www.google.com/chrome/update"
                ],
                "interval_range": [300, 3600],  # Less frequent
                "large_downloads": True
            },
            
            "dns_queries": {
                "enabled": True,
                "weight": 25,
                "domains": [
                    "google.com", "microsoft.com", "cloudflare.com",
                    "amazon.com", "facebook.com", "twitter.com",
                    "github.com", "stackoverflow.com", "wikipedia.org"
                ],
                "query_types": ["A", "AAAA", "MX", "TXT"],
                "interval_range": [1, 10]
            },
            
            "email_simulation": {
                "enabled": False,  # Disabled by default
                "weight": 10,
                "servers": [
                    "outlook.office365.com:993",
                    "imap.gmail.com:993"
                ],
                "interval_range": [120, 600]
            },
            
            "background_services": {
                "enabled": True,
                "weight": 30,
                "services": [
                    {"host": "time.windows.com", "port": 123, "protocol": "UDP"},  # NTP
                    {"host": "dns.google", "port": 53, "protocol": "UDP"},  # DNS
                    {"host": "1.1.1.1", "port": 53, "protocol": "UDP"}  # Cloudflare DNS
                ],
                "interval_range": [60, 300]
            }
        }
    
    def start_simulation(self, duration: int = None, intensity: str = "medium") -> bool:
        """
        Start traffic simulation.
        
        Args:
            duration: Simulation duration in seconds (None for indefinite)
            intensity: Traffic intensity ("low", "medium", "high")
            
        Returns:
            True if simulation started successfully
        """
        if self.is_running:
            logger.warning("Traffic simulation is already running")
            return True
        
        # Configure intensity
        intensity_multipliers = {
            "low": 0.5,
            "medium": 1.0,
            "high": 2.0
        }
        
        multiplier = intensity_multipliers.get(intensity, 1.0)
        
        try:
            self.is_running = True
            self.stats["start_time"] = datetime.now()
            
            # Start pattern threads
            for pattern_name, pattern_config in self.traffic_patterns.items():
                if not pattern_config.get("enabled", False):
                    continue
                
                # Adjust interval based on intensity
                interval_range = pattern_config.get("interval_range", [30, 120])
                adjusted_range = [int(i / multiplier) for i in interval_range]
                pattern_config["adjusted_interval_range"] = adjusted_range
                
                # Start thread for this pattern
                thread = threading.Thread(
                    target=self._pattern_worker,
                    args=(pattern_name, pattern_config, duration),
                    name=f"TrafficSim-{pattern_name}",
                    daemon=True
                )
                thread.start()
                self.simulator_threads.append(thread)
            
            logger.info(f"Started traffic simulation with {len(self.simulator_threads)} patterns at {intensity} intensity")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start traffic simulation: {e}")
            self.is_running = False
            return False
    
    def stop_simulation(self) -> Dict:
        """
        Stop traffic simulation and return statistics.
        
        Returns:
            Simulation statistics dictionary
        """
        if not self.is_running:
            logger.warning("Traffic simulation is not running")
            return self.get_statistics()
        
        self.is_running = False
        
        # Wait for threads to finish (with timeout)
        for thread in self.simulator_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        # Clear thread list
        self.simulator_threads.clear()
        
        # Calculate final statistics
        if self.stats["start_time"]:
            self.stats["total_duration"] = (datetime.now() - self.stats["start_time"]).total_seconds()
        
        logger.info("Traffic simulation stopped")
        return self.get_statistics()
    
    def _pattern_worker(self, pattern_name: str, pattern_config: Dict, duration: int = None):
        """Worker thread for executing a specific traffic pattern."""
        logger.info(f"Started traffic pattern worker: {pattern_name}")
        
        start_time = time.time()
        interval_range = pattern_config.get("adjusted_interval_range", [30, 120])
        
        while self.is_running:
            # Check duration limit
            if duration and (time.time() - start_time) >= duration:
                break
            
            try:
                # Execute pattern
                if pattern_name == "web_browsing":
                    self._simulate_web_browsing(pattern_config)
                elif pattern_name == "social_media":
                    self._simulate_social_media(pattern_config)
                elif pattern_name == "software_updates":
                    self._simulate_software_updates(pattern_config)
                elif pattern_name == "dns_queries":
                    self._simulate_dns_queries(pattern_config)
                elif pattern_name == "email_simulation":
                    self._simulate_email_traffic(pattern_config)
                elif pattern_name == "background_services":
                    self._simulate_background_services(pattern_config)
                
                self.stats["patterns_executed"][pattern_name] += 1
                
            except Exception as e:
                logger.debug(f"Error in pattern {pattern_name}: {e}")
                self.stats["errors"] += 1
            
            # Wait before next execution
            if self.is_running:
                wait_time = random.uniform(interval_range[0], interval_range[1])
                time.sleep(wait_time)
        
        logger.info(f"Traffic pattern worker stopped: {pattern_name}")
    
    def _simulate_web_browsing(self, config: Dict):
        """Simulate web browsing traffic."""
        if not REQUESTS_AVAILABLE:
            return self._simulate_web_browsing_basic(config)
        
        sites = config.get("sites", [])
        user_agents = config.get("user_agents", [])
        
        if not sites:
            return
        
        # Select random site and user agent
        url = random.choice(sites)
        user_agent = random.choice(user_agents) if user_agents else None
        
        headers = {}
        if user_agent:
            headers['User-Agent'] = user_agent
        
        # Add common browser headers
        headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        try:
            response = requests.get(
                url,
                headers=headers,
                timeout=10,
                allow_redirects=config.get("max_redirects", 3) > 0,
                verify=False  # For simulation purposes
            )
            
            self.stats["requests_sent"] += 1
            self.stats["bytes_received"] += len(response.content)
            self.stats["connections_made"] += 1
            
            # Simulate following links occasionally
            if config.get("follow_links", False) and random.random() < 0.3:
                self._follow_random_link(response.text, url, headers)
            
        except Exception as e:
            logger.debug(f"Web browsing simulation error: {e}")
            self.stats["errors"] += 1
    
    def _simulate_web_browsing_basic(self, config: Dict):
        """Basic web browsing simulation without requests library."""
        sites = config.get("sites", [])
        if not sites:
            return
        
        url = random.choice(sites)
        
        try:
            # Parse URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            # Create basic HTTP request
            request = urllib.request.Request(url)
            request.add_header('User-Agent', random.choice(config.get("user_agents", ["Shikra-Simulator/1.0"])))
            
            with urllib.request.urlopen(request, timeout=10) as response:
                data = response.read()
                self.stats["requests_sent"] += 1
                self.stats["bytes_received"] += len(data)
                self.stats["connections_made"] += 1
                
        except Exception as e:
            logger.debug(f"Basic web browsing error: {e}")
            self.stats["errors"] += 1
    
    def _follow_random_link(self, html_content: str, base_url: str, headers: Dict):
        """Extract and follow a random link from HTML content."""
        try:
            import re
            from urllib.parse import urljoin, urlparse
            
            # Simple link extraction (not as robust as BeautifulSoup)
            link_pattern = r'href=[\'"]([^\'"]+)[\'"]'
            links = re.findall(link_pattern, html_content)
            
            if not links:
                return
            
            # Filter for reasonable links
            filtered_links = []
            for link in links:
                if link.startswith(('http://', 'https://')):
                    filtered_links.append(link)
                elif link.startswith('/'):
                    filtered_links.append(urljoin(base_url, link))
            
            if filtered_links:
                link_url = random.choice(filtered_links)
                
                # Don't follow too many redirects
                if REQUESTS_AVAILABLE:
                    response = requests.get(link_url, headers=headers, timeout=5, verify=False)
                    self.stats["requests_sent"] += 1
                    self.stats["bytes_received"] += len(response.content)
                
        except Exception as e:
            logger.debug(f"Link following error: {e}")
    
    def _simulate_social_media(self, config: Dict):
        """Simulate social media traffic patterns."""
        sites = config.get("sites", [])
        if not sites:
            return
        
        url = random.choice(sites)
        
        # Social media requests often have specific patterns
        endpoints = ["/", "/feed", "/notifications", "/messages", "/profile"]
        endpoint = random.choice(endpoints)
        
        full_url = url.rstrip('/') + endpoint
        
        try:
            if REQUESTS_AVAILABLE:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json, text/javascript, */*; q=0.01',
                    'X-Requested-With': 'XMLHttpRequest'  # AJAX request
                }
                
                response = requests.get(full_url, headers=headers, timeout=10, verify=False)
                self.stats["requests_sent"] += 1
                self.stats["bytes_received"] += len(response.content)
                self.stats["connections_made"] += 1
                
                # Simulate scrolling behavior (multiple requests)
                if config.get("simulate_scrolling", False) and random.random() < 0.4:
                    for _ in range(random.randint(1, 3)):
                        time.sleep(random.uniform(0.5, 2.0))
                        # Additional AJAX requests for content loading
                        ajax_response = requests.get(full_url + "?scroll=true", headers=headers, timeout=5, verify=False)
                        self.stats["requests_sent"] += 1
                        self.stats["bytes_received"] += len(ajax_response.content)
                
        except Exception as e:
            logger.debug(f"Social media simulation error: {e}")
            self.stats["errors"] += 1
    
    def _simulate_software_updates(self, config: Dict):
        """Simulate software update checks and downloads."""
        sites = config.get("sites", [])
        if not sites:
            return
        
        url = random.choice(sites)
        
        try:
            if REQUESTS_AVAILABLE:
                headers = {
                    'User-Agent': 'Microsoft-Delivery-Optimization/10.0',
                    'Accept': '*/*'
                }
                
                response = requests.get(url, headers=headers, timeout=15, verify=False)
                self.stats["requests_sent"] += 1
                self.stats["bytes_received"] += len(response.content)
                self.stats["connections_made"] += 1
                
                # Simulate large download occasionally
                if config.get("large_downloads", False) and random.random() < 0.2:
                    # Simulate downloading update chunks
                    for _ in range(random.randint(5, 15)):
                        time.sleep(random.uniform(0.1, 0.5))
                        chunk_response = requests.get(url + "/chunk", headers=headers, timeout=10, verify=False)
                        self.stats["requests_sent"] += 1
                        self.stats["bytes_received"] += len(chunk_response.content)
                
        except Exception as e:
            logger.debug(f"Software update simulation error: {e}")
            self.stats["errors"] += 1
    
    def _simulate_dns_queries(self, config: Dict):
        """Simulate DNS queries."""
        domains = config.get("domains", [])
        query_types = config.get("query_types", ["A"])
        
        if not domains:
            return
        
        domain = random.choice(domains)
        query_type = random.choice(query_types)
        
        try:
            # Use socket for basic DNS resolution
            if query_type == "A":
                result = socket.gethostbyname(domain)
                self.stats["connections_made"] += 1
            elif query_type == "AAAA":
                result = socket.getaddrinfo(domain, None, socket.AF_INET6)
                self.stats["connections_made"] += 1
            else:
                # For other query types, we'd need a DNS library
                # For simulation, just count as attempted
                self.stats["connections_made"] += 1
            
        except Exception as e:
            logger.debug(f"DNS query simulation error for {domain}: {e}")
            self.stats["errors"] += 1
    
    def _simulate_email_traffic(self, config: Dict):
        """Simulate email client traffic."""
        servers = config.get("servers", [])
        if not servers:
            return
        
        server_info = random.choice(servers)
        host, port = server_info.split(":")
        port = int(port)
        
        try:
            # Simulate IMAP connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            if port == 993:  # IMAPS
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            sock.connect((host, port))
            
            # Send basic IMAP commands
            commands = [
                b"A001 CAPABILITY\r\n",
                b"A002 NOOP\r\n"
            ]
            
            for cmd in commands:
                sock.send(cmd)
                response = sock.recv(1024)
                self.stats["bytes_sent"] += len(cmd)
                self.stats["bytes_received"] += len(response)
                time.sleep(0.1)
            
            sock.close()
            self.stats["connections_made"] += 1
            
        except Exception as e:
            logger.debug(f"Email simulation error: {e}")
            self.stats["errors"] += 1
    
    def _simulate_background_services(self, config: Dict):
        """Simulate background service traffic."""
        services = config.get("services", [])
        if not services:
            return
        
        service = random.choice(services)
        host = service["host"]
        port = service["port"]
        protocol = service.get("protocol", "TCP")
        
        try:
            if protocol == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(5)
                
                # Send simple UDP packet
                if port == 123:  # NTP
                    # Simple NTP request packet
                    ntp_packet = b'\x1b' + 47 * b'\0'
                    sock.sendto(ntp_packet, (host, port))
                    response = sock.recv(1024)
                    self.stats["bytes_sent"] += len(ntp_packet)
                    self.stats["bytes_received"] += len(response)
                elif port == 53:  # DNS
                    # Simple DNS query packet (simplified)
                    dns_packet = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                    sock.sendto(dns_packet, (host, port))
                    response = sock.recv(1024)
                    self.stats["bytes_sent"] += len(dns_packet)
                    self.stats["bytes_received"] += len(response)
                
                sock.close()
                
            else:  # TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
                response = sock.recv(1024)
                self.stats["bytes_sent"] += 19  # Length of GET request
                self.stats["bytes_received"] += len(response)
                sock.close()
            
            self.stats["connections_made"] += 1
            
        except Exception as e:
            logger.debug(f"Background service simulation error: {e}")
            self.stats["errors"] += 1
    
    def add_custom_pattern(self, pattern_name: str, pattern_config: Dict):
        """Add custom traffic pattern at runtime."""
        self.traffic_patterns[pattern_name] = pattern_config
        logger.info(f"Added custom traffic pattern: {pattern_name}")
        
        # If simulation is running, start new pattern thread
        if self.is_running and pattern_config.get("enabled", False):
            thread = threading.Thread(
                target=self._pattern_worker,
                args=(pattern_name, pattern_config, None),
                name=f"TrafficSim-{pattern_name}",
                daemon=True
            )
            thread.start()
            self.simulator_threads.append(thread)
    
    def get_statistics(self) -> Dict:
        """Get current simulation statistics."""
        stats = self.stats.copy()
        
        if stats["start_time"]:
            current_time = datetime.now()
            stats["runtime_seconds"] = (current_time - stats["start_time"]).total_seconds()
            
            if stats["runtime_seconds"] > 0:
                stats["requests_per_second"] = stats["requests_sent"] / stats["runtime_seconds"]
                stats["connections_per_second"] = stats["connections_made"] / stats["runtime_seconds"]
                stats["bytes_per_second"] = (stats["bytes_sent"] + stats["bytes_received"]) / stats["runtime_seconds"]
            
        stats["active_patterns"] = len([t for t in self.simulator_threads if t.is_alive()])
        stats["is_running"] = self.is_running
        
        return stats
    
    def export_statistics(self, output_file: str = None) -> str:
        """Export simulation statistics to JSON file."""
        if not output_file:
            output_file = f"traffic_simulation_stats_{int(time.time())}.json"
        
        stats = self.get_statistics()
        
        # Convert datetime objects to strings
        if "start_time" in stats and stats["start_time"]:
            stats["start_time"] = stats["start_time"].isoformat()
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, default=str)
            
            logger.info(f"Statistics exported to: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to export statistics: {e}")
            return ""
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.is_running:
            self.stop_simulation()

# Utility functions
def simulate_normal_traffic(duration: int = 300, intensity: str = "medium") -> Dict:
    """
    Convenience function to simulate normal network traffic.
    
    Args:
        duration: Simulation duration in seconds
        intensity: Traffic intensity level
        
    Returns:
        Simulation statistics
    """
    with TrafficSimulator() as simulator:
        if simulator.start_simulation(duration, intensity):
            time.sleep(duration + 5)  # Wait for completion
            return simulator.stop_simulation()
        else:
            return {"error": "Failed to start simulation"}

def create_custom_simulation(patterns: Dict, duration: int = 300) -> Dict:
    """
    Create custom traffic simulation with specific patterns.
    
    Args:
        patterns: Dictionary of custom traffic patterns
        duration: Simulation duration in seconds
        
    Returns:
        Simulation statistics
    """
    config = {"patterns": patterns}
    
    with TrafficSimulator(config) as simulator:
        # Add custom patterns
        for pattern_name, pattern_config in patterns.items():
            simulator.add_custom_pattern(pattern_name, pattern_config)
        
        if simulator.start_simulation(duration):
            time.sleep(duration + 5)
            return simulator.stop_simulation()
        else:
            return {"error": "Failed to start custom simulation"}

if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Network Traffic Simulator')
    parser.add_argument('--duration', type=int, default=300, help='Simulation duration in seconds')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], default='medium', help='Traffic intensity')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--export-stats', help='Export statistics to file')
    parser.add_argument('--patterns', nargs='+', help='Specific patterns to enable')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    print(f"🌐 Starting network traffic simulation")
    print(f"   Duration: {args.duration} seconds")
    print(f"   Intensity: {args.intensity}")
    print("   Press Ctrl+C to stop early\n")
    
    try:
        with TrafficSimulator(config) as simulator:
            # Disable patterns not specified if --patterns is used
            if args.patterns:
                for pattern_name in simulator.traffic_patterns:
                    simulator.traffic_patterns[pattern_name]["enabled"] = pattern_name in args.patterns
            
            if not simulator.start_simulation(args.duration, args.intensity):
                print("❌ Failed to start traffic simulation")
                exit(1)
            
            print("✅ Traffic simulation started")
            print("📊 Live statistics (press Ctrl+C to stop):\n")
            
            start_time = time.time()
            try:
                while simulator.is_running and (time.time() - start_time) < args.duration:
                    time.sleep(5)
                    
                    stats = simulator.get_statistics()
                    print(f"\r🔄 Requests: {stats['requests_sent']} | "
                          f"Connections: {stats['connections_made']} | "
                          f"Errors: {stats['errors']} | "
                          f"Active: {stats['active_patterns']}", end="")
                    
            except KeyboardInterrupt:
                print("\n\n⏹️  Simulation interrupted by user")
            
            print("\n\n🔄 Stopping simulation...")
            final_stats = simulator.stop_simulation()
            
            print("✅ Simulation completed!")
            print(f"\n📈 Final Statistics:")
            print(f"   Total Requests: {final_stats.get('requests_sent', 0)}")
            print(f"   Total Connections: {final_stats.get('connections_made', 0)}")
            print(f"   Bytes Sent: {final_stats.get('bytes_sent', 0):,}")
            print(f"   Bytes Received: {final_stats.get('bytes_received', 0):,}")
            print(f"   Runtime: {final_stats.get('runtime_seconds', 0):.1f} seconds")
            print(f"   Errors: {final_stats.get('errors', 0)}")
            
            if final_stats.get('patterns_executed'):
                print(f"\n📋 Pattern Execution Count:")
                for pattern, count in final_stats['patterns_executed'].items():
                    print(f"   {pattern}: {count}")
            
            # Export statistics if requested
            if args.export_stats:
                export_file = simulator.export_statistics(args.export_stats)
                if export_file:
                    print(f"\n💾 Statistics exported to: {export_file}")
            
    except Exception as e:
        print(f"❌ Error during simulation: {e}")
        exit(1)
