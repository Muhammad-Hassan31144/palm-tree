# shikra/core/modules/network/packet_analyzer.py
# Purpose: Enhanced packet analysis with deep inspection capabilities

import os
import logging
import time
import json
import hashlib
import base64
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple, Any, Set
import ipaddress
import socket
import struct

# Try to import packet analysis libraries
try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.tls import TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    scapy = None
    logger = logging.getLogger(__name__)
    logger.warning("Scapy not available. Packet analysis will be limited.")

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False
    dpkt = None

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None

logger = logging.getLogger(__name__)

class PacketAnalyzer:
    """
    Enhanced packet analyzer with deep inspection capabilities for malware analysis.
    Provides comprehensive analysis of network traffic patterns, payloads, and behaviors.
    """
    
    def __init__(self, sample_id: str = None, config: Dict = None):
        """
        Initialize the packet analyzer.
        
        Args:
            sample_id: Unique identifier for the analysis session
            config: Configuration dictionary
        """
        self.sample_id = sample_id or f"packet_analysis_{int(time.time())}"
        self.config = config or {}
        
        # Analysis results
        self.results = {
            "sample_id": self.sample_id,
            "analysis_timestamp": datetime.now().isoformat(),
            "total_packets": 0,
            "protocols": Counter(),
            "conversations": defaultdict(dict),
            "dns_analysis": {"queries": [], "responses": [], "suspicious_domains": []},
            "http_analysis": {"requests": [], "responses": [], "suspicious_requests": []},
            "tls_analysis": {"handshakes": [], "certificates": [], "suspicious_connections": []},
            "payload_analysis": {"extracted_files": [], "suspicious_payloads": [], "yara_matches": []},
            "behavioral_indicators": [],
            "network_map": {"hosts": {}, "connections": []},
            "statistics": {},
            "errors": []
        }
        
        # Load detection patterns
        self._load_detection_patterns()
        
        # Initialize YARA rules if available
        self._load_yara_rules()
        
        # Conversation tracking
        self.conversations = {}
        self.connection_states = defaultdict(dict)
        
        # Payload extraction
        self.extracted_payloads = []
        self.file_carving_enabled = self.config.get('file_carving', True)
        
        logger.info(f"Packet analyzer initialized for sample: {self.sample_id}")
    
    def _load_detection_patterns(self):
        """Load network detection patterns."""
        patterns_file = self.config.get('network_patterns_file', 'config/network/detection_patterns.json')
        
        try:
            if os.path.exists(patterns_file):
                with open(patterns_file, 'r') as f:
                    self.detection_patterns = json.load(f)
            else:
                self.detection_patterns = self._get_default_patterns()
        except Exception as e:
            logger.error(f"Failed to load detection patterns: {e}")
            self.detection_patterns = self._get_default_patterns()
    
    def _get_default_patterns(self) -> Dict:
        """Default network detection patterns."""
        return {
            "suspicious_domains": [
                r".*\.onion$", r".*\.bit$", r".*\.bazar$",
                r"pastebin\.com", r"paste\.ee", r"ghostbin\.co",
                r"transfer\.sh", r"anonfile\.com", r"mega\.(nz|co\.nz)",
                r"duckdns\.org", r"no-ip\.(com|org)", r"ddns\.net"
            ],
            "suspicious_ips": [
                "127.0.0.1", "0.0.0.0", "255.255.255.255",
                # Add known bad IP ranges
            ],
            "suspicious_ports": [
                4444, 6667, 31337, 8080, 9999, 1337, 6666, 7777
            ],
            "malware_user_agents": [
                "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
                "curl/", "wget/", "python-requests/", "masscan/",
                # Empty or minimal user agents
                "", " ", "User-Agent"
            ],
            "suspicious_http_patterns": [
                r"/gate\.php", r"/panel/", r"/admin\.php",
                r"\?key=", r"\?id=[a-f0-9]{32}", r"\.php\?[a-zA-Z]=[a-f0-9]{8,}",
                r"/upload\.php", r"/cmd\.php", r"/shell\.php"
            ],
            "file_signatures": {
                "PE": b"MZ",
                "ELF": b"\x7fELF",
                "PDF": b"%PDF",
                "ZIP": b"PK\x03\x04",
                "RAR": b"Rar!",
                "GZIP": b"\x1f\x8b",
                "JPEG": b"\xff\xd8\xff",
                "PNG": b"\x89PNG"
            }
        }
    
    def _load_yara_rules(self):
        """Load YARA rules for payload analysis."""
        if not YARA_AVAILABLE:
            self.yara_rules = None
            return
        
        rules_file = self.config.get('yara_rules_file', 'config/network/network_yara_rules.yar')
        
        try:
            if os.path.exists(rules_file):
                self.yara_rules = yara.compile(filepath=rules_file)
                logger.info(f"Loaded YARA rules from {rules_file}")
            else:
                # Create basic rules if file doesn't exist
                self.yara_rules = self._create_default_yara_rules()
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            self.yara_rules = None
    
    def _create_default_yara_rules(self):
        """Create default YARA rules for network analysis."""
        if not YARA_AVAILABLE:
            return None
        
        default_rules = '''
        rule Suspicious_HTTP_Request {
            meta:
                description = "Suspicious HTTP request patterns"
                author = "Shikra"
            strings:
                $gate = "/gate.php"
                $panel = "/panel/"
                $upload = "/upload.php"
                $cmd = "/cmd.php"
            condition:
                any of them
        }
        
        rule Base64_Encoded_Payload {
            meta:
                description = "Base64 encoded payload in network traffic"
            strings:
                $b64_1 = /[A-Za-z0-9+\/]{20,}={0,2}/
            condition:
                $b64_1
        }
        
        rule Executable_Download {
            meta:
                description = "Executable file download"
            strings:
                $pe = { 4D 5A }  // PE header
                $elf = { 7F 45 4C 46 }  // ELF header
            condition:
                any of them at 0
        }
        '''
        
        try:
            return yara.compile(source=default_rules)
        except Exception as e:
            logger.error(f"Failed to compile default YARA rules: {e}")
            return None
    
    def analyze_pcap(self, pcap_file: str) -> Dict:
        """
        Analyze a PCAP file with deep packet inspection.
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Analysis results dictionary
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available for packet analysis")
            self.results["errors"].append("Scapy library not available")
            return self.results
        
        if not os.path.exists(pcap_file):
            logger.error(f"PCAP file not found: {pcap_file}")
            self.results["errors"].append(f"PCAP file not found: {pcap_file}")
            return self.results
        
        logger.info(f"Analyzing PCAP file: {pcap_file}")
        
        try:
            # Read packets
            packets = scapy.rdpcap(pcap_file)
            self.results["total_packets"] = len(packets)
            
            logger.info(f"Loaded {len(packets)} packets for analysis")
            
            # Analyze each packet
            for i, packet in enumerate(packets):
                try:
                    self._analyze_packet(packet, i)
                except Exception as e:
                    logger.debug(f"Error analyzing packet {i}: {e}")
                    continue
            
            # Post-processing analysis
            self._post_process_analysis()
            
            # Generate statistics
            self._generate_statistics()
            
            logger.info("Packet analysis completed")
            return self.results
            
        except Exception as e:
            error_msg = f"Failed to analyze PCAP file: {e}"
            logger.error(error_msg)
            self.results["errors"].append(error_msg)
            return self.results
    
    def _analyze_packet(self, packet, packet_num: int):
        """Analyze individual packet."""
        # Extract basic packet information
        packet_info = {
            "number": packet_num,
            "timestamp": float(packet.time) if hasattr(packet, 'time') else time.time(),
            "length": len(packet)
        }
        
        # Protocol analysis
        if packet.haslayer(IP):
            self._analyze_ip_packet(packet, packet_info)
        elif packet.haslayer(IPv6):
            self._analyze_ipv6_packet(packet, packet_info)
        elif packet.haslayer(ARP):
            self._analyze_arp_packet(packet, packet_info)
        
        # Layer-specific analysis
        if packet.haslayer(TCP):
            self._analyze_tcp_packet(packet, packet_info)
        elif packet.haslayer(UDP):
            self._analyze_udp_packet(packet, packet_info)
        elif packet.haslayer(ICMP):
            self._analyze_icmp_packet(packet, packet_info)
        
        # Application layer analysis
        if packet.haslayer(DNS):
            self._analyze_dns_packet(packet, packet_info)
        elif packet.haslayer(HTTP):
            self._analyze_http_packet(packet, packet_info)
        elif packet.haslayer(TLS):
            self._analyze_tls_packet(packet, packet_info)
        
        # Payload analysis
        self._analyze_payload(packet, packet_info)
    
    def _analyze_ip_packet(self, packet, packet_info: Dict):
        """Analyze IP layer."""
        ip_layer = packet[IP]
        
        packet_info.update({
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": ip_layer.proto,
            "ttl": ip_layer.ttl,
            "id": ip_layer.id
        })
        
        self.results["protocols"]["IPv4"] += 1
        
        # Track conversations
        conv_key = f"{ip_layer.src}:{ip_layer.dst}"
        if conv_key not in self.conversations:
            self.conversations[conv_key] = {
                "src": ip_layer.src,
                "dst": ip_layer.dst,
                "packets": 0,
                "bytes": 0,
                "first_seen": packet_info["timestamp"],
                "last_seen": packet_info["timestamp"],
                "protocols": set()
            }
        
        conv = self.conversations[conv_key]
        conv["packets"] += 1
        conv["bytes"] += packet_info["length"]
        conv["last_seen"] = packet_info["timestamp"]
        
        # Check for suspicious IPs
        self._check_suspicious_ip(ip_layer.src, ip_layer.dst, packet_info)
    
    def _analyze_ipv6_packet(self, packet, packet_info: Dict):
        """Analyze IPv6 layer."""
        ipv6_layer = packet[IPv6]
        
        packet_info.update({
            "src_ip": ipv6_layer.src,
            "dst_ip": ipv6_layer.dst,
            "next_header": ipv6_layer.nh,
            "hop_limit": ipv6_layer.hlim
        })
        
        self.results["protocols"]["IPv6"] += 1
    
    def _analyze_tcp_packet(self, packet, packet_info: Dict):
        """Analyze TCP layer."""
        tcp_layer = packet[TCP]
        
        packet_info.update({
            "src_port": tcp_layer.sport,
            "dst_port": tcp_layer.dport,
            "flags": tcp_layer.flags,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "window": tcp_layer.window
        })
        
        self.results["protocols"]["TCP"] += 1
        
        # Track connection state
        conn_key = f"{packet_info.get('src_ip')}:{tcp_layer.sport}-{packet_info.get('dst_ip')}:{tcp_layer.dport}"
        
        if conn_key not in self.connection_states:
            self.connection_states[conn_key] = {
                "state": "NEW",
                "syn_seen": False,
                "syn_ack_seen": False,
                "established": False,
                "fin_seen": False,
                "rst_seen": False
            }
        
        conn_state = self.connection_states[conn_key]
        
        # Update connection state based on TCP flags
        if tcp_layer.flags & 0x02:  # SYN
            conn_state["syn_seen"] = True
        if tcp_layer.flags & 0x12:  # SYN+ACK
            conn_state["syn_ack_seen"] = True
        if tcp_layer.flags & 0x10:  # ACK
            if conn_state["syn_seen"] and conn_state["syn_ack_seen"]:
                conn_state["established"] = True
        if tcp_layer.flags & 0x01:  # FIN
            conn_state["fin_seen"] = True
        if tcp_layer.flags & 0x04:  # RST
            conn_state["rst_seen"] = True
        
        # Check for suspicious ports
        self._check_suspicious_port(tcp_layer.sport, tcp_layer.dport, packet_info)
    
    def _analyze_udp_packet(self, packet, packet_info: Dict):
        """Analyze UDP layer."""
        udp_layer = packet[UDP]
        
        packet_info.update({
            "src_port": udp_layer.sport,
            "dst_port": udp_layer.dport,
            "length": udp_layer.len
        })
        
        self.results["protocols"]["UDP"] += 1
        
        # Check for suspicious ports
        self._check_suspicious_port(udp_layer.sport, udp_layer.dport, packet_info)
    
    def _analyze_dns_packet(self, packet, packet_info: Dict):
        """Analyze DNS packets."""
        dns_layer = packet[DNS]
        
        dns_info = {
            "id": dns_layer.id,
            "qr": dns_layer.qr,
            "opcode": dns_layer.opcode,
            "rcode": dns_layer.rcode,
            "timestamp": packet_info["timestamp"],
            "src_ip": packet_info.get("src_ip"),
            "dst_ip": packet_info.get("dst_ip")
        }
        
        # DNS queries
        if dns_layer.qr == 0 and dns_layer.qd:  # Query
            for query in dns_layer.qd:
                query_info = dns_info.copy()
                query_info.update({
                    "query": query.qname.decode() if query.qname else "",
                    "qtype": query.qtype,
                    "qclass": query.qclass
                })
                
                self.results["dns_analysis"]["queries"].append(query_info)
                
                # Check for suspicious domains
                self._check_suspicious_domain(query_info["query"], query_info)
        
        # DNS responses
        elif dns_layer.qr == 1 and dns_layer.an:  # Response
            for answer in dns_layer.an:
                response_info = dns_info.copy()
                response_info.update({
                    "name": answer.rrname.decode() if answer.rrname else "",
                    "type": answer.type,
                    "rdata": str(answer.rdata) if answer.rdata else "",
                    "ttl": answer.ttl
                })
                
                self.results["dns_analysis"]["responses"].append(response_info)
    
    def _analyze_http_packet(self, packet, packet_info: Dict):
        """Analyze HTTP packets."""
        if packet.haslayer(HTTPRequest):
            self._analyze_http_request(packet, packet_info)
        elif packet.haslayer(HTTPResponse):
            self._analyze_http_response(packet, packet_info)
    
    def _analyze_http_request(self, packet, packet_info: Dict):
        """Analyze HTTP request."""
        http_layer = packet[HTTPRequest]
        
        request_info = {
            "timestamp": packet_info["timestamp"],
            "src_ip": packet_info.get("src_ip"),
            "dst_ip": packet_info.get("dst_ip"),
            "src_port": packet_info.get("src_port"),
            "dst_port": packet_info.get("dst_port"),
            "method": http_layer.Method.decode() if http_layer.Method else "",
            "host": http_layer.Host.decode() if http_layer.Host else "",
            "path": http_layer.Path.decode() if http_layer.Path else "",
            "user_agent": http_layer.User_Agent.decode() if http_layer.User_Agent else "",
            "headers": {}
        }
        
        # Extract headers
        if hasattr(http_layer, 'headers'):
            for header, value in http_layer.headers.items():
                request_info["headers"][header.decode()] = value.decode()
        
        self.results["http_analysis"]["requests"].append(request_info)
        
        # Check for suspicious HTTP patterns
        self._check_suspicious_http_request(request_info)
    
    def _analyze_http_response(self, packet, packet_info: Dict):
        """Analyze HTTP response."""
        http_layer = packet[HTTPResponse]
        
        response_info = {
            "timestamp": packet_info["timestamp"],
            "src_ip": packet_info.get("src_ip"),
            "dst_ip": packet_info.get("dst_ip"),
            "status_code": http_layer.Status_Code.decode() if http_layer.Status_Code else "",
            "reason_phrase": http_layer.Reason_Phrase.decode() if http_layer.Reason_Phrase else "",
            "content_type": http_layer.Content_Type.decode() if http_layer.Content_Type else "",
            "content_length": http_layer.Content_Length.decode() if http_layer.Content_Length else "",
            "headers": {}
        }
        
        # Extract headers
        if hasattr(http_layer, 'headers'):
            for header, value in http_layer.headers.items():
                response_info["headers"][header.decode()] = value.decode()
        
        self.results["http_analysis"]["responses"].append(response_info)
        
        # Check for file downloads
        self._check_file_download(response_info, packet)
    
    def _analyze_tls_packet(self, packet, packet_info: Dict):
        """Analyze TLS packets."""
        tls_layer = packet[TLS]
        
        # Basic TLS info
        tls_info = {
            "timestamp": packet_info["timestamp"],
            "src_ip": packet_info.get("src_ip"),
            "dst_ip": packet_info.get("dst_ip"),
            "src_port": packet_info.get("src_port"),
            "dst_port": packet_info.get("dst_port"),
            "version": getattr(tls_layer, 'version', None),
            "type": getattr(tls_layer, 'type', None)
        }
        
        # Extract SNI from ClientHello if present
        if hasattr(tls_layer, 'msg') and tls_layer.msg:
            for msg in tls_layer.msg:
                if hasattr(msg, 'ext') and msg.ext:
                    for ext in msg.ext:
                        if hasattr(ext, 'servernames') and ext.servernames:
                            for sni in ext.servernames:
                                if hasattr(sni, 'servername'):
                                    tls_info["sni"] = sni.servername.decode()
        
        self.results["tls_analysis"]["handshakes"].append(tls_info)
        
        # Check for suspicious TLS connections
        if "sni" in tls_info:
            self._check_suspicious_domain(tls_info["sni"], tls_info)
    
    def _analyze_payload(self, packet, packet_info: Dict):
        """Analyze packet payload for suspicious content."""
        try:
            # Get raw payload
            if packet.haslayer(scapy.Raw):
                payload = bytes(packet[scapy.Raw])
            else:
                payload = bytes(packet.payload) if hasattr(packet, 'payload') else b""
            
            if not payload:
                return
            
            # File signature detection
            self._check_file_signatures(payload, packet_info)
            
            # YARA analysis
            if self.yara_rules:
                self._yara_scan_payload(payload, packet_info)
            
            # Base64 detection
            self._check_base64_content(payload, packet_info)
            
            # Store payload for further analysis if significant
            if len(payload) > 100:  # Only store substantial payloads
                payload_hash = hashlib.sha256(payload).hexdigest()
                payload_info = {
                    "hash": payload_hash,
                    "size": len(payload),
                    "timestamp": packet_info["timestamp"],
                    "src_ip": packet_info.get("src_ip"),
                    "dst_ip": packet_info.get("dst_ip"),
                    "protocol": packet_info.get("protocol"),
                    "payload_preview": payload[:100].hex()
                }
                
                self.extracted_payloads.append(payload_info)
                
        except Exception as e:
            logger.debug(f"Error analyzing payload: {e}")
    
    def _check_suspicious_ip(self, src_ip: str, dst_ip: str, packet_info: Dict):
        """Check for suspicious IP addresses."""
        for ip in [src_ip, dst_ip]:
            # Check against known bad IPs
            if ip in self.detection_patterns["suspicious_ips"]:
                self._add_behavioral_indicator(
                    "suspicious_ip",
                    f"Communication with known suspicious IP: {ip}",
                    "high",
                    packet_info
                )
            
            # Check for private IP ranges communicating externally
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private and dst_ip != src_ip:
                    other_ip = dst_ip if ip == src_ip else src_ip
                    other_ip_obj = ipaddress.ip_address(other_ip)
                    if not other_ip_obj.is_private:
                        # Private to public communication - normal but worth noting
                        pass
            except ValueError:
                pass
    
    def _check_suspicious_port(self, src_port: int, dst_port: int, packet_info: Dict):
        """Check for suspicious port usage."""
        for port in [src_port, dst_port]:
            if port in self.detection_patterns["suspicious_ports"]:
                self._add_behavioral_indicator(
                    "suspicious_port",
                    f"Communication on suspicious port: {port}",
                    "medium",
                    packet_info
                )
    
    def _check_suspicious_domain(self, domain: str, context_info: Dict):
        """Check domain against suspicious patterns."""
        for pattern in self.detection_patterns["suspicious_domains"]:
            import re
            if re.match(pattern, domain):
                self.results["dns_analysis"]["suspicious_domains"].append({
                    "domain": domain,
                    "pattern_matched": pattern,
                    "context": context_info
                })
                
                self._add_behavioral_indicator(
                    "suspicious_domain",
                    f"Suspicious domain detected: {domain}",
                    "high",
                    context_info
                )
                break
    
    def _check_suspicious_http_request(self, request_info: Dict):
        """Check HTTP request for suspicious patterns."""
        url_path = request_info.get("path", "")
        user_agent = request_info.get("user_agent", "")
        
        # Check URL patterns
        for pattern in self.detection_patterns["suspicious_http_patterns"]:
            import re
            if re.search(pattern, url_path):
                self.results["http_analysis"]["suspicious_requests"].append({
                    "request": request_info,
                    "reason": f"Suspicious URL pattern: {pattern}"
                })
                
                self._add_behavioral_indicator(
                    "suspicious_http_request",
                    f"Suspicious HTTP request pattern: {pattern}",
                    "medium",
                    request_info
                )
                break
        
        # Check user agent
        if user_agent in self.detection_patterns["malware_user_agents"]:
            self.results["http_analysis"]["suspicious_requests"].append({
                "request": request_info,
                "reason": f"Suspicious user agent: {user_agent}"
            })
            
            self._add_behavioral_indicator(
                "suspicious_user_agent",
                f"Suspicious user agent: {user_agent}",
                "medium",
                request_info
            )
    
    def _check_file_download(self, response_info: Dict, packet):
        """Check for potentially malicious file downloads."""
        content_type = response_info.get("content_type", "")
        status_code = response_info.get("status_code", "")
        
        # Check for executable downloads
        suspicious_content_types = [
            "application/octet-stream",
            "application/x-executable",
            "application/x-msdownload",
            "application/x-msdos-program"
        ]
        
        if content_type in suspicious_content_types and status_code.startswith("200"):
            # Extract payload if possible
            if packet.haslayer(scapy.Raw):
                payload = bytes(packet[scapy.Raw])
                
                # Check file signatures
                for file_type, signature in self.detection_patterns["file_signatures"].items():
                    if payload.startswith(signature):
                        self.results["payload_analysis"]["extracted_files"].append({
                            "file_type": file_type,
                            "size": len(payload),
                            "hash": hashlib.sha256(payload).hexdigest(),
                            "source": response_info,
                            "timestamp": response_info["timestamp"]
                        })
                        
                        self._add_behavioral_indicator(
                            "file_download",
                            f"Downloaded {file_type} file ({len(payload)} bytes)",
                            "high",
                            response_info
                        )
                        break
    
    def _check_file_signatures(self, payload: bytes, packet_info: Dict):
        """Check payload for file signatures."""
        for file_type, signature in self.detection_patterns["file_signatures"].items():
            if payload.startswith(signature):
                file_info = {
                    "file_type": file_type,
                    "size": len(payload),
                    "hash": hashlib.sha256(payload).hexdigest(),
                    "timestamp": packet_info["timestamp"],
                    "context": packet_info
                }
                
                self.results["payload_analysis"]["extracted_files"].append(file_info)
                break
    
    def _yara_scan_payload(self, payload: bytes, packet_info: Dict):
        """Scan payload with YARA rules."""
        try:
            matches = self.yara_rules.match(data=payload)
            
            for match in matches:
                match_info = {
                    "rule": match.rule,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": [],
                    "timestamp": packet_info["timestamp"],
                    "context": packet_info
                }
                
                # Extract string matches
                for string_match in match.strings:
                    match_info["strings"].append({
                        "identifier": string_match.identifier,
                        "instances": [
                            {
                                "offset": instance.offset,
                                "length": instance.length,
                                "data": payload[instance.offset:instance.offset+instance.length].hex()
                            }
                            for instance in string_match.instances
                        ]
                    })
                
                self.results["payload_analysis"]["yara_matches"].append(match_info)
                
                self._add_behavioral_indicator(
                    "yara_match",
                    f"YARA rule matched: {match.rule}",
                    "high",
                    packet_info
                )
                
        except Exception as e:
            logger.debug(f"YARA scan error: {e}")
    
    def _check_base64_content(self, payload: bytes, packet_info: Dict):
        """Check for base64 encoded content."""
        try:
            # Look for base64 patterns
            import re
            text_payload = payload.decode('utf-8', errors='ignore')
            
            # Find potential base64 strings (minimum length 20)
            base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(base64_pattern, text_payload)
            
            for match in matches:
                if len(match) > 50:  # Only check substantial base64 strings
                    try:
                        decoded = base64.b64decode(match)
                        
                        # Check if decoded content is interesting
                        if len(decoded) > 10:
                            decoded_info = {
                                "base64_string": match[:100] + "..." if len(match) > 100 else match,
                                "decoded_size": len(decoded),
                                "decoded_preview": decoded[:50].hex(),
                                "timestamp": packet_info["timestamp"],
                                "context": packet_info
                            }
                            
                            self.results["payload_analysis"]["suspicious_payloads"].append(decoded_info)
                            
                            # Check decoded content for file signatures
                            self._check_file_signatures(decoded, packet_info)
                            
                    except Exception:
                        pass  # Not valid base64
                        
        except Exception as e:
            logger.debug(f"Base64 check error: {e}")
    
    def _add_behavioral_indicator(self, indicator_type: str, description: str, severity: str, context: Dict):
        """Add behavioral indicator to results."""
        indicator = {
            "type": indicator_type,
            "description": description,
            "severity": severity,
            "timestamp": context.get("timestamp", time.time()),
            "context": context
        }
        
        self.results["behavioral_indicators"].append(indicator)
    
    def _post_process_analysis(self):
        """Post-processing analysis after all packets are analyzed."""
        # Build network map
        self._build_network_map()
        
        # Analyze conversation patterns
        self._analyze_conversation_patterns()
        
        # Detect beaconing behavior
        self._detect_beaconing()
        
        # Correlate indicators
        self._correlate_indicators()
    
    def _build_network_map(self):
        """Build network topology map."""
        hosts = {}
        connections = []
        
        for conv_key, conv_data in self.conversations.items():
            src_ip = conv_data["src"]
            dst_ip = conv_data["dst"]
            
            # Add hosts
            for ip in [src_ip, dst_ip]:
                if ip not in hosts:
                    hosts[ip] = {
                        "ip": ip,
                        "connections": 0,
                        "bytes_sent": 0,
                        "bytes_received": 0,
                        "first_seen": conv_data["first_seen"],
                        "last_seen": conv_data["last_seen"],
                        "protocols": set()
                    }
                
                hosts[ip]["connections"] += 1
                hosts[ip]["protocols"].update(conv_data["protocols"])
                
                if ip == src_ip:
                    hosts[ip]["bytes_sent"] += conv_data["bytes"]
                else:
                    hosts[ip]["bytes_received"] += conv_data["bytes"]
            
            # Add connection
            connections.append({
                "src": src_ip,
                "dst": dst_ip,
                "packets": conv_data["packets"],
                "bytes": conv_data["bytes"],
                "duration": conv_data["last_seen"] - conv_data["first_seen"],
                "protocols": list(conv_data["protocols"])
            })
        
        # Convert sets to lists for JSON serialization
        for host_info in hosts.values():
            host_info["protocols"] = list(host_info["protocols"])
        
        self.results["network_map"] = {
            "hosts": hosts,
            "connections": connections
        }
    
    def _analyze_conversation_patterns(self):
        """Analyze communication patterns between hosts."""
        # Look for unusual communication patterns
        for conv_key, conv_data in self.conversations.items():
            duration = conv_data["last_seen"] - conv_data["first_seen"]
            
            # High packet rate
            if duration > 0 and conv_data["packets"] / duration > 100:  # More than 100 packets/second
                self._add_behavioral_indicator(
                    "high_packet_rate",
                    f"High packet rate: {conv_data['packets']/duration:.1f} packets/second",
                    "medium",
                    {"conversation": conv_key, "data": conv_data}
                )
            
            # Long-duration connection
            if duration > 3600:  # More than 1 hour
                self._add_behavioral_indicator(
                    "long_connection",
                    f"Long-duration connection: {duration/3600:.1f} hours",
                    "low",
                    {"conversation": conv_key, "data": conv_data}
                )
    
    def _detect_beaconing(self):
        """Detect beaconing behavior in network traffic."""
        # Group connections by destination
        dest_connections = defaultdict(list)
        
        for conv_key, conv_data in self.conversations.items():
            dest_connections[conv_data["dst"]].append(conv_data)
        
        # Look for regular communication patterns
        for dest_ip, connections in dest_connections.items():
            if len(connections) < 3:  # Need at least 3 connections to detect pattern
                continue
            
            # Calculate intervals between connections
            timestamps = sorted([conn["first_seen"] for conn in connections])
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            
            if len(intervals) < 2:
                continue
            
            # Check for regular intervals (beaconing)
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((interval - avg_interval) ** 2 for interval in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # If standard deviation is low relative to average, it might be beaconing
            if avg_interval > 0 and std_dev / avg_interval < 0.3:  # Less than 30% variation
                self._add_behavioral_indicator(
                    "beaconing_detected",
                    f"Regular communication pattern to {dest_ip}: {avg_interval:.1f}s intervals",
                    "high",
                    {"destination": dest_ip, "connections": len(connections), "avg_interval": avg_interval}
                )
    
    def _correlate_indicators(self):
        """Correlate different behavioral indicators."""
        # Group indicators by type
        indicator_types = defaultdict(list)
        for indicator in self.results["behavioral_indicators"]:
            indicator_types[indicator["type"]].append(indicator)
        
        # Look for indicator combinations that suggest specific malware behaviors
        combinations = [
            (["suspicious_domain", "beaconing_detected"], "c2_communication", "Critical: C2 communication detected"),
            (["file_download", "suspicious_http_request"], "malware_download", "High: Malware download detected"),
            (["suspicious_port", "high_packet_rate"], "data_exfiltration", "High: Potential data exfiltration"),
            (["yara_match", "file_download"], "confirmed_malware", "Critical: Confirmed malware activity")
        ]
        
        for required_types, combined_type, description in combinations:
            if all(req_type in indicator_types for req_type in required_types):
                # Create combined indicator
                combined_indicator = {
                    "type": combined_type,
                    "description": description,
                    "severity": "critical",
                    "timestamp": time.time(),
                    "related_indicators": [
                        {"type": req_type, "count": len(indicator_types[req_type])}
                        for req_type in required_types
                    ]
                }
                
                self.results["behavioral_indicators"].append(combined_indicator)
    
    def _generate_statistics(self):
        """Generate analysis statistics."""
        # Protocol statistics
        total_packets = sum(self.results["protocols"].values())
        protocol_stats = {}
        for protocol, count in self.results["protocols"].items():
            protocol_stats[protocol] = {
                "count": count,
                "percentage": (count / max(total_packets, 1)) * 100
            }
        
        # Conversation statistics
        if self.conversations:
            total_bytes = sum(conv["bytes"] for conv in self.conversations.values())
            total_duration = max(conv["last_seen"] for conv in self.conversations.values()) - \
                           min(conv["first_seen"] for conv in self.conversations.values())
        else:
            total_bytes = 0
            total_duration = 0
        
        # Behavioral statistics
        indicator_counts = Counter(ind["type"] for ind in self.results["behavioral_indicators"])
        severity_counts = Counter(ind["severity"] for ind in self.results["behavioral_indicators"])
        
        self.results["statistics"] = {
            "total_packets": total_packets,
            "total_conversations": len(self.conversations),
            "total_bytes": total_bytes,
            "analysis_duration": total_duration,
            "protocol_distribution": protocol_stats,
            "dns_queries": len(self.results["dns_analysis"]["queries"]),
            "dns_responses": len(self.results["dns_analysis"]["responses"]),
            "http_requests": len(self.results["http_analysis"]["requests"]),
            "http_responses": len(self.results["http_analysis"]["responses"]),
            "tls_handshakes": len(self.results["tls_analysis"]["handshakes"]),
            "behavioral_indicators": dict(indicator_counts),
            "severity_distribution": dict(severity_counts),
            "extracted_files": len(self.results["payload_analysis"]["extracted_files"]),
            "yara_matches": len(self.results["payload_analysis"]["yara_matches"])
        }
    
    def export_results(self, output_file: str = None) -> str:
        """Export analysis results to JSON file."""
        if not output_file:
            output_file = f"packet_analysis_{self.sample_id}.json"
        
        try:
            # Make results JSON serializable
            serializable_results = self._make_json_serializable(self.results)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, default=str)
            
            logger.info(f"Results exported to: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return ""
    
    def _make_json_serializable(self, obj):
        """Convert objects to JSON-serializable format."""
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, Counter):
            return dict(obj)
        elif isinstance(obj, defaultdict):
            return dict(obj)
        else:
            return obj

# Utility functions
def analyze_pcap_file(pcap_file: str, sample_id: str = None, config: Dict = None) -> Dict:
    """
    Convenience function to analyze a PCAP file.
    
    Args:
        pcap_file: Path to PCAP file
        sample_id: Sample identifier
        config: Configuration dictionary
        
    Returns:
        Analysis results dictionary
    """
    analyzer = PacketAnalyzer(sample_id, config)
    return analyzer.analyze_pcap(pcap_file)

def extract_files_from_pcap(pcap_file: str, output_dir: str = None) -> List[str]:
    """
    Extract files from network traffic in PCAP.
    
    Args:
        pcap_file: Path to PCAP file
        output_dir: Directory to save extracted files
        
    Returns:
        List of extracted file paths
    """
    if not output_dir:
        output_dir = f"extracted_files_{int(time.time())}"
    
    os.makedirs(output_dir, exist_ok=True)
    
    analyzer = PacketAnalyzer(config={"file_carving": True})
    results = analyzer.analyze_pcap(pcap_file)
    
    extracted_files = []
    
    for file_info in results["payload_analysis"]["extracted_files"]:
        file_hash = file_info["hash"]
        file_type = file_info["file_type"]
        
        # Find the actual payload data
        # This would require storing the payload data in the analysis
        # For now, just return the file info
        extracted_files.append(file_info)
    
    return extracted_files

if __name__ == "__main__":
    import argparse
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description='Enhanced Packet Analyzer')
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('--sample-id', help='Sample ID for analysis')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--output', help='Output JSON file path')
    parser.add_argument('--extract-files', action='store_true', help='Extract files from traffic')
    parser.add_argument('--yara-rules', help='YARA rules file for payload analysis')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    if args.yara_rules:
        config['yara_rules_file'] = args.yara_rules
    
    # Analyze PCAP
    analyzer = PacketAnalyzer(args.sample_id, config)
    results = analyzer.analyze_pcap(args.pcap_file)
    
    # Export results
    output_file = args.output or f"packet_analysis_{args.sample_id or 'unknown'}.json"
    analyzer.export_results(output_file)
    
    # Print summary
    stats = results.get("statistics", {})
    print(f"\n📊 Analysis Summary:")
    print(f"   Total Packets: {stats.get('total_packets', 0)}")
    print(f"   Conversations: {stats.get('total_conversations', 0)}")
    print(f"   DNS Queries: {stats.get('dns_queries', 0)}")
    print(f"   HTTP Requests: {stats.get('http_requests', 0)}")
    print(f"   Behavioral Indicators: {sum(stats.get('behavioral_indicators', {}).values())}")
    print(f"   Extracted Files: {stats.get('extracted_files', 0)}")
    
    if results.get("behavioral_indicators"):
        print(f"\n🚨 Key Findings:")
        for indicator in results["behavioral_indicators"][:5]:  # Show top 5
            print(f"   [{indicator['severity'].upper()}] {indicator['description']}")
    
    print(f"\n💾 Results saved to: {output_file}")
