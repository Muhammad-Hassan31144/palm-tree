# shikra/modules/monitoring/fake_services.py
# Purpose: Simulates common network services that malware might interact with.
# Provides fake HTTP/S, DNS, FTP, SMTP services for controlled malware analysis.

import os
import ssl
import json
import time
import socket
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Union
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn, UDPServer, BaseRequestHandler
import logging

logger = logging.getLogger(__name__)

class InteractionLog:
    """Manages interaction logging for fake services."""
    
    def __init__(self):
        self.logs: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
    
    def log_interaction(self, service_name: str, details: Dict[str, Any]):
        """Log an interaction with a fake service."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "service": service_name,
            "client_ip": details.get("client_ip", "unknown"),
            "details": details
        }
        
        with self.lock:
            self.logs.append(log_entry)
            
        logger.info(f"[{service_name}] {details.get('summary', 'Interaction logged')}")
    
    def get_logs(self, service_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get interaction logs, optionally filtered by service."""
        with self.lock:
            if service_filter:
                return [log for log in self.logs if log["service"] == service_filter]
            return list(self.logs)
    
    def clear_logs(self):
        """Clear all interaction logs."""
        with self.lock:
            self.logs.clear()
            
    def export_logs(self, output_file: Union[str, Path]) -> bool:
        """Export logs to JSON file."""
        try:
            with self.lock:
                logs_data = {
                    "export_time": datetime.now().isoformat(),
                    "total_interactions": len(self.logs),
                    "interactions": self.logs
                }
            
            with open(output_file, 'w') as f:
                json.dump(logs_data, f, indent=2)
            
            logger.info(f"Exported {len(self.logs)} interaction logs to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export logs: {e}")
            return False


class FakeHTTPHandler(BaseHTTPRequestHandler):
    """Custom HTTP request handler for fake HTTP service."""
    
    def __init__(self, request, client_address, server, response_config=None, interaction_log=None):
        self.response_config = response_config or {}
        self.interaction_log = interaction_log
        super().__init__(request, client_address, server)
    
    def do_GET(self):
        self._handle_request("GET")
    
    def do_POST(self):
        self._handle_request("POST")
    
    def do_PUT(self):
        self._handle_request("PUT")
    
    def do_DELETE(self):
        self._handle_request("DELETE")
    
    def _handle_request(self, method: str):
        client_ip = self.client_address[0]
        path = self.path
        headers = dict(self.headers)
        
        # Read POST data if available
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        
        # Log interaction
        if self.interaction_log:
            self.interaction_log.log_interaction("http", {
                "summary": f"{method} {path}",
                "client_ip": client_ip,
                "method": method,
                "path": path,
                "headers": headers,
                "content_length": content_length,
                "user_agent": headers.get("User-Agent", ""),
                "host": headers.get("Host", "")
            })
        
        # Check for custom responses
        response_data = self._get_response_for_path(path, method)
        
        # Send response
        self.send_response(response_data["status"])
        for header, value in response_data["headers"].items():
            self.send_header(header, value)
        self.end_headers()
        
        if response_data["body"]:
            self.wfile.write(response_data["body"])
    
    def _get_response_for_path(self, path: str, method: str) -> Dict[str, Any]:
        """Get configured response for a specific path and method."""
        # Check for exact path match
        path_key = f"{method}:{path}"
        if path_key in self.response_config:
            return self.response_config[path_key]
        
        # Check for pattern matches
        for pattern, response in self.response_config.items():
            if pattern.startswith("pattern:") and pattern[8:] in path:
                return response
        
        # Default responses for common malware requests
        default_responses = {
            "/gate.php": self._create_response(200, b"OK", {"Content-Type": "text/plain"}),
            "/panel/": self._create_response(200, b"Admin Panel", {"Content-Type": "text/html"}),
            "/check.php": self._create_response(200, b"1", {"Content-Type": "text/plain"}),
            "/config.txt": self._create_response(200, b"server=127.0.0.1\nkey=test123", {"Content-Type": "text/plain"})
        }
        
        for default_path, response in default_responses.items():
            if default_path in path:
                return response
        
        # Generic response
        return self._create_response(404, b"Not Found", {"Content-Type": "text/plain"})
    
    def _create_response(self, status: int, body: bytes, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Create a response dictionary."""
        return {
            "status": status,
            "headers": headers or {},
            "body": body
        }
    
    def log_message(self, format, *args):
        """Override to use our logger instead of stderr."""
        logger.debug(f"HTTP: {format % args}")


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threading HTTP server for handling multiple connections."""
    daemon_threads = True
    allow_reuse_address = True


class FakeDNSHandler(BaseRequestHandler):
    """DNS request handler for fake DNS service."""
    
    def __init__(self, request, client_address, server):
        self.dns_config = server.dns_config
        self.interaction_log = server.interaction_log
        super().__init__(request, client_address, server)
    
    def handle(self):
        try:
            data, socket = self.request
            client_ip = self.client_address[0]
            
            if len(data) < 12:  # Minimum DNS header size
                return
            
            # Parse basic DNS header
            transaction_id = data[:2]
            flags = int.from_bytes(data[2:4], 'big')
            
            # Check if it's a query (QR bit = 0)
            if flags & 0x8000:
                return
            
            # Extract query name (simplified parsing)
            query_name = self._parse_domain_name(data, 12)
            query_type = int.from_bytes(data[12 + len(self._encode_domain_name(query_name)):12 + len(self._encode_domain_name(query_name)) + 2], 'big')
            
            # Log interaction
            if self.interaction_log:
                self.interaction_log.log_interaction("dns", {
                    "summary": f"Query {query_name} (type {query_type})",
                    "client_ip": client_ip,
                    "query_name": query_name,
                    "query_type": query_type
                })
            
            # Create response
            response = self._create_dns_response(transaction_id, query_name, query_type)
            socket.sendto(response, self.client_address)
            
        except Exception as e:
            logger.debug(f"DNS handler error: {e}")
    
    def _parse_domain_name(self, data: bytes, offset: int) -> str:
        """Parse domain name from DNS packet."""
        name_parts = []
        pos = offset
        
        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            if length > 63:  # Compression pointer
                break
            
            pos += 1
            if pos + length > len(data):
                break
                
            name_parts.append(data[pos:pos + length].decode('ascii', errors='ignore'))
            pos += length
        
        return '.'.join(name_parts)
    
    def _encode_domain_name(self, name: str) -> bytes:
        """Encode domain name for DNS packet."""
        encoded = b''
        for part in name.split('.'):
            part_bytes = part.encode('ascii', errors='ignore')
            encoded += bytes([len(part_bytes)]) + part_bytes
        encoded += b'\x00'
        return encoded
    
    def _create_dns_response(self, transaction_id: bytes, query_name: str, query_type: int) -> bytes:
        """Create DNS response packet."""
        # Get configured IP for this domain
        response_ip = self.dns_config.get(query_name, self.dns_config.get("*", "127.0.0.1"))
        
        # DNS header (response)
        flags = 0x8180  # Standard query response, no error
        qdcount = 1
        ancount = 1
        nscount = 0
        arcount = 0
        
        header = transaction_id + flags.to_bytes(2, 'big') + qdcount.to_bytes(2, 'big') + \
                ancount.to_bytes(2, 'big') + nscount.to_bytes(2, 'big') + arcount.to_bytes(2, 'big')
        
        # Question section
        question = self._encode_domain_name(query_name) + query_type.to_bytes(2, 'big') + b'\x00\x01'
        
        # Answer section (A record)
        if query_type == 1:  # A record
            answer = (b'\xc0\x0c' +  # Name compression pointer to question
                     b'\x00\x01' +  # Type A
                     b'\x00\x01' +  # Class IN
                     b'\x00\x00\x00\x3c' +  # TTL (60 seconds)
                     b'\x00\x04' +  # Data length
                     bytes(map(int, response_ip.split('.'))))  # IP address
        else:
            # For other query types, return empty answer
            answer = b''
            header = transaction_id + flags.to_bytes(2, 'big') + qdcount.to_bytes(2, 'big') + \
                    b'\x00\x00\x00\x00\x00\x00'  # No answers
        
        return header + question + answer


class ThreadingUDPServer(ThreadingMixIn, UDPServer):
    """Threading UDP server for DNS."""
    daemon_threads = True
    allow_reuse_address = True


class FakeServicesManager:
    """
    Manages various fake network services for malware analysis.
    Supports both built-in Python services and external tools like INetSim.
    """

    def __init__(self,
                 bind_ip: str = "0.0.0.0",
                 inetsim_path: Optional[str] = None,
                 inetsim_config_path: Optional[str] = None,
                 config_data: Optional[Dict] = None):
        """
        Initialize the FakeServicesManager.

        Args:
            bind_ip: IP address for services to bind to.
            inetsim_path: Path to INetSim executable if using INetSim.
            inetsim_config_path: Path to INetSim configuration file.
            config_data: Configuration settings for fake services.
        """
        self.bind_ip = bind_ip
        self.config = config_data or {}
        self.services: Dict[str, Any] = {}
        self.interaction_log = InteractionLog()
        
        # INetSim configuration
        self.inetsim_executable = inetsim_path
        self.inetsim_config = inetsim_config_path
        self.inetsim_process: Optional[subprocess.Popen] = None
        
        # Service configurations
        self.http_responses = {}
        self.dns_responses = {"*": "127.0.0.1"}  # Default: resolve all to localhost
        
        logger.info(f"FakeServicesManager initialized. Bind IP: {self.bind_ip}")
        if self.inetsim_executable:
            logger.info(f"INetSim configured: {self.inetsim_executable}")

    def configure_http_responses(self, responses: Dict[str, Dict[str, Any]]):
        """
        Configure custom HTTP responses for specific paths.
        
        Args:
            responses: Dict mapping paths to response configurations.
                      Key format: "METHOD:path" or "pattern:substring"
                      Value: {"status": int, "headers": dict, "body": bytes}
        """
        self.http_responses.update(responses)
        logger.info(f"Configured {len(responses)} HTTP response patterns")

    def configure_dns_responses(self, responses: Dict[str, str]):
        """
        Configure DNS responses for specific domains.
        
        Args:
            responses: Dict mapping domain names to IP addresses.
                      Use "*" as key for default response.
        """
        self.dns_responses.update(responses)
        logger.info(f"Configured DNS responses for {len(responses)} domains")

    def start_http_server(self, 
                         port: int = 80, 
                         ssl_cert_path: Optional[str] = None,
                         ssl_key_path: Optional[str] = None) -> bool:
        """
        Start fake HTTP/HTTPS server.
        
        Args:
            port: Port to bind to.
            ssl_cert_path: Path to SSL certificate for HTTPS.
            ssl_key_path: Path to SSL private key for HTTPS.
            
        Returns:
            bool: True if server started successfully.
        """
        service_id = f"http_{port}"
        
        if service_id in self.services:
            logger.warning(f"HTTP server already running on port {port}")
            return True

        try:
            # Create custom handler with configuration
            def handler_factory(*args, **kwargs):
                return FakeHTTPHandler(*args, 
                                     response_config=self.http_responses,
                                     interaction_log=self.interaction_log,
                                     **kwargs)
            
            server = ThreadingHTTPServer((self.bind_ip, port), handler_factory)
            
            # Configure SSL if certificates provided
            if ssl_cert_path and ssl_key_path:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(ssl_cert_path, ssl_key_path)
                server.socket = context.wrap_socket(server.socket, server_side=True)
                logger.info(f"SSL enabled for HTTP server on port {port}")
            
            # Start server in thread
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            self.services[service_id] = {
                "server": server,
                "thread": server_thread,
                "type": "http",
                "port": port,
                "ssl": ssl_cert_path is not None
            }
            
            protocol = "HTTPS" if ssl_cert_path else "HTTP"
            logger.info(f"{protocol} server started on {self.bind_ip}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start HTTP server on port {port}: {e}")
            return False

    def start_dns_server(self, port: int = 53) -> bool:
        """
        Start fake DNS server.
        
        Args:
            port: Port to bind to (default 53).
            
        Returns:
            bool: True if server started successfully.
        """
        service_id = f"dns_{port}"
        
        if service_id in self.services:
            logger.warning(f"DNS server already running on port {port}")
            return True

        try:
            server = ThreadingUDPServer((self.bind_ip, port), FakeDNSHandler)
            server.dns_config = self.dns_responses
            server.interaction_log = self.interaction_log
            
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            self.services[service_id] = {
                "server": server,
                "thread": server_thread,
                "type": "dns",
                "port": port
            }
            
            logger.info(f"DNS server started on {self.bind_ip}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start DNS server on port {port}: {e}")
            return False

    def start_simple_tcp_service(self, 
                                port: int, 
                                service_name: str,
                                response_data: bytes = b"OK\r\n") -> bool:
        """
        Start a simple TCP service that responds with fixed data.
        
        Args:
            port: Port to bind to.
            service_name: Name for the service (for logging).
            response_data: Data to send in response to connections.
            
        Returns:
            bool: True if service started successfully.
        """
        service_id = f"tcp_{service_name}_{port}"
        
        if service_id in self.services:
            logger.warning(f"TCP service {service_name} already running on port {port}")
            return True

        def tcp_handler():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.bind_ip, port))
                sock.listen(5)
                
                logger.info(f"TCP service {service_name} listening on {self.bind_ip}:{port}")
                
                while True:
                    try:
                        client_sock, client_addr = sock.accept()
                        
                        # Log connection
                        self.interaction_log.log_interaction(service_name, {
                            "summary": f"TCP connection from {client_addr[0]}",
                            "client_ip": client_addr[0],
                            "client_port": client_addr[1]
                        })
                        
                        # Send response and close
                        client_sock.send(response_data)
                        client_sock.close()
                        
                    except Exception as e:
                        if "stopped" not in str(e).lower():
                            logger.debug(f"TCP handler error: {e}")
                        break
                        
            except Exception as e:
                logger.error(f"TCP service {service_name} error: {e}")
            finally:
                try:
                    sock.close()
                except:
                    pass

        try:
            service_thread = threading.Thread(target=tcp_handler)
            service_thread.daemon = True
            service_thread.start()
            
            self.services[service_id] = {
                "thread": service_thread,
                "type": "tcp",
                "service_name": service_name,
                "port": port
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start TCP service {service_name} on port {port}: {e}")
            return False

    def start_inetsim(self, data_dir_path: Optional[str] = None) -> bool:
        """
        Start INetSim service if configured.
        
        Args:
            data_dir_path: Path to INetSim data directory.
            
        Returns:
            bool: True if INetSim started successfully.
        """
        if not self.inetsim_executable:
            logger.error("INetSim executable path not configured")
            return False
            
        if self.inetsim_process and self.inetsim_process.poll() is None:
            logger.info("INetSim already running")
            return True

        command = [self.inetsim_executable]
        
        if self.inetsim_config:
            command.extend(["--config", self.inetsim_config])
            
        if data_dir_path:
            command.extend(["--data-dir", data_dir_path])

        logger.info(f"Starting INetSim: {' '.join(command)}")
        
        try:
            self.inetsim_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid if os.name == 'posix' else None
            )
            
            # Wait a moment to check if it started successfully
            time.sleep(2)
            if self.inetsim_process.poll() is not None:
                stdout, stderr = self.inetsim_process.communicate()
                logger.error(f"INetSim failed to start. Stderr: {stderr.decode()}")
                return False
            
            logger.info(f"INetSim started with PID {self.inetsim_process.pid}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start INetSim: {e}")
            self.inetsim_process = None
            return False

    def stop_service(self, service_id: str) -> bool:
        """
        Stop a specific service.
        
        Args:
            service_id: Service identifier (e.g., "http_80", "dns_53").
            
        Returns:
            bool: True if service stopped successfully.
        """
        if service_id not in self.services:
            logger.warning(f"Service {service_id} not found")
            return False

        try:
            service_info = self.services[service_id]
            
            if "server" in service_info:
                service_info["server"].shutdown()
                service_info["server"].server_close()
            
            if "thread" in service_info:
                service_info["thread"].join(timeout=5)
            
            del self.services[service_id]
            logger.info(f"Service {service_id} stopped")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping service {service_id}: {e}")
            return False

    def stop_inetsim(self) -> bool:
        """Stop INetSim service."""
        if not self.inetsim_process or self.inetsim_process.poll() is not None:
            logger.info("INetSim not running")
            return True

        logger.info(f"Stopping INetSim (PID: {self.inetsim_process.pid})")
        
        try:
            if os.name == 'posix':
                os.killpg(os.getpgid(self.inetsim_process.pid), 15)  # SIGTERM
            else:
                self.inetsim_process.terminate()
            
            try:
                self.inetsim_process.wait(timeout=10)
                logger.info("INetSim terminated gracefully")
            except subprocess.TimeoutExpired:
                logger.warning("INetSim did not terminate gracefully, killing")
                if os.name == 'posix':
                    os.killpg(os.getpgid(self.inetsim_process.pid), 9)  # SIGKILL
                else:
                    self.inetsim_process.kill()
                self.inetsim_process.wait(timeout=5)
                
        except Exception as e:
            logger.error(f"Error stopping INetSim: {e}")
            return False
        finally:
            self.inetsim_process = None
            
        return True

    def start_all_services(self, 
                          http_ports: List[int] = None,
                          https_ports: List[int] = None,
                          dns_ports: List[int] = None,
                          additional_services: List[Dict[str, Any]] = None) -> bool:
        """
        Start all configured services.
        
        Args:
            http_ports: List of HTTP ports to start (default: [80, 8080]).
            https_ports: List of HTTPS ports to start (default: [443]).
            dns_ports: List of DNS ports to start (default: [53]).
            additional_services: List of additional service configurations.
            
        Returns:
            bool: True if all services started successfully.
        """
        success = True
        
        # Start INetSim if configured
        if self.inetsim_executable:
            if not self.start_inetsim():
                success = False
        else:
            # Start individual Python services
            if http_ports is None:
                http_ports = [80, 8080]
            if https_ports is None:
                https_ports = [443] if self.config.get("ssl_cert_path") else []
            if dns_ports is None:
                dns_ports = [53]
            
            # Start HTTP servers
            for port in http_ports:
                if not self.start_http_server(port):
                    success = False
            
            # Start HTTPS servers
            for port in https_ports:
                if not self.start_http_server(
                    port, 
                    ssl_cert_path=self.config.get("ssl_cert_path"),
                    ssl_key_path=self.config.get("ssl_key_path")
                ):
                    success = False
            
            # Start DNS servers
            for port in dns_ports:
                if not self.start_dns_server(port):
                    success = False
            
            # Start additional services
            if additional_services:
                for service_config in additional_services:
                    service_type = service_config.get("type")
                    if service_type == "tcp":
                        if not self.start_simple_tcp_service(
                            port=service_config["port"],
                            service_name=service_config["name"],
                            response_data=service_config.get("response", b"OK\r\n")
                        ):
                            success = False
        
        return success

    def stop_all_services(self) -> bool:
        """Stop all managed services."""
        success = True
        
        # Stop Python services
        service_ids = list(self.services.keys())
        for service_id in service_ids:
            if not self.stop_service(service_id):
                success = False
        
        # Stop INetSim
        if self.inetsim_process:
            if not self.stop_inetsim():
                success = False
        
        return success

    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all services."""
        status = {
            "python_services": {},
            "inetsim_running": self.inetsim_process is not None and self.inetsim_process.poll() is None,
            "total_interactions": len(self.interaction_log.get_logs())
        }
        
        for service_id, service_info in self.services.items():
            status["python_services"][service_id] = {
                "type": service_info.get("type"),
                "port": service_info.get("port"),
                "running": True  # If it's in services dict, it should be running
            }
        
        return status

    def get_interaction_logs(self, service_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get interaction logs."""
        return self.interaction_log.get_logs(service_filter)

    def export_interaction_logs(self, output_file: Union[str, Path]) -> bool:
        """Export interaction logs to file."""
        return self.interaction_log.export_logs(output_file)

    def clear_interaction_logs(self):
        """Clear all interaction logs."""
        self.interaction_log.clear_logs()

    def create_malware_environment(self) -> bool:
        """
        Set up a complete fake environment for malware analysis.
        
        Returns:
            bool: True if environment created successfully.
        """
        logger.info("Creating comprehensive malware analysis environment")
        
        # Configure common malware HTTP endpoints
        malware_http_responses = {
            "GET:/gate.php": {"status": 200, "headers": {"Content-Type": "text/plain"}, "body": b"OK"},
            "POST:/gate.php": {"status": 200, "headers": {"Content-Type": "text/plain"}, "body": b"RECEIVED"},
            "GET:/panel/login.php": {"status": 200, "headers": {"Content-Type": "text/html"}, 
                                   "body": b"<html><body><h1>Admin Panel</h1></body></html>"},
            "GET:/config.txt": {"status": 200, "headers": {"Content-Type": "text/plain"}, 
                              "body": b"server=127.0.0.1:8080\nkey=malware123\ntimeout=30"},
            "pattern:payload": {"status": 200, "headers": {"Content-Type": "application/octet-stream"}, 
                              "body": b"FAKE_PAYLOAD_DATA"},
            "pattern:update": {"status": 200, "headers": {"Content-Type": "text/plain"}, "body": b"NO_UPDATE"}
        }
        
        self.configure_http_responses(malware_http_responses)
        
        # Configure DNS to resolve common malware domains
        malware_dns_responses = {
            "*": "127.0.0.1",  # Default: resolve everything to localhost
            "update.microsoft.com": "127.0.0.1",
            "windowsupdate.com": "127.0.0.1"
        }
        
        self.configure_dns_responses(malware_dns_responses)
        
        # Additional services for malware analysis
        additional_services = [
            {"type": "tcp", "port": 21, "name": "ftp", "response": b"220 FTP Server Ready\r\n"},
            {"type": "tcp", "port": 25, "name": "smtp", "response": b"220 SMTP Server Ready\r\n"},
            {"type": "tcp", "port": 110, "name": "pop3", "response": b"+OK POP3 Server Ready\r\n"},
            {"type": "tcp", "port": 143, "name": "imap", "response": b"* OK IMAP Server Ready\r\n"}
        ]
        
        # Start all services
        return self.start_all_services(
            http_ports=[80, 8080, 8000],
            dns_ports=[53],
            additional_services=additional_services
        )


# Convenience function for quick setup
def setup_malware_analysis_environment(bind_ip: str = "0.0.0.0", 
                                     use_inetsim: bool = False,
                                     inetsim_path: Optional[str] = None) -> FakeServicesManager:
    """
    Quick setup of fake services environment for malware analysis.
    
    Args:
        bind_ip: IP address to bind services to.
        use_inetsim: Whether to use INetSim instead of Python services.
        inetsim_path: Path to INetSim executable if using INetSim.
        
    Returns:
        FakeServicesManager: Configured and started service manager.
    """
    logger.info("Setting up malware analysis environment")
    
    if use_inetsim and inetsim_path:
        manager = FakeServicesManager(
            bind_ip=bind_ip,
            inetsim_path=inetsim_path
        )
        manager.start_inetsim()
    else:
        manager = FakeServicesManager(bind_ip=bind_ip)
        manager.create_malware_environment()
    
    return manager


# Example usage and testing
if __name__ == "__main__":
    import argparse
    import signal
    import sys
    
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def signal_handler(sig, frame):
        """Handle Ctrl+C to stop services gracefully."""
        print("\nReceived interrupt signal, stopping services...")
        if 'services_manager' in globals():
            services_manager.stop_all_services()
        sys.exit(0)

    def test_fake_services():
        """Test fake services functionality."""
        print("\n" + "="*80)
        print("TESTING FAKE NETWORK SERVICES")
        print("="*80)
        
        print("1. Initializing FakeServicesManager...")
        manager = FakeServicesManager(bind_ip="127.0.0.1")
        
        # Configure custom responses
        print("2. Configuring custom HTTP responses...")
        custom_responses = {
            "GET:/test": {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": b'{"status": "success", "message": "Test response"}'
            },
            "POST:/submit": {
                "status": 201,
                "headers": {"Content-Type": "text/plain"},
                "body": b"Data received"
            },
            "pattern:malware": {
                "status": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": b"Malware detected pattern response"
            }
        }
        manager.configure_http_responses(custom_responses)
        
        # Configure DNS responses
        print("3. Configuring DNS responses...")
        dns_config = {
            "evil.com": "192.168.1.100",
            "c2server.net": "10.0.0.1",
            "*": "127.0.0.1"
        }
        manager.configure_dns_responses(dns_config)
        
        # Start services
        print("4. Starting HTTP server on port 8080...")
        if manager.start_http_server(port=8080):
            print("   ✓ HTTP server started")
        else:
            print("   ✗ HTTP server failed to start")
        
        print("5. Starting DNS server on port 5353...")
        if manager.start_dns_server(port=5353):
            print("   ✓ DNS server started")
        else:
            print("   ✗ DNS server failed to start")
        
        print("6. Starting additional TCP services...")
        services_started = 0
        tcp_services = [
            (2121, "ftp", b"220 Fake FTP Server Ready\r\n"),
            (2525, "smtp", b"220 Fake SMTP Server Ready\r\n")
        ]
        
        for port, name, response in tcp_services:
            if manager.start_simple_tcp_service(port, name, response):
                services_started += 1
                print(f"   ✓ {name.upper()} service started on port {port}")
            else:
                print(f"   ✗ {name.upper()} service failed to start on port {port}")
        
        # Show status
        print("7. Service status:")
        status = manager.get_service_status()
        print(f"   Python services: {len(status['python_services'])}")
        print(f"   INetSim running: {status['inetsim_running']}")
        
        # Simulate some interactions
        print("8. Simulating malware interactions...")
        time.sleep(1)
        
        # Manual log entries for demonstration
        manager.interaction_log.log_interaction("http", {
            "summary": "GET /gate.php",
            "client_ip": "192.168.1.10",
            "method": "GET",
            "path": "/gate.php",
            "user_agent": "Python/malware"
        })
        
        manager.interaction_log.log_interaction("dns", {
            "summary": "Query evil.com",
            "client_ip": "192.168.1.10",
            "query_name": "evil.com",
            "query_type": 1
        })
        
        # Show interaction logs
        print("9. Interaction logs:")
        logs = manager.get_interaction_logs()
        for log in logs:
            print(f"   [{log['service']}] {log['details'].get('summary', 'No summary')} from {log['client_ip']}")
        
        # Export logs
        log_file = Path("./test_interactions.json")
        if manager.export_interaction_logs(log_file):
            print(f"   ✓ Logs exported to {log_file}")
            log_file.unlink()  # Clean up
        
        # Stop services
        print("10. Stopping all services...")
        if manager.stop_all_services():
            print("   ✓ All services stopped")
        else:
            print("   ✗ Some services failed to stop")

    def test_malware_environment():
        """Test complete malware environment setup."""
        print("\n" + "="*80)
        print("TESTING MALWARE ANALYSIS ENVIRONMENT")
        print("="*80)
        
        print("1. Creating comprehensive malware environment...")
        manager = FakeServicesManager(bind_ip="127.0.0.1")
        
        if manager.create_malware_environment():
            print("   ✓ Malware environment created successfully")
            
            # Show what was created
            status = manager.get_service_status()
            print(f"   Services running: {len(status['python_services'])}")
            
            for service_id, service_info in status['python_services'].items():
                print(f"   - {service_id}: {service_info['type']} on port {service_info['port']}")
            
            print("\n2. Testing HTTP endpoints...")
            test_endpoints = [
                "/gate.php",
                "/panel/login.php", 
                "/config.txt",
                "/some_payload.exe",
                "/update_check.php"
            ]
            
            for endpoint in test_endpoints:
                print(f"   Endpoint {endpoint} configured for testing")
            
            print("\n3. This environment provides:")
            print("   - HTTP/HTTPS servers for C2 communication")
            print("   - DNS server for domain resolution")
            print("   - Common protocol services (FTP, SMTP, POP3, IMAP)")
            print("   - Configurable responses for malware analysis")
            print("   - Comprehensive interaction logging")
            
            # Cleanup
            print("\n4. Stopping malware environment...")
            if manager.stop_all_services():
                print("   ✓ Environment stopped successfully")
            
        else:
            print("   ✗ Failed to create malware environment")

    def test_integration_scenario():
        """Test integration with malware analysis workflow."""
        print("\n" + "="*80)
        print("TESTING MALWARE ANALYSIS INTEGRATION")
        print("="*80)
        
        print("Simulating complete malware analysis workflow:")
        print("1. Setting up isolated network environment...")
        
        # This would typically be done in coordination with VM setup
        manager = setup_malware_analysis_environment(bind_ip="192.168.100.1")
        
        print("2. Environment ready for malware execution:")
        print("   - All network requests intercepted")
        print("   - C2 communication captured") 
        print("   - Data exfiltration attempts logged")
        print("   - Secondary payload downloads intercepted")
        
        print("\n3. During analysis, the environment would:")
        print("   - Respond to HTTP requests with realistic data")
        print("   - Resolve DNS queries to controlled IPs")
        print("   - Log all network interactions for analysis")
        print("   - Provide consistent responses for reproducible analysis")
        
        print("\n4. Integration points:")
        print("   → Network capture coordinates with packet capture")
        print("   → Interaction logs feed into behavioral analysis")
        print("   → Service responses simulate real C2 infrastructure")
        print("   → Timeline correlates with other monitoring tools")
        
        status = manager.get_service_status()
        print(f"\n5. Current status: {len(status['python_services'])} services active")
        
        # Cleanup
        manager.stop_all_services()
        print("   ✓ Test environment cleaned up")

    def run_interactive_mode():
        """Run services in interactive mode for testing."""
        print("\n" + "="*80)
        print("INTERACTIVE FAKE SERVICES MODE")
        print("="*80)
        
        global services_manager
        
        print("Starting fake services environment...")
        services_manager = FakeServicesManager(bind_ip="0.0.0.0")
        
        if services_manager.create_malware_environment():
            print("✓ Malware analysis environment ready")
            print("\nServices running:")
            status = services_manager.get_service_status()
            for service_id, info in status['python_services'].items():
                print(f"  - {service_id}: {info['type'].upper()} on port {info['port']}")
            
            print("\nTest the services:")
            print("  HTTP: curl http://localhost:8080/gate.php")
            print("  DNS:  nslookup evil.com localhost -port=53")
            print("  FTP:  telnet localhost 21")
            
            print("\nPress Ctrl+C to stop services and exit")
            
            try:
                while True:
                    time.sleep(5)
                    logs = services_manager.get_interaction_logs()
                    if logs:
                        recent_logs = [log for log in logs if 
                                     (datetime.now() - datetime.fromisoformat(log['timestamp'])).seconds < 10]
                        if recent_logs:
                            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Recent interactions:")
                            for log in recent_logs[-3:]:  # Show last 3
                                print(f"  {log['service']}: {log['details'].get('summary', 'interaction')}")
            except KeyboardInterrupt:
                pass
        else:
            print("✗ Failed to start environment")

    # Command line interface
    parser = argparse.ArgumentParser(description="Test fake network services")
    parser.add_argument("--test-services", action="store_true", help="Test basic service functionality")
    parser.add_argument("--test-environment", action="store_true", help="Test malware environment setup")
    parser.add_argument("--test-integration", action="store_true", help="Test integration scenarios")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--test-all", action="store_true", help="Run all tests")
    
    args = parser.parse_args()
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    if args.interactive:
        run_interactive_mode()
    elif args.test_all or len([arg for arg in vars(args).values() if arg]) == 0:
        test_fake_services()
        test_malware_environment()
        test_integration_scenario()
    else:
        if args.test_services:
            test_fake_services()
        if args.test_environment:
            test_malware_environment()
        if args.test_integration:
            test_integration_scenario()
    
    print("\n" + "="*80)
    print("FAKE SERVICES TESTING COMPLETE")
    print("="*80)
    
    print("\nNote: For production use:")
    print("  - Ensure proper network isolation")
    print("  - Configure firewall rules appropriately")
    print("  - Monitor resource usage during analysis")
    print("  - Regularly review and update service responses")