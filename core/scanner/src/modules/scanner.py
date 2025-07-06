import time
import subprocess
import xml.etree.ElementTree as ET
import json
from typing import Dict, List, Optional
import re
from datetime import datetime

class NetworkScanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def _log(self, message: str, level: str = "INFO"):
        """Print log messages if verbose mode is enabled"""
        if self.verbose:
            print(f"[{level}] {message}")
    
    def _run_nmap(self, target: str, ports: str, additional_args: List[str] = None) -> Dict:
        """Execute nmap and return parsed results"""
        # Build nmap command
        cmd = ["nmap", "-oX", "-", "-sV"]  # -oX - outputs XML to stdout, -sV for version detection
        
        if ports and ports != "top1000":
            cmd.extend(["-p", ports])
        
        if additional_args:
            cmd.extend(additional_args)
            
        cmd.append(target)
        
        self._log(f"Running command: {' '.join(cmd)}")
        
        try:
            # Run nmap
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                raise Exception(f"Nmap failed: {result.stderr}")
            
            # Parse XML output
            return self._parse_nmap_xml(result.stdout)
            
        except subprocess.TimeoutExpired:
            raise Exception("Scan timeout exceeded")
        except Exception as e:
            raise Exception(f"Scan failed: {str(e)}")
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict:
        """Parse nmap XML output into structured data"""
        try:
            root = ET.fromstring(xml_output)
            results = {
                'scan_info': {},
                'hosts': []
            }
            
            # Get scan info
            scan_info = root.find('.//scaninfo')
            if scan_info is not None:
                results['scan_info'] = {
                    'type': scan_info.get('type', ''),
                    'protocol': scan_info.get('protocol', ''),
                    'services': scan_info.get('services', '')
                }
            
            # Parse each host
            for host in root.findall('.//host'):
                host_data = self._parse_host(host)
                if host_data:
                    results['hosts'].append(host_data)
            
            return results
            
        except ET.ParseError as e:
            # Fallback to basic text parsing if XML fails
            return self._parse_nmap_text(xml_output)
    
    def _parse_host(self, host_elem) -> Optional[Dict]:
        """Parse individual host from XML"""
        host_data = {
            'ip': '',
            'hostname': '',
            'state': '',
            'ports': []
        }
        
        # Get IP address
        addr = host_elem.find('.//address[@addrtype="ipv4"]')
        if addr is not None:
            host_data['ip'] = addr.get('addr', '')
        
        # Get hostname
        hostname = host_elem.find('.//hostname')
        if hostname is not None:
            host_data['hostname'] = hostname.get('name', '')
        
        # Get host state
        status = host_elem.find('.//status')
        if status is not None:
            host_data['state'] = status.get('state', '')
        
        # Get OS guess
        os_match = host_elem.find('.//osmatch')
        if os_match is not None:
            host_data['os_guess'] = os_match.get('name', '')
        
        # Parse ports
        for port in host_elem.findall('.//port'):
            port_data = self._parse_port(port)
            if port_data:
                host_data['ports'].append(port_data)
        
        return host_data if host_data['ip'] else None
    
    def _parse_port(self, port_elem) -> Optional[Dict]:
        """Parse individual port from XML"""
        port_data = {
            'port': port_elem.get('portid', ''),
            'protocol': port_elem.get('protocol', ''),
            'state': '',
            'service': '',
            'version': '',
            'product': ''
        }
        
        # Get port state
        state = port_elem.find('.//state')
        if state is not None:
            port_data['state'] = state.get('state', '')
        
        # Get service info
        service = port_elem.find('.//service')
        if service is not None:
            port_data['service'] = service.get('name', '')
            port_data['product'] = service.get('product', '')
            port_data['version'] = service.get('version', '')
        
        return port_data if port_data['state'] == 'open' else None
    
    def _parse_nmap_text(self, text_output: str) -> Dict:
        """Fallback text parser for nmap output"""
        results = {'hosts': []}
        current_host = None
        
        for line in text_output.split('\n'):
            # Match IP address
            ip_match = re.match(r'Nmap scan report for (.+?)( \((.+?)\))?$', line)
            if ip_match:
                if current_host and current_host['ports']:
                    results['hosts'].append(current_host)
                
                current_host = {
                    'ip': ip_match.group(3) if ip_match.group(3) else ip_match.group(1),
                    'hostname': ip_match.group(1) if ip_match.group(3) else '',
                    'ports': []
                }
            
            # Match open ports
            port_match = re.match(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$', line)
            if port_match and current_host:
                port_info = {
                    'port': port_match.group(1),
                    'protocol': port_match.group(2),
                    'state': 'open',
                    'service': port_match.group(3),
                    'version': port_match.group(4).strip() if port_match.group(4) else ''
                }
                current_host['ports'].append(port_info)
        
        # Don't forget the last host
        if current_host and current_host['ports']:
            results['hosts'].append(current_host)
        
        return results
    
    def scan(self, target: str, ports: str = "1-1000", timeout: int = 300, rate_limit: int = 1000) -> List[Dict]:
        """Main scan method that returns list of services found"""
        self._log(f"Starting scan of {target} on ports {ports}")
        
        # Run the scan
        scan_results = self._run_nmap(target, ports)
        
        # Convert to flat list format for CSV output
        results = []
        for host in scan_results.get('hosts', []):
            for port in host.get('ports', []):
                result = {
                    'timestamp': datetime.now().isoformat(),
                    'scan_id': self.scan_id,
                    'target_ip': host.get('ip', ''),
                    'hostname': host.get('hostname', ''),
                    'port': port.get('port', ''),
                    'protocol': port.get('protocol', ''),
                    'service': port.get('service', ''),
                    'version': port.get('version', ''),
                    'product': port.get('product', ''),
                    'os_guess': host.get('os_guess', '')
                }
                results.append(result)
                
                self._log(f"Found: {result['target_ip']}:{result['port']} - {result['service']} {result['version']}")
        
        self._log(f"Scan completed. Found {len(results)} services on {len(scan_results.get('hosts', []))} hosts")
        
        return results
    
    def scan_network(self, cidr: str) -> List[Dict]:
        """Scan entire network range"""
        return self.scan(cidr, ports="1-1000")
    
    def quick_scan(self, target: str) -> List[Dict]:
        """Quick scan of most common ports"""
        common_ports = "21,22,23,25,80,110,139,443,445,3306,3389,8080,8443"
        return self.scan(target, ports=common_ports)