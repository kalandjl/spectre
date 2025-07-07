import time
import subprocess
import xml.etree.ElementTree as ET
import json
from typing import Dict, List, Optional
import re
from datetime import datetime
from tqdm import tqdm
from sshkey_tools.keys import RsaPrivateKey

class NetworkScanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.scan_start = None
        self.scan_end = None
    
    def _log(self, message: str, level: str = "INFO"):
        """Print log messages if verbose mode is enabled"""
        if self.verbose:
            print(f"[{level}] {message}")
    
    import subprocess

    def _run_nmap(self, target: str, ports: str, additional_args=None):
        cmd = [
            "sudo", "nmap", "-sV", "-O",
            "--stats-every", "1s",
            "-oX", "-",
            target
        ]

        taskprogress_re = re.compile(r'<taskprogress.*?percent="([\d\.]+)".*?/>')

        xml_started = False
        xml_lines = []
        pbar = tqdm(total=100, desc="Nmap Progress", unit="%")
        last_percent = 0

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        try:
            for line in proc.stdout:
                line = line.strip()
                i = line.find("percent=")

                if i>1: 
                    percent = float(line[i+9:i+13])
                    increment = percent - last_percent
                    if increment > 0:
                        pbar.update(increment)
                        last_percent = percent
                    elif line.find("Parallel DNS resolution of"):
                        pbar.update(increment)
                        last_percent = percent


                # Detect start of main XML document
                if line.startswith("<nmaprun"):
                    xml_started = True

                # Collect XML output lines (including <taskprogress> lines after xml_started)
                if xml_started:
                    xml_lines.append(line)

            proc.wait()
        finally:
            pbar.close()

        xml_output = "\n".join(xml_lines)
        return self._parse_nmap_xml(xml_output)

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
        
        if current_host and current_host['ports']:
            results['hosts'].append(current_host)
        
        return results
    
    def scan(self, target: str, ports: str = "1-1000", timeout: int = 300, rate_limit: int = 1000) -> List[Dict]:
        """Main scan method that returns list of services found"""

        self.scan_id = rsa_priv = RsaPrivateKey.generate().to_string()
        self.scan_start = datetime.now()
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
        
        
        self.scan_end = datetime.now()
        self._log(f"Scan completed in {(self.scan_end - self.scan_start).total_seconds():.1f}s")
        self._log(f"Found {len(results)} services on {len(scan_results.get('hosts', []))} hosts")
        
        return results