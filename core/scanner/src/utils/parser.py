# modules/parser.py
import json
import csv
from typing import List, Dict, Any
import os
from datetime import datetime

class OutputFormatter:
    """Handles all output formatting for scan results"""
    
    def __init__(self):
        self.metadata = {}
    
    def set_metadata(self, scan_start: datetime, scan_end: datetime, 
                     target: str, total_hosts: int, total_services: int):
        """Set scan metadata for inclusion in output"""
        duration = (scan_end - scan_start).total_seconds()
        self.metadata = {
            'scan_id': scan_start.strftime('%Y%m%d_%H%M%S'),
            'target': target,
            'start_time': scan_start.isoformat(),
            'end_time': scan_end.isoformat(),
            'duration_seconds': round(duration, 2),
            'duration_human': self._format_duration(duration),
            'total_hosts_scanned': total_hosts,
            'total_services_found': total_services,
            'scan_date': scan_start.strftime('%Y-%m-%d'),
            'scan_time': scan_start.strftime('%H:%M:%S')
        }
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def save_as_csv(self, results: List[Dict], filepath: str) -> None:
        """
        Save scan results as CSV with proper formatting
        Expected columns: timestamp,scan_id,target_ip,hostname,port,protocol,service,version,product,os_guess
        """
        # Ensure .csv extension
        if not filepath.endswith('.csv'):
            filepath += '.csv'
        
        print(f"[PARSER] Saving results to {filepath}")
        
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(filepath), exist_ok=True) if os.path.dirname(filepath) else None
            
            # Define fieldnames in exact order
            fieldnames = [
                'timestamp',
                'scan_id',
                'target_ip',
                'hostname',
                'port',
                'protocol',
                'service',
                'version',
                'product',
                'os_guess'
            ]
            
            # Ensure all results have all fields (fill missing with empty strings)
            formatted_results = []
            for result in results:
                formatted_result = {field: result.get(field, '') for field in fieldnames}
                formatted_results.append(formatted_result)
            
            # Write CSV
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(formatted_results)
            
            # Write metadata file
            metadata_file = filepath.replace('.csv', '_metadata.json')
            with open(metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
            
            print(f"[PARSER] Successfully saved {len(results)} results to {filepath}")
            print(f"[PARSER] Metadata saved to {metadata_file}")
            
        except Exception as e:
            print(f"[ERROR] Failed to save CSV: {e}")
            raise
    
    def save_as_json(self, results: List[Dict], filepath: str) -> None:
        """Save scan results as JSON with metadata included"""
        # Ensure .json extension
        if not filepath.endswith('.json'):
            filepath += '.json'
        
        print(f"[PARSER] Saving results to {filepath}")
        
        try:
            # Create directory if needed
            os.makedirs(os.path.dirname(filepath), exist_ok=True) if os.path.dirname(filepath) else None
            
            # Structure output with metadata
            output = {
                'metadata': self.metadata,
                'summary': self._generate_summary(results),
                'results': results
            }
            
            # Write JSON with proper formatting
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"[PARSER] Successfully saved {len(results)} results to {filepath}")
            
        except Exception as e:
            print(f"[ERROR] Failed to save JSON: {e}")
            raise
    
    def _generate_summary(self, results: List[Dict]) -> Dict:
        """Generate summary statistics from results"""
        if not results:
            return {
                'total_services': 0,
                'unique_hosts': 0,
                'open_ports': [],
                'services_breakdown': {},
                'top_ports': []
            }
        
        # Calculate statistics
        unique_hosts = set(r.get('target_ip', '') for r in results)
        port_counts = {}
        service_counts = {}
        
        for r in results:
            # Count ports
            port = r.get('port', '')
            if port:
                port_counts[port] = port_counts.get(port, 0) + 1
            
            # Count services
            service = r.get('service', 'unknown')
            if service:
                service_counts[service] = service_counts.get(service, 0) + 1
        
        # Get top 10 ports
        top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_services': len(results),
            'unique_hosts': len(unique_hosts),
            'open_ports': sorted(list(port_counts.keys())),
            'services_breakdown': service_counts,
            'top_ports': [{'port': p[0], 'count': p[1]} for p in top_ports]
        }
    
    def print_summary(self, results: List[Dict]) -> None:
        """Print formatted summary to console"""
        summary = self._generate_summary(results)
        
        print(f"\n{'='*50}")
        print(f"SCAN SUMMARY")
        print(f"{'='*50}")
        print(f"Target: {self.metadata.get('target', 'N/A')}")
        print(f"Duration: {self.metadata.get('duration_human', 'N/A')}")
        print(f"Hosts found: {summary['unique_hosts']}")
        print(f"Services found: {summary['total_services']}")
        
        if summary['top_ports']:
            print(f"\nTop Open Ports:")
            for port_info in summary['top_ports'][:5]:
                print(f"  - Port {port_info['port']}: {port_info['count']} hosts")
        
        if summary['services_breakdown']:
            print(f"\nServices Detected:")
            for service, count in sorted(summary['services_breakdown'].items(), 
                                       key=lambda x: x[1], reverse=True)[:5]:
                print(f"  - {service}: {count}")
        
        print(f"{'='*50}\n")

# Convenience functions for backward compatibility
def save_as_csv(results: List[Dict], filepath: str) -> None:
    """Legacy function - creates formatter and saves"""
    formatter = OutputFormatter()
    formatter.save_as_csv(results, filepath)

def save_as_json(results: List[Dict], filepath: str) -> None:
    """Legacy function - creates formatter and saves"""
    formatter = OutputFormatter()
    formatter.save_as_json(results, filepath)