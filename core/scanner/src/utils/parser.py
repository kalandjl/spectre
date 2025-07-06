import json
import csv
from typing import List, Dict
import os
from datetime import datetime

def save_as_json(results: List[Dict], outDir: str) -> None:
    """Save scan results as JSON file"""
    # Ensure .json extension
    if not outDir.endswith('.json'):
        outDir += '.json'
    
    print(f"[PARSER] Saving results file as {outDir}")
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(outDir), exist_ok=True) if os.path.dirname(outDir) else None
        
        # Prepare data with metadata
        output_data = {
            'scan_metadata': {
                'total_hosts': len(set(r['target_ip'] for r in results)),
                'total_services': len(results),
                'scan_date': datetime.now().isoformat(),
                'scan_id': results[0]['scan_id'] if results else 'unknown'
            },
            'results': results
        }
        
        # Write JSON file
        with open(outDir, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        print(f"[PARSER] Successfully saved {outDir}")
        
    except Exception as e:
        print(f"[ERROR] Failed to save JSON: {e}")
        raise

def save_as_csv(results: List[Dict], outDir: str) -> None:
    """Save scan results as CSV file"""
    # Ensure .csv extension
    if not outDir.endswith('.csv'):
        outDir += '.csv'
    
    print(f"[PARSER] Saving results file as {outDir}")
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(outDir), exist_ok=True) if os.path.dirname(outDir) else None
        
        if not results:
            print("[WARNING] No results to save")
            # Create empty CSV with headers
            with open(outDir, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'scan_id', 'target_ip', 'hostname', 
                               'port', 'protocol', 'service', 'version', 'product', 'os_guess'])
            return
        
        # Define CSV columns (order matters for upload)
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
        
        # Write CSV file
        with open(outDir, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(results)
        
        print(f"[PARSER] Successfully saved {outDir}")  # Fixed: was showing .json
        
    except Exception as e:
        print(f"[ERROR] Failed to save CSV: {e}")
        raise

# Additional utility functions

def validate_results(results: List[Dict]) -> bool:
    """Validate results before saving"""
    if not results:
        return True  # Empty results are valid
    
    required_fields = ['target_ip', 'port', 'service']
    for result in results:
        if not all(field in result for field in required_fields):
            return False
    return True

def get_summary_stats(results: List[Dict]) -> Dict:
    """Get summary statistics from results"""
    if not results:
        return {
            'total_hosts': 0,
            'total_services': 0,
            'open_ports': []
        }
    
    unique_hosts = set(r['target_ip'] for r in results)
    unique_ports = set(r['port'] for r in results)
    service_counts = {}
    
    for r in results:
        service = r.get('service', 'unknown')
        service_counts[service] = service_counts.get(service, 0) + 1
    
    return {
        'total_hosts': len(unique_hosts),
        'total_services': len(results),
        'unique_ports': sorted(list(unique_ports)),
        'top_services': sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    }

def print_summary(results: List[Dict]) -> None:
    """Print scan summary to console"""
    stats = get_summary_stats(results)
    
    print(f"\n[SUMMARY] Scan Results:")
    print(f"  • Hosts found: {stats['total_hosts']}")
    print(f"  • Services found: {stats['total_services']}")
    if stats['top_services']:
        print(f"  • Top services:")
        for service, count in stats['top_services']:
            print(f"    - {service}: {count}")