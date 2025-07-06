import ipaddress

def validate_target(target: str) -> bool:
    """Validate IP, CIDR, or hostname"""
    # Try CIDR notation
    try:
        network = ipaddress.ip_network(target, strict=False)
        # Warn about large networks
        if network.num_addresses > 1024:
            print(f"[WARNING] Large network: {network.num_addresses} addresses. This may take a while.")
        return True
    except ValueError:
        pass
    
    # Try single IP
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Assume hostname if it looks valid
    if re.match(r'^[a-zA-Z0-9.-]+$', target):
        return True
    
    return False

def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR to list of IPs (for custom scanning)"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]  # .hosts() excludes network/broadcast
    except:
        return []