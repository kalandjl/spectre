from colorama import init, Fore, Style
from datetime import datetime

def print_banner():
    """Print ASCII banner"""
    banner = f"""{Fore.CYAN}
╔═╗╔═╗╔═╗╔═╗╔╦╗╦═╗╔═╗
╚═╗╠═╝║╣ ║   ║ ╠╦╝║╣ 
╚═╝╩  ╚═╝╚═╝ ╩ ╩╚═╚═╝
{Fore.WHITE}Network Vulnerability Scanner
{Style.RESET_ALL}"""
    print(banner)


def validate_target(target):
    """Basic target validation"""
    # Add validation logic here
    return True

def generate_output_filename(format='csv'):
    """Generate default output filename with timestamp"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"scan_{timestamp}.{format}"