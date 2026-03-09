#!/usr/bin/env python3
"""
Responder Trigger - Protocol Hash Capture Provocateur
Sends fake solicitations to various protocols that Responder can intercept to capture hashes.
Useful for testing Responder setup or triggering NTLM authentication in a lab.
"""
import socket
import struct
import argparse
import sys
import time
import threading
import random
import string
from datetime import datetime

# ANSI colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def log_info(msg):
    print(f"{Colors.BLUE}[*]{Colors.ENDC} {msg}")

def log_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.ENDC} {msg}")

def log_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.ENDC} {msg}")

def log_error(msg):
    print(f"{Colors.RED}[-]{Colors.ENDC} {msg}")

def log_section(msg):
    print(f"\n{Colors.CYAN}{Colors.BOLD}[>] {msg}{Colors.ENDC}")

def random_name(length=8):
    """Generate random NetBIOS-compatible name."""
    return ''.join(random.choices(string.ascii_uppercase, k=length))

# ==================== LLMNR (Link-Local Multicast Name Resolution) ====================
def send_llmnr_query(name, target=None, count=1):
    """
    Send LLMNR query to trigger Responder.
    LLMNR uses UDP port 5355, multicast address 224.0.0.252
    """
    log_section("LLMNR Query (UDP 5355)")
    
    LLMNR_MULTICAST = "224.0.0.252"
    LLMNR_PORT = 5355
    
    # LLMNR packet structure (similar to DNS)
    transaction_id = random.randint(0, 65535)
    flags = 0x0000  # Standard query
    questions = 1
    answers = 0
    authority = 0
    additional = 0
    
    # Encode name (DNS-style length-prefixed labels)
    encoded_name = b""
    for part in name.split('.'):
        encoded_name += bytes([len(part)]) + part.encode('utf-8')
    encoded_name += b'\x00'  # End of name
    
    qtype = 1  # A record
    qclass = 1  # IN class
    
    packet = struct.pack(">HHHHHH", transaction_id, flags, questions, answers, authority, additional)
    packet += encoded_name
    packet += struct.pack(">HH", qtype, qclass)
    
    dest = target if target else LLMNR_MULTICAST
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)
        
        for i in range(count):
            query_name = name if name else random_name()
            log_info(f"Sending LLMNR query for '{query_name}' to {dest}:{LLMNR_PORT}")
            sock.sendto(packet, (dest, LLMNR_PORT))
            time.sleep(0.5)
        
        sock.close()
        log_success(f"LLMNR queries sent ({count}x)")
        return True
    except Exception as e:
        log_error(f"LLMNR failed: {e}")
        return False

# ==================== NBT-NS (NetBIOS Name Service) ====================
def send_nbtns_query(name, target=None, count=1):
    """
    Send NBT-NS query to trigger Responder.
    NBT-NS uses UDP port 137, broadcast or unicast.
    """
    log_section("NBT-NS Query (UDP 137)")
    
    NBTNS_PORT = 137
    NBTNS_BROADCAST = "255.255.255.255"
    
    def encode_netbios_name(name):
        """Encode name in NetBIOS First-Level encoding."""
        # Pad to 16 chars (15 name + 1 suffix)
        padded = name.upper().ljust(15)[:15] + '\x00'  # 0x00 suffix = workstation
        encoded = b''
        for char in padded:
            byte = ord(char)
            encoded += bytes([((byte >> 4) & 0x0F) + ord('A')])
            encoded += bytes([(byte & 0x0F) + ord('A')])
        return bytes([32]) + encoded + b'\x00'  # Length prefix + encoded + null
    
    # NBT-NS Name Query packet
    transaction_id = random.randint(0, 65535)
    flags = 0x0110  # Broadcast, recursion desired
    questions = 1
    answers = 0
    authority = 0
    additional = 0
    
    header = struct.pack(">HHHHHH", transaction_id, flags, questions, answers, authority, additional)
    
    dest = target if target else NBTNS_BROADCAST
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)
        
        for i in range(count):
            query_name = name if name else random_name()
            encoded = encode_netbios_name(query_name)
            qtype = 0x0020  # NB (NetBIOS general Name Service)
            qclass = 0x0001  # IN class
            
            packet = header + encoded + struct.pack(">HH", qtype, qclass)
            
            log_info(f"Sending NBT-NS query for '{query_name}' to {dest}:{NBTNS_PORT}")
            sock.sendto(packet, (dest, NBTNS_PORT))
            time.sleep(0.5)
        
        sock.close()
        log_success(f"NBT-NS queries sent ({count}x)")
        return True
    except Exception as e:
        log_error(f"NBT-NS failed: {e}")
        return False

# ==================== mDNS (Multicast DNS) ====================
def send_mdns_query(name, count=1):
    """
    Send mDNS query to trigger Responder.
    mDNS uses UDP port 5353, multicast address 224.0.0.251
    """
    log_section("mDNS Query (UDP 5353)")
    
    MDNS_MULTICAST = "224.0.0.251"
    MDNS_PORT = 5353
    
    # mDNS packet (same as DNS)
    transaction_id = 0  # mDNS uses 0
    flags = 0x0000  # Standard query
    questions = 1
    answers = 0
    authority = 0
    additional = 0
    
    # Encode name with .local suffix
    query_name = name if name else random_name()
    if not query_name.endswith('.local'):
        query_name += '.local'
    
    encoded_name = b""
    for part in query_name.split('.'):
        if part:
            encoded_name += bytes([len(part)]) + part.encode('utf-8')
    encoded_name += b'\x00'
    
    qtype = 1  # A record
    qclass = 1  # IN class
    
    packet = struct.pack(">HHHHHH", transaction_id, flags, questions, answers, authority, additional)
    packet += encoded_name
    packet += struct.pack(">HH", qtype, qclass)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(2)
        
        for i in range(count):
            log_info(f"Sending mDNS query for '{query_name}' to {MDNS_MULTICAST}:{MDNS_PORT}")
            sock.sendto(packet, (MDNS_MULTICAST, MDNS_PORT))
            time.sleep(0.5)
        
        sock.close()
        log_success(f"mDNS queries sent ({count}x)")
        return True
    except Exception as e:
        log_error(f"mDNS failed: {e}")
        return False

# ==================== SMB ====================
def send_smb_request(target, share=None, count=1):
    """
    Attempt SMB connection to trigger NTLM authentication.
    """
    log_section("SMB Connection (TCP 445)")
    
    SMB_PORT = 445
    share_name = share if share else random_name()
    
    try:
        for i in range(count):
            path = f"\\\\{target}\\{share_name}"
            log_info(f"Attempting SMB connection to {path}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, SMB_PORT))
                
                # SMB Negotiate Protocol Request (SMB1)
                # This is enough to trigger Responder
                netbios_header = b'\x00'  # Message type
                smb_header = b'\xffSMB'  # SMB signature
                command = b'\x72'  # Negotiate Protocol
                
                # Minimal negotiate request
                negotiate = (
                    b'\x00' * 4 +  # Status
                    b'\x18' +      # Flags
                    b'\x53\xc8' +  # Flags2
                    b'\x00' * 12 + # PID, etc.
                    b'\x00' * 8 +  # Signature
                    b'\x00\x00' +  # Reserved
                    b'\x00\x00' +  # TID
                    b'\x00\x00' +  # PID
                    b'\x00\x00' +  # UID
                    b'\x00\x00'    # MID
                )
                
                # Dialect: NT LM 0.12
                dialect = b'\x02NT LM 0.12\x00'
                word_count = b'\x00'
                byte_count = struct.pack('<H', len(dialect))
                
                smb_packet = smb_header + command + negotiate + word_count + byte_count + dialect
                length = struct.pack('>I', len(smb_packet))[1:]  # 3 bytes
                
                packet = netbios_header + length + smb_packet
                sock.send(packet)
                
                log_success(f"SMB negotiate sent to {target}")
            except socket.timeout:
                log_warning(f"SMB connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"SMB connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"SMB failed: {e}")
        return False

# ==================== HTTP/WPAD ====================
def send_http_request(target, path="/wpad.dat", count=1):
    """
    Send HTTP request with NTLM auth expectation to trigger Responder.
    """
    log_section("HTTP/WPAD Request (TCP 80)")
    
    HTTP_PORT = 80
    
    try:
        for i in range(count):
            log_info(f"Sending HTTP request to http://{target}{path}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, HTTP_PORT))
                
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                    f"Accept: */*\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                
                sock.send(request.encode())
                
                # Try to receive response (might get 401 with NTLM challenge)
                try:
                    response = sock.recv(1024)
                    if b'NTLM' in response or b'401' in response:
                        log_success(f"HTTP NTLM challenge received from {target}")
                    else:
                        log_info(f"HTTP response received from {target}")
                except:
                    pass
                
            except socket.timeout:
                log_warning(f"HTTP connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"HTTP connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"HTTP failed: {e}")
        return False

# ==================== LDAP ====================
def send_ldap_request(target, count=1):
    """
    Send LDAP bind request to trigger NTLM authentication.
    """
    log_section("LDAP Request (TCP 389)")
    
    LDAP_PORT = 389
    
    try:
        for i in range(count):
            log_info(f"Sending LDAP bind request to {target}:{LDAP_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, LDAP_PORT))
                
                # LDAP Bind Request (simplified)
                # Message ID: 1, Bind Request, Version 3, Simple Auth
                bind_request = (
                    b'\x30\x0c'      # SEQUENCE, length 12
                    b'\x02\x01\x01'  # INTEGER, Message ID: 1
                    b'\x60\x07'      # Bind Request, length 7
                    b'\x02\x01\x03'  # INTEGER, Version: 3
                    b'\x04\x00'      # OCTET STRING, Empty DN
                    b'\x80\x00'      # Simple Auth, Empty password
                )
                
                sock.send(bind_request)
                log_success(f"LDAP bind request sent to {target}")
                
            except socket.timeout:
                log_warning(f"LDAP connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"LDAP connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"LDAP failed: {e}")
        return False

# ==================== SQL (MS-SQL) ====================
def send_mssql_request(target, count=1):
    """
    Send MS-SQL pre-login request to trigger authentication.
    """
    log_section("MS-SQL Request (TCP 1433)")
    
    MSSQL_PORT = 1433
    
    try:
        for i in range(count):
            log_info(f"Sending MS-SQL pre-login to {target}:{MSSQL_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, MSSQL_PORT))
                
                # TDS Pre-login packet
                # Type: Pre-Login (0x12), Status: EOM (0x01)
                prelogin = (
                    b'\x12\x01'  # Type: Pre-login, Status: EOM
                    b'\x00\x2f'  # Length (47 bytes total)
                    b'\x00\x00'  # SPID
                    b'\x00\x00'  # Packet ID, Window
                    # Pre-login options
                    b'\x00\x00\x15\x00\x06'  # VERSION
                    b'\x01\x00\x1b\x00\x01'  # ENCRYPTION
                    b'\x02\x00\x1c\x00\x01'  # INSTOPT
                    b'\x03\x00\x1d\x00\x00'  # THREADID
                    b'\x04\x00\x1d\x00\x01'  # MARS
                    b'\xff'                  # Terminator
                    b'\x09\x00\x00\x00\x00\x00'  # Version data
                    b'\x01'      # Encryption: Encrypt Off
                    b'\x00'      # Instance
                    b'\x00'      # MARS disabled
                )
                
                sock.send(prelogin)
                log_success(f"MS-SQL pre-login sent to {target}")
                
            except socket.timeout:
                log_warning(f"MS-SQL connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"MS-SQL connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"MS-SQL failed: {e}")
        return False

# ==================== FTP ====================
def send_ftp_request(target, count=1):
    """
    Send FTP connection to trigger authentication.
    """
    log_section("FTP Request (TCP 21)")
    
    FTP_PORT = 21
    
    try:
        for i in range(count):
            log_info(f"Sending FTP request to {target}:{FTP_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, FTP_PORT))
                
                # Wait for banner
                try:
                    banner = sock.recv(1024)
                    log_info(f"FTP banner: {banner.decode().strip()}")
                except:
                    pass
                
                # Send USER command
                sock.send(b'USER anonymous\r\n')
                log_success(f"FTP USER command sent to {target}")
                
            except socket.timeout:
                log_warning(f"FTP connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"FTP connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"FTP failed: {e}")
        return False

# ==================== SMTP ====================
def send_smtp_request(target, count=1):
    """
    Send SMTP connection to trigger authentication.
    """
    log_section("SMTP Request (TCP 25)")
    
    SMTP_PORT = 25
    
    try:
        for i in range(count):
            log_info(f"Sending SMTP request to {target}:{SMTP_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, SMTP_PORT))
                
                # Wait for banner
                try:
                    banner = sock.recv(1024)
                    log_info(f"SMTP banner: {banner.decode().strip()}")
                except:
                    pass
                
                # Send EHLO
                sock.send(b'EHLO test\r\n')
                log_success(f"SMTP EHLO sent to {target}")
                
            except socket.timeout:
                log_warning(f"SMTP connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"SMTP connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"SMTP failed: {e}")
        return False

# ==================== POP3 ====================
def send_pop3_request(target, count=1):
    """
    Send POP3 connection to trigger authentication.
    """
    log_section("POP3 Request (TCP 110)")
    
    POP3_PORT = 110
    
    try:
        for i in range(count):
            log_info(f"Sending POP3 request to {target}:{POP3_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, POP3_PORT))
                
                # Wait for banner
                try:
                    banner = sock.recv(1024)
                    log_info(f"POP3 banner: {banner.decode().strip()}")
                except:
                    pass
                
                # Send USER command
                sock.send(b'USER test\r\n')
                log_success(f"POP3 USER command sent to {target}")
                
            except socket.timeout:
                log_warning(f"POP3 connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"POP3 connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"POP3 failed: {e}")
        return False

# ==================== IMAP ====================
def send_imap_request(target, count=1):
    """
    Send IMAP connection to trigger authentication.
    """
    log_section("IMAP Request (TCP 143)")
    
    IMAP_PORT = 143
    
    try:
        for i in range(count):
            log_info(f"Sending IMAP request to {target}:{IMAP_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, IMAP_PORT))
                
                # Wait for banner
                try:
                    banner = sock.recv(1024)
                    log_info(f"IMAP banner: {banner.decode().strip()}")
                except:
                    pass
                
                # Send CAPABILITY command
                sock.send(b'a001 CAPABILITY\r\n')
                log_success(f"IMAP CAPABILITY command sent to {target}")
                
            except socket.timeout:
                log_warning(f"IMAP connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"IMAP connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"IMAP failed: {e}")
        return False

# ==================== HTTPS ====================
def send_https_request(target, count=1):
    """
    Send HTTPS connection to trigger authentication.
    """
    log_section("HTTPS Request (TCP 443)")
    
    HTTPS_PORT = 443
    
    try:
        import ssl
    except ImportError:
        log_warning("SSL module not available, skipping HTTPS")
        return False
    
    try:
        for i in range(count):
            log_info(f"Sending HTTPS request to {target}:{HTTPS_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, HTTPS_PORT))
                
                # Wrap with SSL (ignore cert errors)
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                try:
                    ssl_sock = context.wrap_socket(sock, server_hostname=target)
                    
                    request = (
                        f"GET / HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        f"User-Agent: Mozilla/5.0\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    )
                    
                    ssl_sock.send(request.encode())
                    log_success(f"HTTPS request sent to {target}")
                    ssl_sock.close()
                except ssl.SSLError as e:
                    log_warning(f"SSL error: {e}")
                
            except socket.timeout:
                log_warning(f"HTTPS connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"HTTPS connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"HTTPS failed: {e}")
        return False

# ==================== WebDAV ====================
def send_webdav_request(target, count=1):
    """
    Send WebDAV PROPFIND request to trigger NTLM authentication.
    """
    log_section("WebDAV Request (TCP 80)")
    
    HTTP_PORT = 80
    
    try:
        for i in range(count):
            log_info(f"Sending WebDAV PROPFIND to {target}:{HTTP_PORT}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            try:
                sock.connect((target, HTTP_PORT))
                
                # WebDAV PROPFIND request
                request = (
                    f"PROPFIND / HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: Microsoft-WebDAV-MiniRedir/10.0.19041\r\n"
                    f"Depth: 0\r\n"
                    f"Content-Type: text/xml\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                )
                
                sock.send(request.encode())
                log_success(f"WebDAV PROPFIND sent to {target}")
                
            except socket.timeout:
                log_warning(f"WebDAV connection timeout to {target}")
            except ConnectionRefusedError:
                log_warning(f"WebDAV connection refused by {target}")
            finally:
                sock.close()
            
            time.sleep(0.5)
        
        return True
    except Exception as e:
        log_error(f"WebDAV failed: {e}")
        return False

# ==================== Main ====================
def main():
    banner = """
╦═╗┌─┐┌─┐┌─┐┌─┐┌┐┌┌┬┐┌─┐┬─┐  ╔╦╗┬─┐┬┌─┐┌─┐┌─┐┬─┐
╠╦╝├┤ └─┐├─┘│ ││││ ││├┤ ├┬┘   ║ ├┬┘││ ┬│ ┬├┤ ├┬┘
╩╚═└─┘└─┘┴  └─┘┘└┘─┴┘└─┘┴└─   ╩ ┴└─┴└─┘└─┘└─┘┴└─
        Protocol Hash Capture Provocateur
    """
    print(f"{Colors.CYAN}{banner}{Colors.ENDC}")
    
    parser = argparse.ArgumentParser(
        description="Responder Trigger - Send fake solicitations to capture NTLM hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Trigger all protocols against Responder IP
  ./responder-trigger.py 192.168.1.100
  
  # Only broadcast protocols (no target needed)
  ./responder-trigger.py --broadcast
  
  # Specific protocols only
  ./responder-trigger.py 192.168.1.100 --protocols llmnr nbtns smb
  
  # Multiple iterations
  ./responder-trigger.py 192.168.1.100 --count 5
  
  # Continuous mode (loop forever)
  ./responder-trigger.py 192.168.1.100 --loop --delay 10

Supported Protocols:
  llmnr    - Link-Local Multicast Name Resolution (UDP 5355)
  nbtns    - NetBIOS Name Service (UDP 137)
  mdns     - Multicast DNS (UDP 5353)
  smb      - SMB Connection (TCP 445)
  http     - HTTP/WPAD Request (TCP 80)
  https    - HTTPS Request (TCP 443)
  webdav   - WebDAV PROPFIND (TCP 80)
  ldap     - LDAP Bind (TCP 389)
  mssql    - MS-SQL Pre-login (TCP 1433)
  ftp      - FTP Connection (TCP 21)
  smtp     - SMTP Connection (TCP 25)
  pop3     - POP3 Connection (TCP 110)
  imap     - IMAP Connection (TCP 143)
        """
    )
    
    parser.add_argument("target", nargs="?", help="Target IP (Responder's IP or victim to spoof)")
    parser.add_argument("--broadcast", "-b", action="store_true", 
                       help="Only use broadcast/multicast protocols (no target needed)")
    parser.add_argument("--protocols", "-p", nargs="+", 
                       choices=["llmnr", "nbtns", "mdns", "smb", "http", "https", 
                               "webdav", "ldap", "mssql", "ftp", "smtp", "pop3", "imap", "all"],
                       default=["all"], help="Protocols to trigger (default: all)")
    parser.add_argument("--count", "-c", type=int, default=1, 
                       help="Number of requests per protocol (default: 1)")
    parser.add_argument("--name", "-n", default=None, 
                       help="Name to query (default: random)")
    parser.add_argument("--loop", "-l", action="store_true", 
                       help="Loop continuously")
    parser.add_argument("--delay", "-d", type=int, default=5, 
                       help="Delay between loops in seconds (default: 5)")
    parser.add_argument("--quiet", "-q", action="store_true", 
                       help="Minimal output")
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.broadcast and not args.target:
        parser.error("Either target IP or --broadcast is required")
    
    protocols = args.protocols
    if "all" in protocols:
        protocols = ["llmnr", "nbtns", "mdns", "smb", "http", "https", 
                    "webdav", "ldap", "mssql", "ftp", "smtp", "pop3", "imap"]
    
    # Broadcast-only protocols don't need a target
    broadcast_protocols = ["llmnr", "nbtns", "mdns"]
    tcp_protocols = ["smb", "http", "https", "webdav", "ldap", "mssql", "ftp", "smtp", "pop3", "imap"]
    
    if args.broadcast:
        protocols = [p for p in protocols if p in broadcast_protocols]
        if not protocols:
            log_error("No broadcast protocols selected")
            sys.exit(1)
    
    # Protocol handlers
    handlers = {
        "llmnr": lambda: send_llmnr_query(args.name, args.target, args.count),
        "nbtns": lambda: send_nbtns_query(args.name, args.target, args.count),
        "mdns": lambda: send_mdns_query(args.name, args.count),
        "smb": lambda: send_smb_request(args.target, args.name, args.count),
        "http": lambda: send_http_request(args.target, "/wpad.dat", args.count),
        "https": lambda: send_https_request(args.target, args.count),
        "webdav": lambda: send_webdav_request(args.target, args.count),
        "ldap": lambda: send_ldap_request(args.target, args.count),
        "mssql": lambda: send_mssql_request(args.target, args.count),
        "ftp": lambda: send_ftp_request(args.target, args.count),
        "smtp": lambda: send_smtp_request(args.target, args.count),
        "pop3": lambda: send_pop3_request(args.target, args.count),
        "imap": lambda: send_imap_request(args.target, args.count),
    }
    
    iteration = 0
    try:
        while True:
            iteration += 1
            
            if args.loop:
                print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
                print(f"{Colors.HEADER}[ITERATION {iteration}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")
                print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}")
            
            log_info(f"Target: {args.target if args.target else 'Broadcast/Multicast'}")
            log_info(f"Protocols: {', '.join(protocols)}")
            log_info(f"Requests per protocol: {args.count}")
            
            results = {}
            for proto in protocols:
                if proto in handlers:
                    # Skip TCP protocols if no target
                    if proto in tcp_protocols and not args.target:
                        log_warning(f"Skipping {proto} - requires target IP")
                        continue
                    results[proto] = handlers[proto]()
            
            # Summary
            print(f"\n{Colors.BOLD}{'='*40}{Colors.ENDC}")
            print(f"{Colors.BOLD}Summary:{Colors.ENDC}")
            for proto, success in results.items():
                status = f"{Colors.GREEN}✓{Colors.ENDC}" if success else f"{Colors.RED}✗{Colors.ENDC}"
                print(f"  {status} {proto.upper()}")
            
            if not args.loop:
                break
            
            log_info(f"Sleeping {args.delay} seconds before next iteration...")
            time.sleep(args.delay)
            
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
