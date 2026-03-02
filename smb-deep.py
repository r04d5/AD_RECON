#!/usr/bin/env python3
"""
SMB Deep Enumeration Tool
Comprehensive SMB enumeration for Active Directory pentesting and CTFs.
Supports password and hash authentication with multiple tools.
"""
import subprocess
import sys
import argparse
import shlex

def run_cmd(cmd_str, file_handle, section_title=None):
    """Execute command, print to terminal and write to file in real time.
       Returns the full output for error checking."""
    if section_title:
        print(f"\n\033[1;36m[>] {section_title}\033[0m")
        file_handle.write(f"### {section_title}\n\n")
    
    print(f"\033[1;34m[*] Executing:\033[0m {cmd_str}")
    file_handle.write(f"**Command:** `{cmd_str}`\n\n```bash\n")
    file_handle.flush()
    
    full_output = ""
    try:
        process = subprocess.Popen(cmd_str, shell=True, executable='/bin/bash', 
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                   text=True, bufsize=1)
        for line in process.stdout:
            print(line, end="")          
            file_handle.write(line)     
            file_handle.flush()
            full_output += line
        process.wait()
    except Exception as e:
        print(f"\033[1;31mERROR: {e}\033[0m")
        file_handle.write(f"ERROR: {e}\n")
        full_output += f"ERROR: {e}"
    file_handle.write("```\n\n---\n\n")
    return full_output

def check_smb_error(output):
    """Check for common SMB errors and return error message if found."""
    out_lower = output.lower()
    if "logon_failure" in out_lower or "status_logon_failure" in out_lower:
        return "Invalid credentials"
    if "connection refused" in out_lower:
        return "Connection refused - check if SMB port 445 is open"
    if "connection reset" in out_lower or "timeout" in out_lower:
        return "Connection timeout - host may be unreachable"
    if "access_denied" in out_lower or "status_access_denied" in out_lower:
        return "Access denied - user lacks permissions"
    return None

def main():
    parser = argparse.ArgumentParser(
        description="SMB Deep Enumeration - Comprehensive AD Recon Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./smb-deep.py 10.10.10.10 -d corp.local -u admin -p 'Password123'
  ./smb-deep.py 10.10.10.10 -d corp.local -u admin -H ':aad3b435b51404eeaad3b435b51404ee:ntlmhash'
  ./smb-deep.py 10.10.10.10 -d corp.local -u admin -p 'Password123' --quick
        """
    )
    parser.add_argument("target", help="Target IP address (e.g., 10.10.10.10)")
    parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g., corp.local)")
    parser.add_argument("-u", "--user", required=True, help="Username for authentication")
    
    # Mutually exclusive group: Password or Hash
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("-p", "--password", help="Cleartext password")
    auth_group.add_argument("-H", "--hash", help="NTLM hash (LMHASH:NTHASH or :NTHASH)")
    
    parser.add_argument("--quick", action="store_true", help="Quick mode: only essential scans")
    parser.add_argument("--spider", action="store_true", help="Spider all readable shares (slow)")
    parser.add_argument("--secrets", action="store_true", help="Attempt to dump secrets (requires admin)")

    args = parser.parse_args()

    # Prepare shell-safe variables
    safe_target = shlex.quote(args.target)
    safe_domain = shlex.quote(args.domain)
    safe_user = shlex.quote(args.user)

    report_name = f"smb_deep_{args.target.replace('.', '_')}.md"
    
    with open(report_name, "w") as f:
        f.write(f"# SMB Deep Enumeration Report\n\n")
        f.write(f"**Target:** {args.target}  \n")
        f.write(f"**Domain:** {args.domain}  \n")
        f.write(f"**User:** {args.user}  \n\n")
        f.write("---\n\n")
        
        # Build authentication strings for different tools
        if args.password:
            safe_pass = shlex.quote(args.password)
            auth_type = "Password"
            
            # NetExec auth
            nxc_auth = f"-u {safe_user} -p {safe_pass}"
            # Impacket auth
            impacket_auth = f"'{args.domain}/{args.user}:{args.password}'@{args.target}"
            # smbclient auth
            smb_auth = f"-U '{args.domain}\\{args.user}%{args.password}'"
            # rpcclient auth
            rpc_auth = f"-U '{args.domain}\\{args.user}%{args.password}'"
            # enum4linux-ng auth
            enum4linux_auth = f"-u {safe_user} -p {safe_pass}"
            
        elif args.hash:
            safe_hash = shlex.quote(args.hash)
            auth_type = "Hash (PTH)"
            
            # NetExec auth
            nxc_auth = f"-u {safe_user} -H {safe_hash}"
            # Impacket auth
            impacket_auth = f"'{args.domain}/{args.user}'@{args.target} -hashes {args.hash}"
            # smbclient auth (hash format: --pw-nt-hash)
            # Get just the NT hash if LMHASH:NTHASH format
            nt_hash = args.hash.split(":")[-1] if ":" in args.hash else args.hash
            smb_auth = f"-U '{args.domain}\\{args.user}%{nt_hash}' --pw-nt-hash"
            # rpcclient auth
            rpc_auth = f"-U '{args.domain}\\{args.user}%{nt_hash}' --pw-nt-hash"
            # enum4linux-ng auth
            enum4linux_auth = f"-u {safe_user} -H {safe_hash}"
        
        print(f"\033[1;32m[+] {auth_type} authentication mode\033[0m")
        f.write(f"## Authentication: {auth_type}\n\n")
        
        # =================================================================
        # SECTION 1: Initial Connectivity & Host Info
        # =================================================================
        f.write("## 1. Connectivity & Host Information\n\n")
        
        # NetExec SMB scan (basic info)
        cmd = f"nxc smb {safe_target} {nxc_auth}"
        output = run_cmd(cmd, f, "SMB Connection Test")
        
        # Check for auth errors
        error = check_smb_error(output)
        if error:
            print(f"\n\033[1;31m[!] FATAL: {error}\033[0m")
            print(f"\033[1;33m[*] Check credentials and domain format\033[0m")
            f.write(f"\n> ❌ **FATAL ERROR:** {error}\n")
            print(f"\n\033[1;32m[+] Partial report saved to: {report_name}\033[0m")
            sys.exit(1)
        
        # Check signing status
        if "signing:True" in output:
            print("\033[1;33m[!] SMB Signing is ENABLED - Relay attacks not possible\033[0m")
            f.write("> ⚠️ **SMB Signing:** Enabled (relay attacks blocked)\n\n")
        elif "signing:False" in output:
            print("\033[1;32m[+] SMB Signing is DISABLED - Relay attacks possible!\033[0m")
            f.write("> 🔓 **SMB Signing:** Disabled (relay attacks possible!)\n\n")
        
        # =================================================================
        # SECTION 2: Share Enumeration
        # =================================================================
        f.write("## 2. Share Enumeration\n\n")
        
        # List shares with permissions
        cmd = f"nxc smb {safe_target} {nxc_auth} --shares"
        run_cmd(cmd, f, "SMB Shares with Permissions")
        
        # smbclient share listing (alternative view)
        cmd = f"smbclient -L //{args.target} {smb_auth} 2>/dev/null"
        run_cmd(cmd, f, "SMB Shares (smbclient)")
        
        if args.spider:
            # Spider shares for interesting files
            f.write("### Share Spidering\n\n")
            cmd = f"nxc smb {safe_target} {nxc_auth} -M spider_plus -o DOWNLOAD_FLAG=false"
            run_cmd(cmd, f, "Spider Shares for Files")
        
        # =================================================================
        # SECTION 3: User Enumeration
        # =================================================================
        f.write("## 3. User Enumeration\n\n")
        
        # Domain users via SMB
        cmd = f"nxc smb {safe_target} {nxc_auth} --users"
        run_cmd(cmd, f, "Domain Users (via SMB)")
        
        # RID Brute (finds hidden users)
        cmd = f"nxc smb {safe_target} {nxc_auth} --rid-brute"
        run_cmd(cmd, f, "RID Bruteforce (discovers all SIDs)")
        
        if not args.quick:
            # Logged on users
            cmd = f"nxc smb {safe_target} {nxc_auth} --loggedon-users"
            run_cmd(cmd, f, "Currently Logged On Users")
            
            # Local users
            cmd = f"nxc smb {safe_target} {nxc_auth} --local-users"
            run_cmd(cmd, f, "Local Users")
        
        # =================================================================
        # SECTION 4: Group Enumeration
        # =================================================================
        f.write("## 4. Group Enumeration\n\n")
        
        # Domain groups via RPC
        cmd = f"rpcclient -c 'enumdomgroups' {args.target} {rpc_auth} 2>/dev/null"
        run_cmd(cmd, f, "Domain Groups (RPC)")
        
        # Local groups
        cmd = f"nxc smb {safe_target} {nxc_auth} --local-groups"
        run_cmd(cmd, f, "Local Groups")
        
        if not args.quick:
            # Local Administrators members
            cmd = f"nxc smb {safe_target} {nxc_auth} --groups 'Administrators'"
            run_cmd(cmd, f, "Local Administrators Members")
            
            # Remote Desktop Users
            cmd = f"nxc smb {safe_target} {nxc_auth} --groups 'Remote Desktop Users'"
            run_cmd(cmd, f, "Remote Desktop Users Members")
        
        # =================================================================
        # SECTION 5: Password Policy
        # =================================================================
        f.write("## 5. Password Policy\n\n")
        
        cmd = f"nxc smb {safe_target} {nxc_auth} --pass-pol"
        run_cmd(cmd, f, "Domain Password Policy")
        
        # =================================================================
        # SECTION 6: Sessions & Connections
        # =================================================================
        if not args.quick:
            f.write("## 6. Sessions & Connections\n\n")
            
            cmd = f"nxc smb {safe_target} {nxc_auth} --sessions"
            run_cmd(cmd, f, "Active Sessions")
            
            cmd = f"nxc smb {safe_target} {nxc_auth} --disks"
            run_cmd(cmd, f, "Disk Enumeration")
        
        # =================================================================
        # SECTION 7: Interesting Files
        # =================================================================
        f.write("## 7. Interesting Files Search\n\n")
        
        # Search for common interesting files in SYSVOL
        interesting_patterns = [
            "*.xml", "*.ps1", "*.bat", "*.vbs", "*.cmd", 
            "*password*", "*cred*", "*config*", "unattend*"
        ]
        
        for share in ["SYSVOL", "NETLOGON"]:
            cmd = f"smbclient //{args.target}/{share} {smb_auth} -c 'recurse ON; ls' 2>/dev/null | head -50"
            run_cmd(cmd, f, f"Files in {share} Share")
        
        # GPP Passwords (Groups.xml)
        if not args.quick:
            cmd = f"nxc smb {safe_target} {nxc_auth} -M gpp_password"
            run_cmd(cmd, f, "GPP Passwords (cpassword)")
            
            cmd = f"nxc smb {safe_target} {nxc_auth} -M gpp_autologin"
            run_cmd(cmd, f, "GPP Autologin Credentials")
        
        # =================================================================
        # SECTION 8: Vulnerability Checks
        # =================================================================
        f.write("## 8. Vulnerability Checks\n\n")
        
        # WebDAV check
        cmd = f"nxc smb {safe_target} {nxc_auth} -M webdav"
        run_cmd(cmd, f, "WebDAV Enabled Check")
        
        # Coerce checks
        cmd = f"nxc smb {safe_target} {nxc_auth} -M coerce_plus"
        run_cmd(cmd, f, "Coercion Vulnerabilities (PetitPotam, etc)")
        
        if not args.quick:
            # Spool service (PrintNightmare)
            cmd = f"nxc smb {safe_target} {nxc_auth} -M spooler"
            run_cmd(cmd, f, "Print Spooler Service (PrintNightmare)")
            
            # MS17-010 EternalBlue
            cmd = f"nxc smb {safe_target} {nxc_auth} -M ms17-010"
            run_cmd(cmd, f, "MS17-010 (EternalBlue)")
            
            # ZeroLogon check
            cmd = f"nxc smb {safe_target} {nxc_auth} -M zerologon"
            run_cmd(cmd, f, "ZeroLogon (CVE-2020-1472)")
            
            # noPac check
            cmd = f"nxc smb {safe_target} {nxc_auth} -M nopac"
            run_cmd(cmd, f, "noPac (CVE-2021-42278)")
        
        # =================================================================
        # SECTION 9: Secrets Dumping (Admin Required)
        # =================================================================
        if args.secrets:
            f.write("## 9. Secrets Dumping (Admin Required)\n\n")
            f.write("> ⚠️ **Warning:** These require local admin privileges\n\n")
            
            # SAM dump
            cmd = f"nxc smb {safe_target} {nxc_auth} --sam"
            run_cmd(cmd, f, "SAM Dump (Local Accounts)")
            
            # LSA Secrets
            cmd = f"nxc smb {safe_target} {nxc_auth} --lsa"
            run_cmd(cmd, f, "LSA Secrets")
            
            # NTDS.dit (DC only)
            cmd = f"nxc smb {safe_target} {nxc_auth} --ntds"
            run_cmd(cmd, f, "NTDS.dit Dump (Domain Controller)")
            
            # LAPS passwords
            cmd = f"nxc smb {safe_target} {nxc_auth} -M laps"
            run_cmd(cmd, f, "LAPS Passwords")
        
        # =================================================================
        # SECTION 10: Additional Enumeration
        # =================================================================
        if not args.quick:
            f.write("## 10. Additional Enumeration\n\n")
            
            # AV Detection
            cmd = f"nxc smb {safe_target} {nxc_auth} -M enum_av"
            run_cmd(cmd, f, "Antivirus Detection")
            
            # Installed software
            cmd = f"nxc smb {safe_target} {nxc_auth} -M installed_software"
            run_cmd(cmd, f, "Installed Software")
            
            # Active Directory Certificate Services
            cmd = f"nxc smb {safe_target} {nxc_auth} -M adcs"
            run_cmd(cmd, f, "AD Certificate Services (ADCS)")
            
            # Enum4linux-ng comprehensive scan
            cmd = f"enum4linux-ng -A {args.target} {enum4linux_auth} 2>/dev/null | head -200"
            run_cmd(cmd, f, "Enum4linux-ng Summary")

    print(f"\n\033[1;32m[+] Full report saved to: {report_name}\033[0m")

if __name__ == "__main__":
    main()
