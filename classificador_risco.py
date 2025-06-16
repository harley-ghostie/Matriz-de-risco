
import argparse
import requests
from rich import print
from rich.console import Console
from rich.table import Table

def classificar_risco_cvss(score):
    if score >= 9.0:
        return "Crítico", "🔴"
    elif 7.0 <= score < 9.0:
        return "Alto", "🟠"
    elif 4.0 <= score < 7.0:
        return "Médio", "🟡"
    elif 0.1 <= score < 4.0:
        return "Baixo", "🟢"
    else:
        return "Informativo", "🔵"

def classificar_impacto_por_cvss(score):
    if score >= 7.0:
        return "Alto", "🔴"
    elif score >= 4.0:
        return "Médio", "🟡"
    else:
        return "Baixo", "🟢"

def classificar_probabilidade_por_cvss(score):
    if score >= 7.0:
        return "Alta", "🔴"
    elif score >= 4.0:
        return "Média", "🟡"
    else:
        return "Baixa", "🟢"

# Mapeamento refinado com múltiplas categorias OWASP
OWASP_MULTI_MAP = {
    "clickjacking": ["A04: Insecure Design", "A05: Security Misconfiguration"],
    "open redirect": ["A01: Broken Access Control", "A04: Insecure Design"],
    "malware": ["A06: Vulnerable and Outdated Components"],
    "data exposure": ["A02: Cryptographic Failures"],
    "sensitive data": ["A02: Cryptographic Failures"],
    "token leakage": ["A07: Identification and Authentication Failures"],
    "csrf": ["A01: Broken Access Control", "A04: Insecure Design"],
    "sql injection": ["A03: Injection"],
    "xss": ["A03: Injection"],
    "command injection": ["A03: Injection"],
    "file upload": ["A05: Security Misconfiguration", "A04: Insecure Design"],
    "unauthorized access": ["A01: Broken Access Control"],
    "deserialization": ["A08: Software and Data Integrity Failures"],
    "directory traversal": ["A05: Security Misconfiguration"],
    "exposure via url": ["A02: Cryptographic Failures"]
}

def classify_owasp(nome):
    nome = nome.lower()
    categorias = []
    for termo, cats in OWASP_MULTI_MAP.items():
        if termo in nome:
            categorias.extend(cats)
    return ", ".join(set(categorias)) if categorias else "Desconhecido"

def fetch_mitre_techniques():
    try:
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        resp = requests.get(url, timeout=30)
        data = resp.json()
        mitre = []
        for obj in data["objects"]:
            if obj.get("type") == "attack-pattern":
                name = obj.get("name", "").lower()
                tid = obj.get("external_references", [{}])[0].get("external_id", "N/A")
                mitre.append((name, tid))
        return mitre
    except:
        return []

def classify_mitre(nome, mitre_list):
    nome = nome.lower()
    for m_name, m_id in mitre_list:
        if m_name in nome:
            return m_name.title(), m_id
    return "Desconhecido", "Desconhecido"

def processar_arquivo(caminho, mitre_list):
    resultados = []
    with open(caminho, 'r') as f:
        for linha in f:
            linha = linha.strip()
            if not linha or linha.startswith("#"):
                continue
            partes = linha.split(",", 3)
            if len(partes) != 4:
                print(f"[red]Linha inválida ignorada:[/red] {linha}")
                continue
            vuln_id, nome_vuln, score, vetor = partes
            try:
                score = float(score)
            except ValueError:
                print(f"[red]Score inválido na linha:[/red] {linha}")
                continue

            impacto, cor_impacto = classificar_impacto_por_cvss(score)
            probabilidade, cor_prob = classificar_probabilidade_por_cvss(score)
            risco, cor_risco = classificar_risco_cvss(score)

            owasp_categoria = classify_owasp(nome_vuln)
            mitre_tec, mitre_id = classify_mitre(nome_vuln, mitre_list)

            resultados.append({
                "ID": vuln_id,
                "CVSS": score,
                "Impacto": f"{cor_impacto} {impacto}",
                "Probabilidade": f"{cor_prob} {probabilidade}",
                "Risco": f"{cor_risco} {risco}",
                "OWASP": owasp_categoria,
                "MITRE_T": mitre_tec,
                "MITRE_ID": mitre_id
            })
    return resultados

def main():
    parser = argparse.ArgumentParser(description="Classificador de risco com OWASP e MITRE.")
    parser.add_argument('--input', required=True, help='Caminho para arquivo .txt com vulnerabilidades')
    args = parser.parse_args()

    console = Console()
    print("[blue]📦 Carregando MITRE ATT&CK...[/blue]")
    mitre = fetch_mitre_techniques()
    resultados = processar_arquivo(args.input, mitre)

    if not resultados:
        print("[red]Nenhuma vulnerabilidade processada.[/red]")
        return

    table = Table(title="Classificação de Risco + OWASP + MITRE", show_lines=True)
    table.add_column("ID")
    table.add_column("CVSS", justify="center")
    table.add_column("Impacto", justify="center")
    table.add_column("Probabilidade", justify="center")
    table.add_column("Risco", justify="center")
    table.add_column("OWASP", justify="center")
    table.add_column("MITRE Tática", justify="center")
    table.add_column("MITRE Técnica", justify="center")

    for r in resultados:
        table.add_row(r["ID"], str(r["CVSS"]), r["Impacto"], r["Probabilidade"], r["Risco"],
                      r["OWASP"], r["MITRE_T"], r["MITRE_ID"])

    console.print(table)

if __name__ == "__main__":
    main()
