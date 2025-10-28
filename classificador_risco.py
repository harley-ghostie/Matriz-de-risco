import argparse
import csv
import requests
from rich import print
from rich.console import Console
from rich.table import Table

# ---------- Severidade por CVSS total ----------
def classificar_risco_cvss(score):
    if score >= 9.0:
        return "Crítico", "⚫"
    elif 7.0 <= score < 9.0:
        return "Alto", "🔴"
    elif 4.0 <= score < 7.0:
        return "Médio", "🟠"
    elif 0.1 <= score < 4.0:
        return "Baixo", "🟡" 
    else:
        return "Informativo", "🔵"

# ---------- Tabelas CVSS v3.x ----------
CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # S:U
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.50},  # S:C
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.00},
    "I": {"H": 0.56, "L": 0.22, "N": 0.00},
    "A": {"H": 0.56, "L": 0.22, "N": 0.00},
}

# ---------- Limiares exatos (terços do intervalo real) ----------
EXP_MAX = 8.22 * 0.85 * 0.77 * 0.85 * 0.85  # 3.8870427750000003
EXP_T1 = EXP_MAX / 3                        # 1.295680925
EXP_T2 = 2 * EXP_MAX / 3                    # 2.59136185

# Impacto máximo ocorre em S:C com C=I=A:H
ISS_MAX = 1 - (1 - 0.56)**3                 # 0.914816...
IMP_MAX = 7.52 * (ISS_MAX - 0.029) - 3.25 * ((ISS_MAX - 0.02)**15)  # 6.0477304915445185
IMP_T1 = IMP_MAX / 3                        # 2.0159101638481727
IMP_T2 = 2 * IMP_MAX / 3                    # 4.031820327696345

def _parse_vector(v):
    if not v:
        return None
    v = v.strip()
    if v.startswith("CVSS:"):
        v = v.split("/", 1)[1] if "/" in v else ""
    parts = [p for p in v.split("/") if ":" in p]
    m = {k.upper(): val.upper() for k, val in (p.split(":", 1) for p in parts)}
    need = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    return m if need.issubset(m) else None

def cvss_subscores_from_vector(vector):
    """Retorna (exploitability, impact) sem arredondar (floats)."""
    m = _parse_vector(vector)
    if not m:
        return None, None

    S  = m["S"]
    AV = CVSS_METRICS["AV"][m["AV"]]
    AC = CVSS_METRICS["AC"][m["AC"]]
    PR = CVSS_METRICS["PR_C" if S == "C" else "PR_U"][m["PR"]]
    UI = CVSS_METRICS["UI"][m["UI"]]
    exploitability = 8.22 * AV * AC * PR * UI

    C  = CVSS_METRICS["C"][m["C"]]
    I  = CVSS_METRICS["I"][m["I"]]
    A  = CVSS_METRICS["A"][m["A"]]
    ISS = 1 - (1 - C) * (1 - I) * (1 - A)

    if S == "U":
        impact = 6.42 * ISS
    else:
        impact = 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)

    # clamp defensivo
    exploitability = max(0.0, min(exploitability, EXP_MAX))
    impact = max(0.0, min(impact, IMP_MAX))
    return exploitability, impact

def classificar_impacto_por_subscore(impact):
    if impact is None:
        return "Desconhecido", "🔵"
    if impact > IMP_T2:
        return "Alto", "🔴"
    elif impact > IMP_T1:
        return "Médio", "🟠"
    else:
        return "Baixo", "🟡"

def classificar_probabilidade_por_subscore(expl):
    if expl is None:
        return "Desconhecido", "🔵"
    if expl > EXP_T2:
        return "Alto", "🔴"
    elif expl > EXP_T1:
        return "Médio", "🟠"
    else:
        return "Baixo", "🟡"

# ---------- OWASP ----------
OWASP_MULTI_MAP = {
    "clickjacking": ["A04-2021: Insecure Design", "A05: Security Misconfiguration"],
    "open redirect": [ "A04: Insecure Design"],
    "malware": ["A06-2021: Vulnerable and Outdated Components"],
    "data exposure": ["A02-2021: Cryptographic Failures"],
    "sensitive data": ["A02-2021: Cryptographic Failures"],
    "token leakage": ["A07-2021: Identification and Authentication Failures"],
    "csrf": ["A01-2021: Broken Access Control", "A04: Insecure Design"],
    "sql injection": ["A03-2021: Injection"],
    "xss": ["A03-2021: Injection"],
    "command injection": ["A03-2021: Injection"],
    "file upload": ["A08-2021: Software and Data Integrity Failures", "A04: Insecure Design"],
    "unauthorized access": ["A01-2021: Broken Access Control"],
    "deserialization": ["A08-2021: Software and Data Integrity Failures"],
    "directory traversal": ["A05-2021: Security Misconfiguration"],
    "exposure via url": ["A02-2021: Cryptographic Failures"],
    "reputacao ip": ["A05-2021: Security Misconfiguration"],
    "google api key": ["A05-2021: Security Misconfiguration"]
}

def classify_owasp(nome):
    nome_l = nome.lower()
    cats = []
    for termo, lista in OWASP_MULTI_MAP.items():
        if termo in nome_l:
            cats.extend(lista)
    seen = set()
    dedup = [c for c in cats if not (c in seen or seen.add(c))]
    return ", ".join(dedup) if dedup else "Desconhecido"

# ---------- MITRE ----------
def fetch_mitre_techniques():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        techniques = []
        for obj in data.get("objects", []):
            if obj.get("type") == "attack-pattern":
                name = (obj.get("name") or "").lower()
                tid = "N/A"
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                        tid = ref["external_id"]
                        break
                tactics = [p.get("phase_name","") for p in obj.get("kill_chain_phases", [])
                           if p.get("kill_chain_name") == "mitre-attack"]
                techniques.append({"name": name, "id": tid, "tactics": tactics})
        return techniques
    except Exception as e:
        print(f"[yellow]Aviso: falha ao baixar MITRE ATT&CK ({e}). Continuando sem MITRE.[/yellow]")
        return []

def classify_mitre(nome, mitre_list):
    nome_l = nome.lower()
    for t in mitre_list:
        if t["name"] in nome_l:
            tactic = ", ".join(sorted(set(t["tactics"]))) or "Desconhecido"
            tech = t["name"].title()
            tid = t["id"]
            return tactic, f"{tech} ({tid})"
    return "Desconhecido", "Desconhecido"

# ---------- Pipeline ----------
def processar_arquivo(caminho, mitre_list):
    resultados = []
    with open(caminho, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or (row[0].strip().startswith("#")):
                continue
            if len(row) < 4:
                print(f"[red]Linha inválida (esperado 4 colunas):[/red] {row}")
                continue
            vuln_id, nome_vuln, score_str, vetor = [c.strip() for c in row[:4]]

            # score base é exibido como veio (sem arredondar)
            try:
                score = float(score_str)
            except ValueError:
                print(f"[red]Score inválido na linha:[/red] {row}")
                continue

            expl, imp = cvss_subscores_from_vector(vetor)
            impacto, cor_impacto = classificar_impacto_por_subscore(imp)
            probabilidade, cor_prob = classificar_probabilidade_por_subscore(expl)
            risco, cor_risco = classificar_risco_cvss(score)

            owasp_categoria = classify_owasp(nome_vuln)
            mitre_tatica, mitre_tecnica = classify_mitre(nome_vuln, mitre_list)

            resultados.append({
                "ID": vuln_id,
                "CVSS": score_str,  # mantém string original (sem arredondar)
                "Impacto": f"{cor_impacto} {impacto}",
                "Probabilidade": f"{cor_prob} {probabilidade}",
                "Risco": f"{cor_risco} {risco}",
                "OWASP": owasp_categoria,
                "MITRE_TATICA": mitre_tatica,
                "MITRE_TECNICA": mitre_tecnica
            })
    return resultados

def main():
    parser = argparse.ArgumentParser(description="Classificador de risco com OWASP e MITRE.")
    parser.add_argument('--input', required=True,
                        help='Caminho para arquivo .csv/.txt (ID,Nome,Score,Vetor)')
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
        table.add_row(
            r["ID"], str(r["CVSS"]), r["Impacto"], r["Probabilidade"], r["Risco"],
            r["OWASP"], r["MITRE_TATICA"], r["MITRE_TECNICA"]
        )

    console.print(table)

if __name__ == "__main__":
    main()
