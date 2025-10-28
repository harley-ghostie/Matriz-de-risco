# Matriz-de-risco
📊 <b>Classificador de Riscos CVSS + OWASP + MITRE - Modelo 3x3<br></b>

Este script em Python realiza a classificação automatizada de vulnerabilidades com base em:<br>

🎯 CVSS Base Score (impacto, probabilidade e nível de risco)<br>

🛡️ OWASP Top 10 2021 (com múltiplas categorias por vulnerabilidade)<br>

🕵️‍♂️ MITRE ATT&CK (associação por tática e técnica, se aplicável)<br>


📁 Estrutura esperada do arquivo .txt<br>
Cada linha representa uma vulnerabilidade:<br>
<ID>,<Nome>,<CVSS Base Score>,<Vetores CVSS><br>
Exemplo:
    
    SAFE-001,MALWARE NO ARQUIVO EXECUTÁVEL,9.8,AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

🔍 Classificação automatizada:<br>
  <b>Impacto:</b> <br>
  🟡 Baixo <br>
  🟠 Médio <br> 
  🔴 Alto<br>
  <b>Probabilidade:</b> <br>
  🟡 Baixo  <br>
  🟠 Médio  <br>
  🔴 Alto<br>
  <b>Risco:</b><br>
  🔵 Informativo <br>
  🟡 Baixo <br>
  🟠 Médio <br>
  🔴 Alto <br>
  ⚫ Crítico<br>
  OWASP Top 10 (1 ou mais categorias por vulnerabilidade)<br>
  MITRE ATT&CK (se nome corresponder a alguma técnica conhecida)<br>

🖥️ Saída em terminal com tabela colorida (via rich) — ideal para relatórios rápidos.<br>
<img width="1337" height="403" alt="image" src="https://github.com/user-attachments/assets/3a722abe-19e8-49c0-804e-07683af11fa0" />

🚀 <b>Como usar<br></b>
Instale os requisitos:<br>

    pip install rich requests

Execute o script com o arquivo de entrada:<br>

    python classificador_risco.py --input vuln-safe.txt

🧠 Lógica de Classificação<br>

<b>Impacto e Probabilidade:</b> calculados com base no CVSS Base Score.<br>
<b>Risco: </b>definido por faixa CVSS conforme tabela oficial.<br>
<b>OWASP:</b> mapeado por palavras-chave reconhecidas no nome da vulnerabilidade. Pode retornar múltiplas categorias.<br>
<b>MITRE:</b> usa lista oficial pública do MITRE ATT&CK via JSON para cruzamento de nome.<br>

📌 <b>Referências<br></b>
OWASP Top 10 2021<br>
MITRE ATT&CK Framework<br>
CVSS v3.1<br>
