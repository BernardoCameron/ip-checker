# IP Threat Intelligence Enricher
 
Script de enriquecimiento de IPs contra distintas fuentes de threat intelligence.

## Fuentes (Iniciales)

| Fuente | Datos | Free Tier |
|--------|-------|-----------|
| VirusTotal | Detecciones AV, reputación, ASN | 4 req/min |
| AbuseIPDB | Abuse score, reportes, ISP, TOR | 1000 req/día |
| Shodan | Puertos abiertos, banners, CVEs | 1 req/seg |
| IPInfo | Geolocalización, ASN, timezone | 50k req/mes |


## Configuración de API Keys
 
```bash
export VT_API_KEY="XXXX-API-KEY-XXXX"
export ABUSEIPDB_API_KEY="XXXX-API-KEY-XXXX"
export SHODAN_API_KEY="XXXX-API-KEY-XXXX"
export IPINFO_TOKEN="XXXX-API-KEY-XXXX"   # opcional, tiene tier sin token
```
 
O crea un archivo `.env`:
```
VT_API_KEY=XXXX-API-KEY-XXXX
ABUSEIPDB_API_KEY=XXXX-API-KEY-XXXX
SHODAN_API_KEY=XXXX-API-KEY-XXXX
```

## Uso
 
```bash
# Desde un .txt (una IP por línea)
python ip-check.py ips.txt
 
# Desde un Excel
python ip-check.py ips.xlsx
 
# Solo fuentes específicas
python ip-check.py ips.txt --sources virustotal abuseipdb
 
# Custom output name
python ip-check.py ips.txt --output reporte_2024-01
```
 
## Output
 
El script genera tres archivos:
 
- `ip_report.xlsx` — Excel con colores por severidad, columnas por fuente, hipervínculos
- `ip_report.json` — JSON completo con todos los datos raw
- `ip_report.html` — Reporte visual navegable en el browser

## Veredictos
 
| Veredicto | Criterio |
|-----------|----------|
| CRÍTICO | Score ≥ 15 |
| ALTO | Score 8–14 |
| MEDIO | Score 3–7 |
| BAJO | Score 1–2 |
| LIMPIO | Score = 0 |
 
El score se calcula combinando:
- VT detecciones maliciosas × 3 + sospechosas × 1
- AbuseIPDB: score >80 -> +10, >50 -> +5, >20 → +2; TOR -> +3
- Shodan: CVEs conocidos × 2 (máx 5)

## Estructura del proyecto
 
```
ip-threat-intel/
├── ip-check.py     # Script principal
├── requirements.txt
├── ips_test.txt       # Archivo con las IPs
└── README.md
```

Comprueba si tienes las dependencias de requirements.txt, de caso contrarui usa 
```bash
pip install -r requirements.txt
```

## Links

Todas las fuentes de informacion tienen su tier gratuito, por lo que puedes registrarte y obtener tu API Key sin costo pero limitado.
 
- **VirusTotal**: https://www.virustotal.com/gui/join-us
- **AbuseIPDB**: https://www.abuseipdb.com/register
- **Shodan**: https://account.shodan.io/register
- **IPInfo**: https://ipinfo.io/signup
