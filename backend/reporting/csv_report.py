# backend/reporting/csv_report.py
import csv, io, json
from datetime import datetime, timezone

CSV_FIELDS = [
    'hostname', 'tls_version', 'cipher_suite', 'key_exchange',
    'forward_secrecy', 'cert_subject', 'cert_issuer', 'cert_not_before',
    'cert_not_after', 'cert_days_remaining', 'cert_sig_algorithm',
    'cert_key_size', 'cert_sha1_fp', 'cert_verified',
    'quantum_score', 'label', 'is_pqc_algorithm', 'hndl_risk', 'scanned_at'
]

def generate_csv_report(scan_results: list, cbom: dict = None) -> str:
    output = io.StringIO()

    # ─────────────────────────────
    # HEADER
    # ─────────────────────────────
    output.write("Q-SHIELD CSV REPORT\n")
    output.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")

    # ─────────────────────────────
    # EXECUTIVE SUMMARY 
    # ─────────────────────────────
    total = len(scan_results)
    avg_score = sum(r.get('quantum_score') or 0 for r in scan_results) / total if total else 0

    output.write("EXECUTIVE SUMMARY\n")
    output.write(f"Total Assets,{total}\n")
    output.write(f"Average Score,{round(avg_score,2)}\n\n")

    # ─────────────────────────────
    # ORIGINAL TABLE 
    # ─────────────────────────────
    w = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction='ignore')
    w.writeheader()

    for r in scan_results:
        row = {k: str(r.get(k, '')) for k in CSV_FIELDS}
        w.writerow(row)

    # ─────────────────────────────
    # VULNERABILITIES 
    # ─────────────────────────────
    output.write("\nVULNERABILITIES\n")
    output.write("hostname,vulnerability,severity\n")

    for r in scan_results:
        vulns = r.get('vulnerabilities', [])
        if isinstance(vulns, str):
            try:
                vulns = json.loads(vulns)
            except:
                vulns = []

        for v in vulns:
            output.write(f"{r.get('hostname')},{v.get('name')},{v.get('severity')}\n")

    # ─────────────────────────────
    # RECOMMENDATIONS 
    # ─────────────────────────────
    output.write("\nRECOMMENDATIONS\n")
    output.write("hostname,recommendation\n")

    for r in scan_results:
        recs = r.get('recommendations', [])
        if isinstance(recs, str):
            try:
                recs = json.loads(recs)
            except:
                recs = []

        for rec in recs:
            output.write(f"{r.get('hostname')},{rec}\n")

    # ─────────────────────────────
    # CBOM SUMMARY 
    # ─────────────────────────────
    if cbom:
        summary = cbom.get('summary', {})

        output.write("\nCBOM SUMMARY\n")
        output.write(f"Total Certificates,{summary.get('total_certs')}\n")
        output.write(f"Total Algorithms,{summary.get('total_algs')}\n")
        output.write(f"PQC Systems,{summary.get('pqc_count')}\n")
        output.write(f"Quantum Vulnerable,{summary.get('quantum_vulnerable')}\n")

    return output.getvalue()