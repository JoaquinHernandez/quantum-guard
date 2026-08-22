from typing import List, Dict, Any


def calculate_security_grade(
    pqc_status: bool,
    tls_version: str,
    open_ports: List[Dict[str, Any]],
    headers: Dict[str, str],
) -> Dict[str, Any]:
    score = 100
    deductions = []

    if not pqc_status:
        score -= 25
        deductions.append("Lacks Post-Quantum Key Exchange (Vulnerable to HNDL attacks)")

    if "TLSv1.3" not in tls_version:
        score -= 20
        deductions.append("Not enforcing TLS 1.3")

    dangerous_ports = {21, 23, 3306, 3389, 6379, 27017}
    for p in open_ports:
        if p["port"] in dangerous_ports:
            score -= 15
            deductions.append(f"High-risk perimeter port exposed: {p['port']} ({p['service']})")

    if not headers.get("Strict-Transport-Security") and not headers.get("strict-transport-security"):
        score -= 10
        deductions.append("Missing HSTS Header (SSL Stripping risk)")

    if not headers.get("Content-Security-Policy") and not headers.get("content-security-policy"):
        score -= 5
        deductions.append("Missing Content-Security-Policy (CSP)")

    score = max(0, score)

    if score >= 90:
        grade = "A+ (Quantum Ready)"
    elif score >= 80:
        grade = "A (Modern Classical)"
    elif score >= 65:
        grade = "B (Acceptable)"
    elif score >= 50:
        grade = "C (Action Required)"
    else:
        grade = "F (High Risk)"

    return {"score": score, "grade": grade, "deductions": deductions}
