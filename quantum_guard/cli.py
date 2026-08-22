import argparse
import asyncio
import socket
import ssl
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from quantum_guard.pqc_engine import inspect_pqc_negotiation
from quantum_guard.port_scanner import scan_perimeter
from quantum_guard.scorer import calculate_security_grade

console = Console()


async def inspect_domain(domain: str):
    console.print(
        Panel(
            f"[bold cyan]quantum-guard Security Assessment[/bold cyan]\n[dim]Target: {domain}[/dim]",
            expand=False,
        )
    )

    # 1. PQC Check
    with console.status("[bold green]Testing Post-Quantum Cryptography support..."):
        pqc_data = inspect_pqc_negotiation(domain)

    # 2. SSL/TLS Standard Check
    tls_version = "Unknown"
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            tls_version = s.version() or "TLS Detected"
    except Exception:
        tls_version = "Failed Handshake"

    # 3. HTTP Security Headers
    headers = {}
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True) as client:
            resp = await client.get(f"https://{domain}")
            headers = dict(resp.headers)
    except Exception:
        pass

    # 4. Port Scan
    with console.status("[bold yellow]Auditing attack surface & open ports..."):
        open_ports = await scan_perimeter(domain)

    # 5. Score Calculation
    audit = calculate_security_grade(pqc_data["pqc_supported"], tls_version, open_ports, headers)

    # Render Results Table
    table = Table(title="Security & Quantum Readiness Matrix", border_style="bright_blue")
    table.add_column("Security Metric", style="cyan", no_wrap=True)
    table.add_column("Status / Findings", style="white")

    pqc_color = "green" if pqc_data["pqc_supported"] else "yellow"
    table.add_row("Post-Quantum KEM", f"[{pqc_color}]{pqc_data['raw_status']}[/{pqc_color}]")
    if pqc_data["negotiated_group"]:
        table.add_row("Negotiated Group", pqc_data["negotiated_group"])
    table.add_row("TLS Protocol", tls_version)
    has_hsts = bool(headers.get("strict-transport-security") or headers.get("Strict-Transport-Security"))
    table.add_row("HSTS Enabled", "[green]Yes[/green]" if has_hsts else "[red]Missing[/red]")
    table.add_row(
        "Open Services",
        ", ".join([f"{p['port']}/{p['service']}" for p in open_ports]) or "None exposed",
    )

    console.print(table)

    # Render Score Panel
    score_color = "green" if audit["score"] >= 80 else ("yellow" if audit["score"] >= 60 else "red")
    deductions_text = (
        "\n".join([f"• [red]Warning:[/red] {d}" for d in audit["deductions"]])
        if audit["deductions"]
        else "• [green]No major critical findings detected.[/green]"
    )

    console.print(
        Panel(
            f"Overall Grade: [{score_color} bold]{audit['grade']}[/{score_color} bold] ({audit['score']}/100)\n\n"
            + deductions_text,
            title="Posture Assessment",
            border_style=score_color,
        )
    )


def main():
    parser = argparse.ArgumentParser(
        prog="quantum-guard",
        description="quantum-guard: Post-Quantum Cryptography & Attack-Surface Auditor",
    )
    parser.add_argument("domain", help="Target domain (e.g., cloudflare.com, google.com)")
    args = parser.parse_args()
    clean_domain = args.domain.replace("https://", "").replace("http://", "").strip("/")
    asyncio.run(inspect_domain(clean_domain))


if __name__ == "__main__":
    main()
