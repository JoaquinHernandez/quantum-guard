import asyncio
from typing import List, Dict, Any

COMMON_PORTS = {
    21: "FTP (Plaintext)",
    22: "SSH",
    23: "Telnet (Insecure)",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis (Exposed Cache)",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB (Exposed NoSQL)",
}


async def probe_port(host: str, port: int, timeout: float = 1.2) -> Dict[str, Any]:
    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "state": "OPEN"}
    except Exception:
        return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "state": "CLOSED"}


async def scan_perimeter(host: str) -> List[Dict[str, Any]]:
    tasks = [probe_port(host, port) for port in COMMON_PORTS.keys()]
    results = await asyncio.gather(*tasks)
    return [res for res in results if res["state"] == "OPEN"]
