import socket
import struct
from typing import Dict, Any

# IANA TLS Supported Groups for PQC & Hybrid Key Agreement
PQC_GROUPS = {
    0x11EC: "X25519MLKEM768 (Standardized Hybrid)",
    0x11ED: "SecP256r1MLKEM768 (Standardized Hybrid)",
    0x6399: "X25519Kyber768Draft00 (Experimental)",
    0x0201: "MLKEM768 (Pure PQC)",
}

CLASSICAL_GROUPS = {
    0x001D: "x25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
}


def build_tls13_pqc_client_hello(hostname: str) -> bytes:
    """Builds a raw TLS 1.3 ClientHello proposing Post-Quantum and Classical groups."""
    hostname_bytes = hostname.encode("utf-8")

    # SNI Extension
    sni_data = (
        struct.pack(">H", len(hostname_bytes) + 3)
        + b"\x00"
        + struct.pack(">H", len(hostname_bytes))
        + hostname_bytes
    )
    sni_ext = struct.pack(">H", 0x0000) + struct.pack(">H", len(sni_data)) + sni_data

    # Supported Groups Extension (PQC groups + Classical)
    all_groups = list(PQC_GROUPS.keys()) + list(CLASSICAL_GROUPS.keys())
    groups_data = struct.pack(">H", len(all_groups) * 2) + b"".join(
        struct.pack(">H", g) for g in all_groups
    )
    groups_ext = struct.pack(">H", 0x000A) + struct.pack(">H", len(groups_data)) + groups_data

    # Supported Versions Extension (TLS 1.3 = 0x0304)
    versions_data = struct.pack("B", 2) + struct.pack(">H", 0x0304)
    versions_ext = struct.pack(">H", 0x002B) + struct.pack(">H", len(versions_data)) + versions_data

    # Key Share Extension dummy (1216 bytes for ML-KEM-768 hybrid payload allocation)
    key_share_group = 0x11EC  # X25519MLKEM768
    dummy_key_exchange = b"\x00" * 1216
    key_share_entry = struct.pack(">HH", key_share_group, len(dummy_key_exchange)) + dummy_key_exchange
    key_share_data = struct.pack(">H", len(key_share_entry)) + key_share_entry
    key_share_ext = struct.pack(">H", 0x0033) + struct.pack(">H", len(key_share_data)) + key_share_data

    # Assemble extensions
    extensions = sni_ext + groups_ext + versions_ext + key_share_ext
    extensions_block = struct.pack(">H", len(extensions)) + extensions

    # Cipher Suites (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)
    cipher_suites = struct.pack(">H", 6) + struct.pack(">HHH", 0x1301, 0x1302, 0x1303)
    compression = b"\x01\x00"
    random_bytes = b"\x42" * 32
    session_id = b"\x00"

    handshake_body = (
        struct.pack(">H", 0x0303)  # Client Version (TLS 1.2 legacy field)
        + random_bytes
        + session_id
        + cipher_suites
        + compression
        + extensions_block
    )

    handshake_header = struct.pack("B", 0x01) + struct.pack(">I", len(handshake_body))[1:]
    record_layer = struct.pack(">H", 0x1603) + struct.pack("B", 0x01) + struct.pack(">H", len(handshake_header + handshake_body))
    return record_layer + handshake_header + handshake_body


def inspect_pqc_negotiation(host: str, port: int = 443, timeout: float = 4.0) -> Dict[str, Any]:
    """Tests if the remote endpoint accepts Post-Quantum key exchanges."""
    result = {
        "pqc_supported": False,
        "negotiated_group": None,
        "tls13_supported": False,
        "raw_status": "Classical Only",
    }

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        payload = build_tls13_pqc_client_hello(host)
        sock.sendall(payload)
        response = sock.recv(4096)
        sock.close()

        if len(response) >= 5 and response[0] == 0x16:  # Handshake record
            result["tls13_supported"] = True
            for pq_code, pq_name in PQC_GROUPS.items():
                group_bytes = struct.pack(">H", pq_code)
                if group_bytes in response:
                    result["pqc_supported"] = True
                    result["negotiated_group"] = pq_name
                    result["raw_status"] = "Quantum-Resilient (Hybrid PQC)"
                    break
    except Exception as e:
        result["raw_status"] = f"Handshake error: {str(e)[:35]}"

    return result
