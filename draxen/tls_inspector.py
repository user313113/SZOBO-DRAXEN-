import socket
import ssl
from datetime import datetime, timezone

from .core import public_ip

SIG_OIDS = {
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04": ("MD5-RSA", True),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05": ("SHA1-RSA", True),
    b"\x2a\x86\x48\xce\x3d\x04\x01": ("SHA1-ECDSA", True),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b": ("SHA256-RSA", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c": ("SHA384-RSA", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d": ("SHA512-RSA", False),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x02": ("SHA256-ECDSA", False),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x03": ("SHA384-ECDSA", False),
    b"\x2b\x65\x70": ("Ed25519", False),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x04": ("SHA512-ECDSA", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0e": ("SHA224-RSA", False),
    b"\x2a\x86\x48\xce\x3d\x04\x03\x01": ("SHA224-ECDSA", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x02": ("MD2-RSA", True),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x03": ("MD4-RSA", True),
    b"\x2b\x65\x71": ("Ed448", False),
    b"\x2a\x86\x48\xce\x3d\x02\x01": ("ECC-Generic", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01": ("RSA-Generic", False),
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a": ("RSASSA-PSS", False),
}


def extract_sig_alg(der_bytes):
    if not isinstance(der_bytes, (bytes, bytearray)):
        return "Bilinmiyor", False
    for oid_bytes, (name, is_weak) in SIG_OIDS.items():
        if oid_bytes in der_bytes:
            return name, is_weak
    return "Bilinmiyor", False


def inspect_tls(domain, timeout=8):
    try:
        addr_info = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        if not addr_info:
            return None
        target_ip = addr_info[0][4][0]
        if not public_ip(target_ip):
            return None
    except Exception:
        return None

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((target_ip, 443), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssock:
                protocol = ssock.version() or "Bilinmiyor"
                cipher_name, _, cipher_bits = ssock.cipher() or ("Bilinmiyor", None, 0)
                cert = ssock.getpeercert() or {}
                der_cert = None
                try:
                    der_cert = ssock.getpeercert(binary_form=True)
                except Exception:
                    pass

                sig_alg, is_weak_sig = extract_sig_alg(der_cert)
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sans = [item[1] for item in cert.get("subjectAltName", []) if item[0] == "DNS"]

                not_before_str = cert.get("notBefore", "")
                not_after_str = cert.get("notAfter", "")
                days_left = None
                validity_days = None
                expiry_iso = None
                start_iso = None

                dt_before = None
                dt_after = None

                if not_before_str:
                    try:
                        dt_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        start_iso = dt_before.isoformat()
                    except Exception:
                        pass

                if not_after_str:
                    try:
                        dt_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        expiry_iso = dt_after.isoformat()
                        days_left = (dt_after - datetime.now(timezone.utc)).days
                    except Exception:
                        pass

                if dt_before and dt_after:
                    validity_days = (dt_after - dt_before).days

                is_self_signed = (subject.get("commonName") == issuer.get("commonName") and subject.get("organizationName") == issuer.get("organizationName"))
                common_name = subject.get("commonName", "")
                is_wildcard = common_name.startswith("*.") or any(s.startswith("*.") for s in sans)
                is_expired = days_left is not None and days_left < 0

                return {
                    "ip": target_ip,
                    "protocol": protocol,
                    "cipher": cipher_name,
                    "cipher_bits": cipher_bits,
                    "signature_algorithm": sig_alg,
                    "is_weak_signature": is_weak_sig,
                    "serial_number": cert.get("serialNumber", ""),
                    "version": cert.get("version", 3),
                    "subject_cn": common_name,
                    "issuer_cn": issuer.get("commonName", ""),
                    "issuer_org": issuer.get("organizationName", ""),
                    "sans": sans,
                    "not_before": start_iso,
                    "not_after": expiry_iso,
                    "validity_days": validity_days,
                    "days_until_expiry": days_left,
                    "is_expired": is_expired,
                    "is_self_signed": is_self_signed,
                    "is_wildcard": is_wildcard,
                }
    except Exception:
        return None
