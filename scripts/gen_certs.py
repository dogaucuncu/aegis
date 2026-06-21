"""mTLS için kendinden-imzalı CA + sunucu + istemci sertifikaları üretir.

Çıktı (certs/):
  ca.pem / ca.key            kök sertifika otoritesi
  server.pem / server.key    sunucu (CN=localhost, SAN: localhost,127.0.0.1)
  client.pem / client.key    ajan istemci sertifikası

Sunucuyu mTLS ile çalıştır:
  uvicorn app.main:app --port 8443 \
    --ssl-keyfile ../certs/server.key --ssl-certfile ../certs/server.pem \
    --ssl-ca-certs ../certs/ca.pem --ssl-cert-reqs 2
"""
import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS = Path(__file__).resolve().parent.parent / "certs"


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _save_key(key, path):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _save_cert(cert, path):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def main():
    CERTS.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    later = now + dt.timedelta(days=825)

    # --- CA ---
    ca_key = _key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis Dev CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(later)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    _save_key(ca_key, CERTS / "ca.key")
    _save_cert(ca_cert, CERTS / "ca.pem")

    # --- Sunucu ---
    srv_key = _key()
    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(later)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    _save_key(srv_key, CERTS / "server.key")
    _save_cert(srv_cert, CERTS / "server.pem")

    # --- İstemci (ajan) ---
    cli_key = _key()
    cli_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aegis-agent")]))
        .issuer_name(ca_name)
        .public_key(cli_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(later)
        .sign(ca_key, hashes.SHA256())
    )
    _save_key(cli_key, CERTS / "client.key")
    _save_cert(cli_cert, CERTS / "client.pem")

    print(f"[gen_certs] Sertifikalar uretildi: {CERTS}")
    for f in ["ca.pem", "server.pem", "server.key", "client.pem", "client.key"]:
        print(f"  {f}")


if __name__ == "__main__":
    main()
