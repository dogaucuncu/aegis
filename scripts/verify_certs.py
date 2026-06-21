"""Üretilen sertifikaların öznelerini ve CA imza zincirini doğrular."""
from pathlib import Path

from cryptography import x509

CERTS = Path(__file__).resolve().parent.parent / "certs"


def main():
    for name in ["ca.pem", "server.pem", "client.pem"]:
        cert = x509.load_pem_x509_certificate((CERTS / name).read_bytes())
        san = ""
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = " SAN=" + ",".join(str(g.value) for g in ext.value)
        except x509.ExtensionNotFound:
            pass
        print(f"{name:12} subject={cert.subject.rfc4514_string():22} issuer={cert.issuer.rfc4514_string()}{san}")


if __name__ == "__main__":
    main()
