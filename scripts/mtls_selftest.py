"""mTLS bellek-içi (MemoryBIO) öz-testi.

Sertifikaların karşılıklı kimlik doğrulamayı (mutual TLS) doğru sağladığını
ağ katmanına (ve dolayısıyla yerel TLS araya-girmesine) çıkmadan kanıtlar.

  - Sunucu: server.pem/key, client'ı CA ile doğrular, CERT_REQUIRED
  - İstemci: client.pem/key, server'ı CA ile doğrular (hostname=localhost)

Kullanım: python scripts/mtls_selftest.py
"""
import ssl
from pathlib import Path

CERTS = Path(__file__).resolve().parent.parent / "certs"


def _cn(peer_cert) -> str:
    if not peer_cert:
        return "(yok)"
    for rdn in peer_cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return "(bilinmiyor)"


def main():
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(CERTS / "server.pem", CERTS / "server.key")
    server_ctx.load_verify_locations(CERTS / "ca.pem")
    server_ctx.verify_mode = ssl.CERT_REQUIRED  # istemci sertifikası zorunlu

    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_cert_chain(CERTS / "client.pem", CERTS / "client.key")
    client_ctx.load_verify_locations(CERTS / "ca.pem")
    client_ctx.check_hostname = True

    c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    cobj = client_ctx.wrap_bio(c_in, c_out, server_hostname="localhost")
    sobj = server_ctx.wrap_bio(s_in, s_out, server_side=True)

    def step(obj):
        try:
            obj.do_handshake()
            return True
        except ssl.SSLWantReadError:
            return False

    cdone = sdone = False
    for _ in range(50):
        if not cdone:
            cdone = step(cobj)
        data = c_out.read()
        if data:
            s_in.write(data)
        if not sdone:
            sdone = step(sobj)
        data = s_out.read()
        if data:
            c_in.write(data)
        if cdone and sdone:
            break

    assert cdone and sdone, "El sıkışması tamamlanamadı"
    print("mTLS el sıkışması: BAŞARILI")
    print(f"  Sunucu, istemciyi gördü : CN={_cn(sobj.getpeercert())}")
    print(f"  İstemci, sunucuyu gördü : CN={_cn(cobj.getpeercert())}")
    print(f"  Şifre paketi            : {cobj.cipher()[0]}")


if __name__ == "__main__":
    main()
