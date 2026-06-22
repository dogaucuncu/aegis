"""In-memory (MemoryBIO) mTLS self-test.

Proves that the certificates correctly provide mutual authentication (mutual TLS)
without going out to the network layer (and thus without local TLS interception).

  - Server: server.pem/key, verifies the client with the CA, CERT_REQUIRED
  - Client: client.pem/key, verifies the server with the CA (hostname=localhost)

Usage: python scripts/mtls_selftest.py
"""
import ssl
from pathlib import Path

CERTS = Path(__file__).resolve().parent.parent / "certs"


def _cn(peer_cert) -> str:
    if not peer_cert:
        return "(none)"
    for rdn in peer_cert.get("subject", ()):
        for k, v in rdn:
            if k == "commonName":
                return v
    return "(unknown)"


def main():
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(CERTS / "server.pem", CERTS / "server.key")
    server_ctx.load_verify_locations(CERTS / "ca.pem")
    server_ctx.verify_mode = ssl.CERT_REQUIRED  # client certificate required

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

    assert cdone and sdone, "Handshake could not be completed"
    print("mTLS handshake: SUCCESS")
    print(f"  Server saw client : CN={_cn(sobj.getpeercert())}")
    print(f"  Client saw server : CN={_cn(cobj.getpeercert())}")
    print(f"  Cipher suite      : {cobj.cipher()[0]}")


if __name__ == "__main__":
    main()
