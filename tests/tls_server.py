"""Minimal HTTPS server for testing recon.tls against real certificates.

Serves whichever cert/key pair PTX_TLS_CERT / PTX_TLS_KEY name, on PTX_TLS_PORT.
"""
import os, ssl, http.server, threading, sys

CERT = os.environ.get("PTX_TLS_CERT", "tests/certs/c1.pem")
KEY  = os.environ.get("PTX_TLS_KEY",  "tests/certs/k1.pem")
PORT = int(os.environ.get("PTX_TLS_PORT", "8443"))


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass


def serve(port=PORT, cert=CERT, key=KEY):
    httpd = http.server.HTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == "__main__":
    print(f"serving {CERT} on {PORT}", flush=True)
    serve()
