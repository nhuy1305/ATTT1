from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
from aes import aes_encrypt, aes_decrypt


import sys
sys.stdout.reconfigure(encoding='utf-8')

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            with open("templates/index.html", "r", encoding="utf-8") as f:
                self.wfile.write(f.read().encode("utf-8"))
        elif self.path.startswith("/encrypt"):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            text = params.get("text", [""])[0]
            key = params.get("key", [""])[0]
            try:
                result = aes_encrypt(text, key)
            except Exception as e:
                result = f"Lỗi: {e}"
            self._send_text(result)
        elif self.path.startswith("/decrypt"):
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            text = params.get("text", [""])[0]
            key = params.get("key", [""])[0]
            try:
                result = aes_decrypt(text, key)
            except Exception as e:
                result = f"Lỗi: {e}"
            self._send_text(result)
        else:
            self.send_response(404)
            self.end_headers()

    def _send_text(self, text):
        self.send_response(200)
        self.send_header("Content-type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode("utf-8"))

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 5000), MyHandler)
    print("Server đang chạy tại http://localhost:5000")
    server.serve_forever()
