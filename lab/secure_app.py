from flask import Flask, make_response, request
from werkzeug.serving import make_server, WSGIRequestHandler
import threading
app=Flask(__name__)
@app.before_request
def https_redirect():
    if request.headers.get("X-Forwarded-Proto")!="https":return None
@app.get("/")
def index():
    r=make_response("<h1>VulnScan Local Secure Lab</h1>");r.set_cookie("lab_session","TEST_ONLY_VALUE",secure=True,httponly=True,samesite="Lax")
    r.headers.update({"Content-Security-Policy":"default-src 'self'; object-src 'none'; frame-ancestors 'none'","Strict-Transport-Security":"max-age=31536000","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"strict-origin-when-cross-origin","Permissions-Policy":"camera=(), microphone=()"})
    r.headers.pop("Server",None); return r
@app.get("/robots.txt")
def robots():return "User-agent: *\nDisallow:\n",200,{"Content-Type":"text/plain","X-Content-Type-Options":"nosniff"}
if __name__=="__main__":
    class QuietHandler(WSGIRequestHandler):
        server_version=""; sys_version=""
    server=make_server("127.0.0.1",8082,app,request_handler=QuietHandler)
    server.serve_forever()
