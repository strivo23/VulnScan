from flask import Flask, make_response
app=Flask(__name__)
@app.get("/")
def index():
    r=make_response('<h1>VulnScan Local Vulnerable Lab</h1><a href="/listing/">Directory</a>')
    r.set_cookie("lab_session","TEST_ONLY_VALUE",httponly=False,samesite=None)
    r.headers["Server"]="LabServer/0.1"
    return r
@app.get("/robots.txt")
def robots():return "User-agent: *\nDisallow: /admin-panel/\n",200,{"Content-Type":"text/plain"}
@app.get("/sitemap.xml")
def sitemap():return "<urlset><url><loc>/</loc></url></urlset>",200,{"Content-Type":"application/xml"}
@app.get("/listing/")
def listing():return "<html><title>Index of /</title><h1>Index of /</h1><a href='backup.zip'>backup.zip</a></html>"
@app.get("/security.txt")
def security():return "Contact: mailto:security@example.invalid\n",200,{"Content-Type":"text/plain"}
if __name__=="__main__":app.run(host="127.0.0.1",port=8081,debug=False)
