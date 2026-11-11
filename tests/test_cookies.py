import requests
from scanner.cookie_analyzer import analyze_cookies
def test_cookie_values_never_exposed():
    r=requests.Response();r.url='http://localhost/';r.headers['Set-Cookie']='session=TOP_SECRET; Path=/'
    jar=requests.cookies.RequestsCookieJar();jar.set('session','TOP_SECRET',domain='localhost',path='/');r.cookies=jar
    fs=analyze_cookies(r,r.url);assert fs and all('TOP_SECRET' not in str(f) for f in fs)
