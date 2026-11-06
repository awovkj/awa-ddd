import urllib.request, json, http.cookiejar, hashlib, os

BASE = 'http://127.0.0.1:8081'
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
jar = http.cookiejar.CookieJar()
for c in json.load(open(os.path.join(work, 'reg_bypass_cookies.json'), encoding='utf-8')):
    jar.set_cookie(http.cookiejar.Cookie(0, c['name'], c['value'], None, False, c['domain'], False, False, c['path'], True, False, None, False, None, None, {}))
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
username = 'awa_u1106b'
phone_b = '13966660006'
pwd = hashlib.sha256('awa@1234'.encode()).hexdigest()
body = json.dumps({'username': username, 'phone': phone_b, 'password': pwd, 'captcha': 'YAAS', 'sms_code': '2320'}).encode()
req = urllib.request.Request(BASE + '/api/user/register', data=body, headers={'Content-Type': 'application/json'}, method='POST')
try:
    r = opener.open(req)
    print('register with unverified phone:', r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print('register HTTP', e.code, e.read().decode())
