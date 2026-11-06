import urllib.request, json, http.cookiejar, hashlib, os

BASE = 'http://127.0.0.1:8081'
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
jar = http.cookiejar.CookieJar()
for c in json.load(open(os.path.join(work, 'reg_cookies.json'), encoding='utf-8')):
    jar.set_cookie(http.cookiejar.Cookie(0, c['name'], c['value'], None, False, c['domain'], False, False, c['path'], True, False, None, False, None, None, {}))
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
username = 'awa_u1106a'
phone = '13966660001'
pwd = hashlib.sha256('awa@1234'.encode()).hexdigest()
body = json.dumps({'username': username, 'phone': phone, 'password': pwd, 'captcha': 'E65M', 'sms_code': '8594'}).encode()
req = urllib.request.Request(BASE + '/api/user/register', data=body, headers={'Content-Type': 'application/json'}, method='POST')
try:
    r = opener.open(req)
    print('register:', r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print('register HTTP', e.code, e.read().decode())
# save session cookie if auto-login? register doesn't auto-login; login now
body = json.dumps({'username': username, 'password': pwd}).encode()
req = urllib.request.Request(BASE + '/api/user/login', data=body, headers={'Content-Type': 'application/json'}, method='POST')
r = opener.open(req)
print('login:', r.status, r.read().decode())
cookies = [{'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path} for c in jar]
open(os.path.join(work, 'sessions', 'awa_u1106a.json'), 'w', encoding='utf-8').write(json.dumps({'Cookie': '; '.join(c['name'] + '=' + c['value'] for c in cookies)}))
print('cookies', cookies)
