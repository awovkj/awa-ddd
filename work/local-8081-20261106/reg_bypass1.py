import urllib.request, urllib.parse, json, http.cookiejar, os

BASE = 'http://127.0.0.1:8081'
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
r = opener.open(BASE + '/api/user/captcha?t=2')
open(os.path.join(work, 'captcha2.png'), 'wb').write(r.read())
phone_a = '13966660005'
body = json.dumps({'phone': phone_a, 'type': 'register'}).encode()
req = urllib.request.Request(BASE + '/api/user/sms/send', data=body, headers={'Content-Type': 'application/json'}, method='POST')
print('sms send:', opener.open(req).read().decode())
sms = json.loads(opener.open(BASE + '/api/sms/list?phone=' + urllib.parse.quote(phone_a)).read().decode())
print('sms list:', json.dumps(sms, ensure_ascii=False))
cookies = [{'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path} for c in jar]
open(os.path.join(work, 'reg_bypass_cookies.json'), 'w', encoding='utf-8').write(json.dumps(cookies))
print('cookies', cookies)
