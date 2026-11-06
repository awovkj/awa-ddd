import urllib.request, urllib.parse, http.cookiejar, json, os

BASE = 'http://127.0.0.1:8081'
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
# get captcha
r = opener.open(BASE + '/api/user/captcha?t=1')
data = r.read()
open(os.path.join(work, 'captcha.png'), 'wb').write(data)
print('captcha bytes', len(data))
# send sms
phone = '13966660001'
body = json.dumps({'phone': phone, 'type': 'register'}).encode()
req = urllib.request.Request(BASE + '/api/user/sms/send', data=body, headers={'Content-Type': 'application/json'}, method='POST')
r = opener.open(req)
print('sms send:', r.read().decode())
# retrieve sms
r = opener.open(BASE + '/api/sms/list?phone=' + urllib.parse.quote(phone))
print('sms list:', r.read().decode()[:1000])
# save cookies
cookies = [{'name': c.name, 'value': c.value, 'domain': c.domain, 'path': c.path} for c in jar]
open(os.path.join(work, 'reg_cookies.json'), 'w', encoding='utf-8').write(json.dumps(cookies))
print('cookies', cookies)
