import urllib.request, urllib.parse, json, http.cookiejar, hashlib, re

BASE = 'http://127.0.0.1:8081'
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
phone = '13966660001'
opener.open(BASE + '/api/session-state').read()
body = json.dumps({'phone': phone, 'type': 'reset_password'}).encode()
req = urllib.request.Request(BASE + '/api/user/sms/send', data=body, headers={'Content-Type': 'application/json'}, method='POST')
print('sms send:', opener.open(req).read().decode())
sms = json.loads(opener.open(BASE + '/api/sms/list?phone=' + urllib.parse.quote(phone)).read().decode())
print('sms list:', json.dumps(sms, ensure_ascii=False)[:800])
# newest first
code = re.search(r'(\d{4})', sms['data']['list'][0]['content']).group(1)
body = json.dumps({'phone': phone, 'sms_code': code, 'user_type': 'user'}).encode()
req = urllib.request.Request(BASE + '/api/user/password/forgot', data=body, headers={'Content-Type': 'application/json'}, method='POST')
r = opener.open(req).read().decode()
print('forgot:', r)
token = json.loads(r)['data']['auth_token']
print('TOKEN=' + token)
