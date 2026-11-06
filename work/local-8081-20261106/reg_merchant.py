import urllib.request, urllib.parse, json, http.cookiejar, hashlib, os

BASE = 'http://127.0.0.1:8081'
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
phone = '13966660002'
# establish session + send sms
opener.open(BASE + '/api/session-state').read()
body = json.dumps({'phone': phone, 'type': 'register'}).encode()
req = urllib.request.Request(BASE + '/api/user/sms/send', data=body, headers={'Content-Type': 'application/json'}, method='POST')
print('sms send:', opener.open(req).read().decode())
r = opener.open(BASE + '/api/sms/list?phone=' + urllib.parse.quote(phone))
sms = json.loads(r.read().decode())
print('sms list:', json.dumps(sms, ensure_ascii=False))
content = sms['data']['list'][0]['content']
import re
m = re.search(r'(\d{4})', content)
code = m.group(1)
username = 'awa_shop1106a'
pwd = hashlib.sha256('shop@1234'.encode()).hexdigest()
body = json.dumps({'username': username, 'shop_name': 'AWA Shop 1106', 'phone': phone, 'password': pwd, 'sms_code': code}).encode()
req = urllib.request.Request(BASE + '/api/merchant/register', data=body, headers={'Content-Type': 'application/json'}, method='POST')
print('merchant register:', opener.open(req).read().decode())
cookies = [{'name': c.name, 'value': c.value} for c in jar]
print('cookies', cookies)
open(os.path.join(work, 'sessions', 'awa_shop1106a.json'), 'w', encoding='utf-8').write(json.dumps({'Cookie': '; '.join(c['name'] + '=' + c['value'] for c in cookies)}))
