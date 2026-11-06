import http.cookiejar
import hashlib
import json
import urllib.request

base = 'http://127.0.0.1:8081'
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
body = json.dumps({
    'username': 'awa_shop1106x',
    'password': hashlib.sha256(b'shop@1234').hexdigest(),
}).encode()
req = urllib.request.Request(base + '/api/merchant/login', data=body, headers={'Content-Type': 'application/json'})
print(opener.open(req).read().decode())
cookies = '; '.join(f'{c.name}={c.value}' for c in jar)
path = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106\sessions\awa_shop1106x.json'
open(path, 'w', encoding='utf-8').write(json.dumps({'Cookie': cookies}))
print(path, cookies)
