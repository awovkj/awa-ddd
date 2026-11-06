import urllib.request, urllib.parse, json

def call(k):
    url = 'http://127.0.0.1:8081/api/products/search?keyword=' + urllib.parse.quote(k)
    try:
        r = urllib.request.urlopen(url)
        body = r.read().decode('utf-8', 'replace')
        j = json.loads(body)
        prods = (j.get('data') or {}).get('products') if j.get('data') else None
        print('KEY=', repr(k), 'STATUS=', r.status, 'SUCCESS=', j.get('success'), 'N=', len(prods) if prods is not None else None, 'MSG=', j.get('message'))
        if prods:
            print('  first=', prods[0].get('name'), prods[0].get('product_no'))
    except Exception as e:
        print('KEY=', repr(k), 'ERR=', type(e).__name__, str(e)[:200])

for k in ["zzzzzz", "%'OR'1'='1", "%'or'1'='1", "%'OR'1'='2", "AWA%'OR'1'='1", "%' UNION SELECT 1--"]:
    call(k)
