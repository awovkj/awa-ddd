import urllib.request, urllib.parse, urllib.error
base = 'http://127.0.0.1:8081/api/merchant/products/'
for p in ["SP20260101001'", "SP20260101001'OR'1'='1", "SP20260101001' OR '1'='1", "SP20260101001"]:
    url = base + urllib.parse.quote(p)
    try:
        r = urllib.request.urlopen(url)
        print(repr(p), r.status, r.read().decode()[:200])
    except urllib.error.HTTPError as e:
        print(repr(p), 'HTTP', e.code, e.read().decode()[:200])
    except Exception as e:
        print(repr(p), 'ERR', type(e).__name__, str(e)[:100])
