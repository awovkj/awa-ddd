import urllib.request, json, os, sys
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
def req(product, status, session_file):
    cookie = json.load(open(os.path.join(work, 'sessions', session_file), encoding='utf-8-sig'))['Cookie']
    url = f'http://127.0.0.1:8081/api/merchant/products/{product}/status'
    body = json.dumps({'status': status}).encode()
    r = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/json', 'Cookie': cookie}, method='PUT')
    try:
        print(product, status, urllib.request.urlopen(r).read().decode())
    except urllib.error.HTTPError as e:
        print(product, status, 'HTTP', e.code, e.read().decode())

if __name__ == '__main__':
    product, status, sess = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    req(product, status, sess)
