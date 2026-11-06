import json, base64, os
base = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\evidence'
ids = ["E-bc245f60bb8749f2af060edbf7adfbe5","E-1e90799c495a46c485f01842b16bdea8","E-8bfd2af39abf417b9092cabb26d2a888","E-bd67d1704ee8483a8ffaa72e912231ce","E-19c6647bd471458383d9e1f743102a9e","E-7dda5a300aa748fdbc23cd7b3ef02e89","E-05fd1ea26a0a4f77a925800c2f6c58a8","E-d0e458ccf5094f03b036b6c972ac8e46","E-1e58b42554264bee828b859a13821b14","E-43f72520652b44f2882b1f6570e5f7f0"]
ok = 0
for i in ids:
    j = json.load(open(os.path.join(base, i + '.json'), encoding='utf-8'))
    body = base64.b64decode(j['response']['body_base64']).decode('utf-8', 'replace')
    print(i, j['response']['status'], body)
    if '"success":true' in body:
        ok += 1
print('success count=', ok)
