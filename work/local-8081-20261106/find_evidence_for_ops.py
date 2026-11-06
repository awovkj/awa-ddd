import glob
import json
import os
import sqlite3

base = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\evidence'
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\assessment.sqlite3'
c = sqlite3.connect(p)
ops = {}
for oid, doc in c.execute("SELECT id, document FROM entities WHERE kind='operation'"):
    ops[oid] = json.loads(doc)
want = []
for oid, doc in c.execute("SELECT id, document FROM entities WHERE kind='obligation'"):
    d = json.loads(doc)
    if d.get('kind') == 'baseline' and d.get('status') == 'open':
        op = ops.get(d.get('operation_id'), {})
        if op.get('auth') == 'public':
            want.append((d['id'], d['operation_id'], op.get('url')))
for ob, op, url in want:
    found = []
    for path in glob.glob(base + r'\E-*.json'):
        j = json.load(open(path, encoding='utf-8'))
        if j.get('operation_id') == op:
            found.append((os.path.basename(path), j['response'].get('body_sha256'), j['response'].get('status')))
    print(ob, op, url, found[:3])
