import json
import sqlite3

p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\assessment.sqlite3'
c = sqlite3.connect(p)
ops = {}
for oid, doc in c.execute("SELECT id, document FROM entities WHERE kind='operation'"):
    d = json.loads(doc)
    ops[oid] = d
for oid, doc in c.execute("SELECT id, document FROM entities WHERE kind='obligation'"):
    d = json.loads(doc)
    if d.get('kind') != 'baseline' or d.get('status') != 'open':
        continue
    op = ops.get(d.get('operation_id'), {})
    if op.get('auth') == 'public' and op.get('method') == 'GET' and not op.get('inputs'):
        print(d['id'], d['operation_id'], op.get('url'))
