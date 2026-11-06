import json
import sqlite3

p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\assessment.sqlite3'
c = sqlite3.connect(p)
ops = {}
for oid, doc in c.execute("SELECT id, document FROM entities WHERE kind='operation'"):
    ops[oid] = json.loads(doc)
evs = {}
for eid, doc in c.execute("SELECT id, document FROM entities WHERE kind='evidence'"):
    d = json.loads(doc)
    evs.setdefault(d.get('operation_id'), []).append((eid, d.get('status_code'), d.get('actor_id'), d.get('resource_id')))
for oid, doc in c.execute("SELECT id, document FROM entities WHERE kind='obligation'"):
    d = json.loads(doc)
    if d.get('kind') != 'baseline' or d.get('status') != 'open':
        continue
    op = ops.get(d.get('operation_id'), {})
    if op.get('auth') == 'public':
        print(d['id'], d['operation_id'], op.get('method'), op.get('url'), 'EV', evs.get(d['operation_id'], [])[:4], 'ACTOR', d.get('actor_id'))
