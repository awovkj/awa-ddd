import json
import os
import sqlite3

proj = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106'
db = os.path.join(proj, 'assessment.sqlite3')
c = sqlite3.connect(db)
ops = {}
for oid, doc in c.execute("SELECT id, document FROM entities WHERE kind='operation'"):
    ops[oid] = json.loads(doc)
ev = {}
for eid, doc in c.execute("SELECT id, document FROM entities WHERE kind='evidence'"):
    ev[eid] = json.loads(doc)
items = []
seen = set()
for obid, doc in c.execute("SELECT id, document FROM entities WHERE kind='obligation'"):
    ob = json.loads(doc)
    if ob.get('kind') != 'baseline' or ob.get('status') != 'open':
        continue
    op = ops.get(ob.get('operation_id'), {})
    candidates = []
    for eid, e in ev.items():
        if e.get('operation_id') != ob.get('operation_id'):
            continue
        if e.get('actor_id') != ob.get('actor_id'):
            continue
        if not (200 <= e.get('status_code', 0) < 300):
            continue
        if not e.get('complete'):
            continue
        path = os.path.join(proj, e.get('artifact_path', ''))
        try:
            raw = json.load(open(path, encoding='utf-8'))
            bh = raw['response']['body_sha256']
        except Exception:
            continue
        candidates.append((eid, bh, e.get('created_at', '')))
    if not candidates:
        continue
    candidates.sort(key=lambda x: x[2], reverse=True)
    eid, bh, _ = candidates[0]
    key = (obid, eid)
    if key in seen:
        continue
    seen.add(key)
    items.append({'obligation_id': obid, 'evidence_ids': [eid], 'oracle': {'type': 'baseline', 'selector': '@raw', 'expected_sha256': bh}})
print(json.dumps({'items': items[:50]}, ensure_ascii=False))
print('TOTAL', len(items))
