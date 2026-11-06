import json
import sqlite3

p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\assessment.sqlite3'
c = sqlite3.connect(p)
rows = c.execute("SELECT id, document FROM entities WHERE kind='obligation'").fetchall()
count = 0
for oid, doc in rows:
    d = json.loads(doc)
    if d.get('kind') == 'baseline' and d.get('status') == 'open':
        count += 1
        if count <= 80:
            print(oid, d.get('operation_id'), d.get('actor_id'), d.get('status'), d.get('reason_code', ''))
print('TOTAL', count)
