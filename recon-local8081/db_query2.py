import sqlite3, json, collections
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261105\assessment.sqlite3'
c = sqlite3.connect(p)
rows = [json.loads(r[0]) for r in c.execute("select document from entities where kind='obligation'")]
print('total', len(rows))
print('by status', collections.Counter(r.get('status') for r in rows))
print('by kind/status')
for k,v in sorted(collections.Counter((r.get('kind'),r.get('status')) for r in rows).items()):
    print(k, v)
print('--- baseline open by operation ---')
bo=[r for r in rows if r.get('kind')=='baseline' and r.get('status')=='open']
print(len(bo))
for op,grp in sorted(collections.Counter(r['operation_id'] for r in bo).items(), key=lambda x:-x[1]):
    print(op, grp)
