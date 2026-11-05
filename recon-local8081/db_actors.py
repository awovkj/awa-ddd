import sqlite3, json
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261105\assessment.sqlite3'
c = sqlite3.connect(p)
for r in c.execute("select document from entities where kind='actor'"):
    d = json.loads(r[0])
    print(d.get('id'), '|', d.get('subject'), '|', d.get('roles'), '|', repr(d.get('tenant_id')))
