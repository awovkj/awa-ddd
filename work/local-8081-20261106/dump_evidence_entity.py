import json
import sqlite3

p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\assessment.sqlite3'
c = sqlite3.connect(p)
print('count', c.execute("select count(*) from entities where kind='evidence'").fetchone()[0])
row = c.execute("select document from entities where kind='evidence' limit 1").fetchone()
print(row[0][:800] if row else None)
print('kinds', [r[0] for r in c.execute('select distinct kind from entities')])
