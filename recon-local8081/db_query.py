import sqlite3, json
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261105\assessment.sqlite3'
c = sqlite3.connect(p)
row = c.execute("select document from entities where kind='obligation' limit 1").fetchone()
print(row[0] if row else 'none')
print('--- counts ---')
for kind in ['obligation','evidence','finding','decision','operation']:
    print(kind, c.execute("select count(*) from entities where kind=?", (kind,)).fetchone()[0])
