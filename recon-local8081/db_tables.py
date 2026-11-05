import sqlite3
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261105\assessment.sqlite3'
c = sqlite3.connect(p)
print('\n'.join(r[0] for r in c.execute("select name from sqlite_master where type='table' order by name")))
