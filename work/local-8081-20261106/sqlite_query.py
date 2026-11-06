import sqlite3
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\assessment.sqlite3'
c = sqlite3.connect(p)
print([r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")])
for name in ['obligation','evidence','operation']:
    try:
        print(name, [r[1] for r in c.execute(f'PRAGMA table_info({name})')])
    except Exception as e:
        print(name, e)
