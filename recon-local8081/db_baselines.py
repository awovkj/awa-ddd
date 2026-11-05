import sqlite3, json, collections
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261105\assessment.sqlite3'
c = sqlite3.connect(p)
rows = [json.loads(r[0]) for r in c.execute("select document from entities where kind='obligation'")]
for op in ['O-0cda76194b4ef7575bc69ddd','O-5ecca8fc3acf879de805ebdd','O-55f9fac38747133f5ff23777','O-1cb2ef9e36da166f641680c7']:
    print('===', op)
    for r in rows:
        if r.get('operation_id')==op and r.get('kind')=='baseline' and r.get('status')=='open':
            print(r.get('id'), 'actor=', r.get('actor_id'))
