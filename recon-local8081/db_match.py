import sqlite3, json, collections
p = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261105\assessment.sqlite3'
c = sqlite3.connect(p)
ents = {}
for kind in ['obligation','evidence']:
    ents[kind] = [json.loads(r[0]) for r in c.execute("select document from entities where kind=?", (kind,))]
obs = [o for o in ents['obligation'] if o.get('kind')=='baseline' and o.get('status')=='open']
evs = ents['evidence']
by_op_actor = collections.defaultdict(list)
for e in evs:
    by_op_actor[(e.get('operation_id'), e.get('actor_id'))].append(e)
matches = []
for o in obs:
    key=(o.get('operation_id'), o.get('actor_id'))
    if by_op_actor.get(key):
        matches.append((o['id'], o.get('operation_id'), o.get('actor_id'), [e['id'] for e in by_op_actor[key]]))
print('open baseline obligations', len(obs), 'with same actor/op evidence', len(matches))
for m in matches:
    print(m[0], m[1], m[2], ','.join(m[3]))
