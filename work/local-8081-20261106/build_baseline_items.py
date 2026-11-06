import json
import os
import sqlite3

proj = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106'
db = os.path.join(proj, 'assessment.sqlite3')
c = sqlite3.connect(db)
ev = {}
for eid, doc in c.execute("SELECT id, document FROM entities WHERE kind='evidence'"):
    ev[eid] = json.loads(doc)
pairs = [
    ('OB-75fa40d84b3976b3bceed35a', 'E-4dc0d00a579c4545909da044b95a7229'),
    ('OB-3c14950b496ca66c21472d54', 'E-87f72742cf6b4c9f88d60131bfab96ba'),
    ('OB-a91ec355db8c8be8c7862dab', 'E-16b1559bb94c49c9a21240e62248db76'),
    ('OB-e2cc43ce500ccbfb66c0fbad', 'E-0212e67c37cd40b1a0804a07cb708021'),
    ('OB-ec1d320a75a78838cdab5b60', 'E-05b6795ee8d74f41adb8e59f8b00d136'),
    ('OB-eabbda9da1db0d2274b63bf7', 'E-d6ed43c754d840f19d299183a1185742'),
    ('OB-caecab9803de73e2eca717da', 'E-da34f2cf032841f792b5f12c14619de8'),
    ('OB-0112a9eacc1e4c30ffc60c2d', 'E-05fd1ea26a0a4f77a925800c2f6c58a8'),
    ('OB-cbfef3ddf2bc6ea47520ac5b', 'E-d94002804d264bb88e004a00e7a87764'),
    ('OB-d74ec999602719b42bba3dce', 'E-63d899fdca0747b4a909087371fdd7b6'),
    ('OB-25e0ba99795939503f3e3ea9', 'E-bd254978d92945b5929c885b5de1a8b4'),
    ('OB-38c156a893a4a9279058ce30', 'E-b5afebd709c742c08712810795560ef6'),
    ('OB-45ee74fd30101bfb8ca43305', 'E-11efd430eaf74ca4aaa5cfbdf60568b7'),
    ('OB-61de80a3b55af1e6ec206d60', 'E-ac8653d525cd4d278567b801652801c7'),
    ('OB-8960b674854f8b5eb3e9079a', 'E-0399d67fe3ba402da46534d5e5575e7c'),
]
items = []
for ob, eid in pairs:
    d = ev[eid]
    path = os.path.join(proj, d['artifact_path'])
    raw = json.load(open(path, encoding='utf-8'))
    body_hash = raw['response']['body_sha256']
    items.append({'obligation_id': ob, 'evidence_ids': [eid], 'oracle': {'type': 'baseline', 'selector': '@raw', 'expected_sha256': body_hash}})
print(json.dumps({'items': items}, ensure_ascii=False))
