import json, base64, sys
base = r'C:\Users\Administrator\.dsh\awa-ddd-data\projects\local-8081-20261106\evidence'
for name in ['E-61d62168d7b647b189d854943a6e0075.json', 'E-46482cc4227f41b6a75daae6bff0b6f4.json']:
    with open(base + '\\' + name, encoding='utf-8') as f:
        j = json.load(f)
    body = json.loads(base64.b64decode(j['response']['body_base64']).decode('utf-8', 'replace'))
    print('===', name, '===')
    if 'list' in body.get('data', {}):
        for o in body['data']['list'][:60]:
            print(o.get('order_no'), 'user=', o.get('user_id'), 'status=', o.get('status'), 'paid=', o.get('paid_amount'), 'product=', o.get('product_name') or o.get('product_no'), 'buyer=', o.get('buyer_name'))
    else:
        print(json.dumps(body, ensure_ascii=False)[:1500])
