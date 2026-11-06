import urllib.request, json
d = json.load(urllib.request.urlopen('http://127.0.0.1:8081/actuator/mappings'))
ctx = d['contexts']['shop-java']['mappings']
for key, val in ctx.items():
    print('===', key, '===')
    if isinstance(val, dict):
        for k, v in val.items():
            print(k, type(v))
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        print('  predicate:', item.get('predicate'))
                        det = item.get('details', {})
                        hm = det.get('handlerMethod', {}) if isinstance(det, dict) else {}
                        print('  handler:', hm.get('className'), hm.get('name'), hm.get('descriptor'))
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    print(' ', kk, '=>', vv if not isinstance(vv, (dict, list)) else type(vv))
