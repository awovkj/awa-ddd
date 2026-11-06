import urllib.request, urllib.error
paths = ['/actuator', '/actuator/env', '/actuator/health', '/actuator/mappings', '/actuator/beans', '/admin/js/config.js', '/v3/api-docs', '/swagger-ui.html', '/swagger-resources', '/api-docs', '/error', '/robots.txt', '/pom.xml', '/application.yml', '/WEB-INF/web.xml']
for p in paths:
    try:
        r = urllib.request.urlopen('http://127.0.0.1:8081' + p, timeout=5)
        body = r.read(400)
        print(p, r.status, r.headers.get('Content-Type'), repr(body[:250]))
    except urllib.error.HTTPError as e:
        print(p, 'HTTP', e.code, e.headers.get('Content-Type'), repr(e.read(150)[:150]))
    except Exception as e:
        print(p, 'ERR', type(e).__name__, str(e)[:100])
