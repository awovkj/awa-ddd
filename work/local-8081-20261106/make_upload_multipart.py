import os
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
# 1x1 png bytes (base64)
import base64
png = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9Z2wAAAABJRU5ErkJggg==')

def build(path, filename, content):
    boundary = '----AWAUPLOAD1106'
    parts = []
    parts.append(('--' + boundary + '\r\n').encode())
    parts.append(('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % filename).encode())
    parts.append(b'Content-Type: image/png\r\n\r\n')
    parts.append(content)
    parts.append(('\r\n--' + boundary + '--\r\n').encode())
    open(path, 'wb').write(b''.join(parts))
    print(path, len(b''.join(parts)))

build(os.path.join(work, 'upload_normal.bin'), 'awa-normal-1106.png', png + b'AWA-UPLOAD-NORMAL-1106')
build(os.path.join(work, 'upload_traversal.bin'), '../awa-traversal-1106.png', png + b'AWA-TRAVERSAL-1106')
