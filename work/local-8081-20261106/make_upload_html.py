import os
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
boundary = '----AWAUPLOAD1106'
content = b"<html><body><script>document.title='AWA-UPLOAD-HTML-1106';document.body.innerHTML='AWA-UPLOAD-HTML-1106';</script></body></html>"
parts = []
parts.append(('--' + boundary + '\r\n').encode())
parts.append(b'Content-Disposition: form-data; name="file"; filename="../awa-upload-1106.html"\r\n')
parts.append(b'Content-Type: image/png\r\n\r\n')
parts.append(content)
parts.append(('\r\n--' + boundary + '--\r\n').encode())
open(os.path.join(work, 'upload_html.bin'), 'wb').write(b''.join(parts))
print('ok', len(b''.join(parts)))
