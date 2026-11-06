import socket, threading, time, sys, os

# Simple dual-purpose listener: HTTP on 18080 logs requests; LDAP-ish on 1389 logs connections.
work = r'D:\Backup\Downloads\awa-ddd\work\local-8081-20261106'
log = os.path.join(work, 'callback.log')

def logline(s):
    with open(log, 'a', encoding='utf-8') as f:
        f.write(s + '\n')
    print(s, flush=True)

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', port))
    s.listen(20)
    logline(f'LISTEN {port}')
    while True:
        conn, addr = s.accept()
        try:
            conn.settimeout(2)
            data = conn.recv(2048)
            logline(f'CONNECT {port} from {addr} data={data!r}')
            if port == 18080:
                body = b'OK-AWA-CALLBACK'
                resp = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n' + body
                conn.sendall(resp)
        except Exception as e:
            logline(f'ERR {port} {e}')
        finally:
            conn.close()

if __name__ == '__main__':
    open(log, 'w', encoding='utf-8').write('START\n')
    threads = [threading.Thread(target=serve, args=(p,), daemon=True) for p in (18080, 1389)]
    for t in threads: t.start()
    while True:
        time.sleep(1)
