#!/usr/bin/env python3
import socket, threading, select, sys

LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = 10015
TARGET_ADDR = '127.0.0.1'
TARGET_PORT = 109
RESPONSE = b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n'

def forward(src, dst):
    try:
        while True:
            r, _, _ = select.select([src, dst], [], [], 60)
            if not r:
                break
            for s in r:
                data = s.recv(8192)
                if not data:
                    return
                (dst if s is src else src).sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.close()
            except Exception:
                pass

def handle_client(client):
    try:
        client.settimeout(10)
        req = client.recv(4096)
        if not req:
            client.close()
            return
        remote = socket.create_connection((TARGET_ADDR, TARGET_PORT), timeout=10)
        client.sendall(RESPONSE)
        client.settimeout(None)
        remote.settimeout(None)
        forward(client, remote)
    except Exception:
        try:
            client.close()
        except Exception:
            pass

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_ADDR, LISTEN_PORT))
    srv.listen(256)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == '__main__':
    main()
