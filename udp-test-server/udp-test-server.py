#!/usr/bin/env python3
import socketserver

# Bind to your server IP and port
SERVER_IP   = '0.0.0.0'
SERVER_PORT = 48764

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request  # data is bytes, sock is the UDP socket
        addr = self.client_address
        text = data.decode('utf-8', errors='ignore')
        print(f"Received from {addr} ---> {text!r}")

        ack = f"ACK: received {len(data)} bytes\n"
        sock.sendto(ack.encode('utf-8'), addr)
        print(f"Sent ack to {addr}")

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    with ThreadedUDPServer((SERVER_IP, SERVER_PORT), UDPHandler) as server:
        print(f"Threaded UDP server listening on {SERVER_IP}:{SERVER_PORT}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")
