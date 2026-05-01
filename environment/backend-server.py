#!/usr/bin/env -S python3 -W ignore::DeprecationWarning

import os, sys, signal
import socket
import threading
import warnings

TARGET1 = "server-a.py"
PORT1 = 48765

TARGET2 = "server-b.py"
PORT2 = 48766

HOST = "0.0.0.0"


def reap_children(signum, frame):
    # reap all exited children in a nonblocking way (WNOHANG) to prevent zombies
    while True:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid == 0:
            break

def client_handler(conn, addr, target):
    print(f"Connection from {addr} for {target}")
    pid = os.fork()
    if pid == 0:
        client_socket_fd = conn.fileno()
        os.dup2(client_socket_fd, sys.stdin.fileno())
        os.dup2(client_socket_fd, sys.stdout.fileno())

        with open(os.devnull, 'w') as devnull:
            os.dup2(devnull.fileno(), sys.stderr.fileno())

        conn.close()
        try:
            os.execvp("python3", ["python3", '-u', target])
        except Exception as e:
            print(f"Failed to execute {target}: {e}")
            sys.exit(1)
    else:
        conn.close()


def start_server(port, target):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen()
        print(f"Server for {target} is running on {HOST}:{port}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=client_handler, args=(conn, addr, target)).start()

if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    signal.signal(signal.SIGCHLD, reap_children)

    # start both servers
    t1 = threading.Thread(target=start_server, args=(PORT1, TARGET1), daemon=True)
    t2 = threading.Thread(target=start_server, args=(PORT2, TARGET2), daemon=True)

    t1.start()
    t2.start()

    print("Servers are running. Press Ctrl+C to stop.")
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        print("Shutting down all servers.")
