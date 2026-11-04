import socket
import threading


def run_proxy_server(host, port, target_server, l4_engine, l7_engine):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(200)

    def handle_session(client_socket, client_address):
        ip = client_address[0]

        # State Handshake Validation Stage
        l4_engine.track_handshake_start(ip)
        l4_engine.increment_connection(ip)

        try:
            if l4_engine.is_blacklisted(ip) or not l4_engine.validate_handshake_completion(
                    ip) or not l4_engine.evaluate_traffic(ip):
                client_socket.close()
                return

            client_socket.settimeout(4.0)  # Dropping persistent idling links (Anti-Slowloris)
            request_bytes = client_socket.recv(8192)

            if not request_bytes or not l7_engine.inspect_request(ip, request_bytes):
                block_screen = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nBlocked by LakshmanRekha WAF Engine Layer."
                client_socket.sendall(block_screen)
                client_socket.close()
                return

            # Route transparently down onto Real Application Destination Server
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect(target_server)
            remote_socket.sendall(request_bytes)

            remote_socket.settimeout(4.0)
            upstream_response = remote_socket.recv(8192)
            client_socket.sendall(upstream_response)
            remote_socket.close()

        except Exception:
            pass
        finally:
            l4_engine.decrement_connection(ip)
            client_socket.close()

    while True:
        sock, addr = server.accept()
        threading.Thread(target=handle_session, args=(sock, addr), daemon=True).start()
