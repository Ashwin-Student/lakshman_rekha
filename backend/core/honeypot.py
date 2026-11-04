import socket

def run_honeypot_trap(host, trap_port, block_callback):
    trap = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    trap.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    trap.bind((host, trap_port))
    trap.listen(50)
    print(f"[*] Trap Activated. Monitoring Honeypot decoy ports on: {trap_port}")

    while True:
        client_sock, client_addr = trap.accept()
        attacker_ip = client_addr[0]
        block_callback(attacker_ip, f"Probed Honeypot Trap Port ({trap_port})")
        client_sock.close()
