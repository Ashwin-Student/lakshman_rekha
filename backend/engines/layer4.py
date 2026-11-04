import time
from collections import defaultdict
import threading


class Layer4Engine:
    def __init__(self, db_callback):
        self.db_callback = db_callback
        self.blacklisted_ips = set()
        self.lock = threading.Lock()

        # State tracking pipelines
        self.connection_history = defaultdict(list)
        self.active_connections = defaultdict(int)
        self.handshake_states = defaultdict(dict)

    def sync_blacklist(self, initial_set):
        with self.lock:
            self.blacklisted_ips = initial_set

    def is_blacklisted(self, ip):
        with self.lock:
            return ip in self.blacklisted_ips

    def penalize_ip(self, ip, reason):
        with self.lock:
            if ip not in self.blacklisted_ips:
                self.blacklisted_ips.add(ip)
                self.db_callback(ip, reason)
                print(f"[L4 MITIGATION] Blacklisted Client: {ip}. Reason: {reason}")

    def track_handshake_start(self, ip):
        """TCP Handshake Validation tracking start point."""
        self.handshake_states[ip]['SYN_RECEIVED'] = time.time()

    def validate_handshake_completion(self, ip):
        """State Management: Confirms handshake steps finalize successfully."""
        if ip not in self.handshake_states or 'SYN_RECEIVED' not in self.handshake_states[ip]:
            self.penalize_ip(ip, "TCP Handshake Out-Of-Order Validation Failure")
            return False

        window = time.time() - self.handshake_states[ip]['SYN_RECEIVED']
        if window > 3.0:  # Incomplete half-open link timed out
            self.penalize_ip(ip, "Dynamic SYN Flood Pattern Detected (Handshake Hang)")
            return False

        self.handshake_states[ip]['ESTABLISHED'] = time.time()
        return True

    def evaluate_traffic(self, ip):
        current_time = time.time()

        # 1. Behavioral Rate Limiting (SYN Flood / Request Burst protection)
        self.connection_history[ip] = [t for t in self.connection_history[ip] if current_time - t < 10]
        self.connection_history[ip].append(current_time)

        if len(self.connection_history[ip]) > 60:
            self.penalize_ip(ip, "Rate Limit Exceeded (Connection Bursting)")
            return False

        # 2. Slowloris / Slow-Connection Prevention
        if self.active_connections[ip] > 15:
            self.penalize_ip(ip, "Slowloris Attack Prevention (Excessive Concurrent Pipelines)")
            return False

        return True

    def increment_connection(self, ip):
        self.active_connections[ip] += 1

    def decrement_connection(self, ip):
        self.active_connections[ip] = max(0, self.active_connections[ip] - 1)
        if ip in self.handshake_states:
            self.handshake_states.pop(ip, None)
