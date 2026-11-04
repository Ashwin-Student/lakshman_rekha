import re


class Layer7Engine:
    def __init__(self, db_log_callback, block_callback):
        self.db_log_callback = db_log_callback
        self.block_callback = block_callback

        self.rules = {
            "SQL_Injection": re.compile(r"(UNION\s+SELECT|SELECT\s+.*\s+FROM|INSERT\s+INTO|' OR '1'='1|--|#)",
                                        re.IGNORECASE),
            "Cross_Site_Scripting": re.compile(r"(<script.*?>|javascript:|onload=|onerror=|alert\()", re.IGNORECASE),
            "Path_Traversal": re.compile(r"(\.\.\/|\.\.\\|/etc/passwd|/windows/win\.ini)", re.IGNORECASE),
            "Malicious_Payload_Extension": re.compile(r"\.(exe|php|sh|pl|py|jsp|asp)$", re.IGNORECASE)
        }

    def inspect_request(self, ip, raw_payload):
        try:
            decoded_string = raw_payload.decode('utf-8', errors='ignore')
        except Exception:
            return True

        for attack_name, pattern in self.rules.items():
            if pattern.search(decoded_string):
                # Clean clean preview mapping for DB metrics layout logs
                payload_preview = decoded_string.splitlines()[
                    0] if decoded_string.splitlines() else "Empty Payload Structure"
                self.db_log_callback(ip, f"L7_{attack_name}", payload_preview)
                self.block_callback(ip, f"Triggered Application Signature Ruleset: {attack_name}")
                return False
        return True
