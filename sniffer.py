from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime

HTTP_METHODS = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]

def log_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        if any(payload.startswith(method) for method in HTTP_METHODS):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            method = payload.split(b' ')[0].decode(errors="ignore")
            path = payload.split(b' ')[1].decode(errors="ignore")

            with open("firewall.log", "a") as f:
                f.write(f"[HTTP] {datetime.now()} {src_ip} -> {dst_ip}:{dst_port} {method} {path}\n")

def start_sniffer(port=None, stop_event=None):
    filter_str = f"tcp port {port}" if port else "tcp"
    
    def stop_filter(packet):
        return stop_event.is_set()

    sniff(
        filter=filter_str,
        prn=log_packet,
        store=0,
        stop_filter=stop_filter if stop_event else None
    )
