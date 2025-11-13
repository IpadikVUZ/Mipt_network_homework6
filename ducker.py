#!/usr/bin/env python3
from scapy.all import *
import sys
import threading

TRIGGER_DOMAIN = "olen.penis."
TRIGGER_IP = "8.8.8.8"
SONG_LYRICS = [
    "mir-televidenya-polon-chudes", "serialov-komikov-i-komikess",
    "byvaet-chto-vklyuchish-tam-reklama-pelmeney", "a-cherez-minutu-penis-oleniy",
    "i-eto-sovsem-ne-malahov-andrey", "a-im-ekstrasens-ishchet-lyudey",
    "on-penisom-vodit-i-vetochki-zhgyot", "on-runy-im-chertit-i-pesnyu-poyot",
    "oleniy-penis-moy-talisman", "vse-vremya-im-zanyat-moy-karman",
    "oleniy-penis-moy-obereg", "on-znaet-v-kakom-bagazhnike-oleg",
    "ya-ne-priemlyu-vaginy-losinoy", "ne-pomogaet-kal-gluharinyy",
    "penis-olenya-moy-amulet", "ego-otryval-eshche-moy-ded"
]

FAKE_IP_PREFIX = "10.6.6."
FAKE_IPS = [f"{FAKE_IP_PREFIX}{i+1}" for i in range(len(SONG_LYRICS))]
IP_TO_LYRIC = {ip: lyric for ip, lyric in zip(FAKE_IPS, SONG_LYRICS)}


IFACE_USER = ""
IFACE_INET = ""


def handle_dns_a_request(packet):

    if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd.qname == TRIGGER_DOMAIN.encode():

        print(f"DNS A-req: {TRIGGER_DOMAIN}")

        dns_resp = DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=TRIGGER_IP)

        resp_pkt = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=packet[IP].dst, dst=packet[IP].src) / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=dns_resp)

        sendp(resp_pkt, iface=IFACE_USER, verbose=0)

        return True
    return False

def handle_dns_ptr_request(packet):

    if packet.haslayer(DNS) and packet[DNS].qr == 0 and packet[DNS].qd.qtype == 12:

        qname_str = packet[DNS].qd.qname.decode()
        ip_to_check = ".".join(reversed(qname_str.replace(".in-addr.arpa.", "").split('.')))

        if ip_to_check in IP_TO_LYRIC:

            lyric = IP_TO_LYRIC[ip_to_check]
            print(f"DNS PTR-req {ip_to_check} - {lyric}")

            dns_resp = DNSRR(rrname=packet[DNS].qd.qname, type='PTR', rdata=f"{lyric}.")

            resp_pkt = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=packet[IP].dst, dst=packet[IP].src) / UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, an=dns_resp)

            sendp(resp_pkt, iface=IFACE_USER, verbose=0)

            return True
    return False

def handle_traceroute_udp(packet):
    if packet[IP].dst == TRIGGER_IP and packet.haslayer(UDP) and packet[UDP].dport > 33434:
        ttl = packet[IP].ttl

        print(f"Traceroute UDP packet with TTL={ttl} on {packet[UDP].dport}")

        if 1 <= ttl <= len(FAKE_IPS):

            fake_router_ip = FAKE_IPS[ttl - 1]
            icmp_resp = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=fake_router_ip, dst=packet[IP].src) / ICMP(type=11, code=0) / packet[IP]

        else:
            icmp_resp = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / IP(src=TRIGGER_IP, dst=packet[IP].src) / ICMP(type=3, code=3) / packet[IP]

        sendp(icmp_resp, iface=IFACE_USER, verbose=0)
        return True

    return False

def packet_handler(packet):

    if not packet.haslayer(IP):
        return False

    if handle_dns_a_request(packet):
        return True

    if handle_dns_ptr_request(packet):
        return True

    if handle_traceroute_udp(packet):
        return True

    return False

def run_bridge(iface_in, iface_out):

    def forwarder(packet):

        if iface_in == IFACE_USER:

            if not packet_handler(packet):

                sendp(packet, iface=iface_out, verbose=0)

        elif iface_in == IFACE_INET:

            sendp(packet, iface=iface_out, verbose=0)

    sniff(iface=iface_in, prn=forwarder, store=0)


if __name__ == "__main__":
    
    IFACE_USER, IFACE_INET = sys.argv[1], sys.argv[2]
    
    print(f"Hacker bridge started. User: {IFACE_USER}, Inet: {IFACE_INET}")
    
    threading.Thread(target=run_bridge, args=(IFACE_USER, IFACE_INET), daemon=True).start()
    run_bridge(IFACE_INET, IFACE_USER)