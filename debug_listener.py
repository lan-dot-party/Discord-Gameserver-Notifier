#!/usr/bin/env python3
import socket
import struct
import threading
import time
import os
import sys

def check_root():
    """Prüft ob das Programm als root ausgeführt wird."""
    if os.geteuid() != 0:
        print("FEHLER: Dieses Programm muss als root ausgeführt werden!")
        print("Verwende: sudo python3 debug_listener.py")
        sys.exit(1)

def raw_socket_listener():
    """RAW Socket Listener für Debugging"""
    try:
        print("[RAW] Starte RAW Socket Listener...")
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw_sock.bind(('', 0))
        
        packet_count = 0
        while True:
            try:
                packet, addr = raw_sock.recvfrom(65535)
                packet_count += 1
                
                # IP Header parsen
                if len(packet) >= 20:
                    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
                    ihl = (ip_header[0] & 0xF) * 4
                    protocol = ip_header[6]
                    source_ip = socket.inet_ntoa(ip_header[8])
                    dest_ip = socket.inet_ntoa(ip_header[9])
                    
                    if protocol == 17:  # UDP
                        # UDP Header parsen
                        udp_start = ihl
                        if len(packet) >= udp_start + 8:
                            udp_header = struct.unpack('!HHHH', packet[udp_start:udp_start + 8])
                            source_port = udp_header[0]
                            dest_port = udp_header[1]
                            
                            print(f"[RAW #{packet_count}] UDP: {source_ip}:{source_port} -> {dest_ip}:{dest_port}")
                            
                            # Payload anzeigen
                            payload_start = udp_start + 8
                            payload = packet[payload_start:payload_start + udp_header[2] - 8]
                            if payload:
                                try:
                                    payload_str = payload.decode('utf-8', errors='ignore')
                                    print(f"[RAW] Payload: {payload_str}")
                                except:
                                    print(f"[RAW] Payload: {payload[:50]}...")
                        
            except Exception as e:
                print(f"[RAW] Fehler: {e}")
                
    except Exception as e:
        print(f"[RAW] Setup-Fehler: {e}")

def normal_udp_listener():
    """Normaler UDP Socket Listener für Vergleich"""
    try:
        print("[UDP] Starte normalen UDP Socket Listener auf Port 27015...")
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        udp_sock.bind(('', 27015))
        
        packet_count = 0
        while True:
            try:
                data, addr = udp_sock.recvfrom(1024)
                packet_count += 1
                print(f"[UDP #{packet_count}] Empfangen von {addr[0]}:{addr[1]}")
                try:
                    payload_str = data.decode('utf-8', errors='ignore')
                    print(f"[UDP] Payload: {payload_str}")
                except:
                    print(f"[UDP] Payload: {data[:50]}...")
                    
            except Exception as e:
                print(f"[UDP] Fehler: {e}")
                
    except Exception as e:
        print(f"[UDP] Setup-Fehler: {e}")

def broadcast_sender():
    """Sendet Test-Broadcasts"""
    time.sleep(2)  # Warten bis Listener bereit sind
    
    try:
        print("[SENDER] Starte Broadcast Sender...")
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        send_sock.bind(('', 0))
        
        counter = 0
        while counter < 5:  # Nur 5 Test-Broadcasts
            message = f"Debug Test Broadcast #{counter}".encode('utf-8')
            
            # Sende an verschiedene Ziele
            targets = [
                ('255.255.255.255', 27015),  # Broadcast
                ('127.0.0.1', 27015),        # Loopback
                ('localhost', 27015),        # Localhost
            ]
            
            for target in targets:
                try:
                    send_sock.sendto(message, target)
                    print(f"[SENDER] Broadcast #{counter} gesendet an {target[0]}:{target[1]}")
                except Exception as e:
                    print(f"[SENDER] Fehler beim Senden an {target}: {e}")
            
            counter += 1
            time.sleep(3)
            
    except Exception as e:
        print(f"[SENDER] Fehler: {e}")

if __name__ == "__main__":
    check_root()
    
    print("=== DEBUG LISTENER ===")
    print("Testet RAW Socket vs. normaler UDP Socket")
    print("Drücke Ctrl+C zum Beenden\n")
    
    # Threads starten
    raw_thread = threading.Thread(target=raw_socket_listener, daemon=True)
    udp_thread = threading.Thread(target=normal_udp_listener, daemon=True)
    sender_thread = threading.Thread(target=broadcast_sender, daemon=True)
    
    raw_thread.start()
    udp_thread.start()
    sender_thread.start()
    
    try:
        # Warten auf Threads
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nProgramm beendet.")
        sys.exit(0) 