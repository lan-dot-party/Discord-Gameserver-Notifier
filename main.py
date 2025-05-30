import logging
import signal
import sys
import os
from discovery import BroadcastListener

def check_root():
    """Prüft ob das Programm als root ausgeführt wird."""
    if os.geteuid() != 0:
        print("FEHLER: Dieses Programm muss als root ausgeführt werden!")
        print("Verwende: sudo python3 main.py")
        sys.exit(1)

def setup_logging():
    """Richtet das Logging-System ein."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler()]
    )

def packet_handler(data, addr):
    """Einfacher Packet Handler für Testzwecke."""
    # addr enthält jetzt (ip, port, source)
    if len(addr) >= 3:
        ip, port, source = addr
        print(f"\n[{source}] UDP Paket empfangen von {ip}:{port}")
    else:
        print(f"\nUDP Paket empfangen von {addr[0]}:{addr[1]}")
    
    # Versuche Payload als Text zu dekodieren
    try:
        payload_str = data.decode('utf-8', errors='ignore')
        print(f"Payload: {payload_str}")
    except:
        print(f"Payload ({len(data)} Bytes): {data[:50]}...")
    
    # Zusätzliche Informationen
    print(f"Daten-Länge: {len(data)} Bytes")

# BroadcastListener Variable global initialisieren
listener = None

def signal_handler(signum, frame):
    """Handler für Ctrl+C"""
    print("\nProgramm wird beendet...")
    if listener:
        listener.stop()
    sys.exit(0)

if __name__ == "__main__":
    # Root-Check als erstes
    check_root()
    
    # Logging einrichten
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.debug("Debug-Logging aktiviert")
    
    # Signal Handler für Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # BroadcastListener erstellen und starten mit erweiterten Optionen
        # Überwache mehrere Ports und verwende sowohl RAW als auch normale UDP Sockets
        listener = BroadcastListener(
            packet_handler=packet_handler,
            use_raw_socket=True,  # RAW Socket verwenden (falls root)
            monitor_ports=[27015, 27016, 27017]  # Häufige GameServer Ports
        )
        listener.start()
        
        logger.info("Hybrid UDP Listener gestartet. Drücke Ctrl+C zum Beenden.")
        logger.info("Überwacht sowohl RAW Socket als auch spezifische UDP Ports")
        logger.debug("Warte auf UDP-Pakete...")
        
        # Hauptprogramm am Leben halten
        signal.pause()
        
    except Exception as e:
        logger.error(f"Fehler im Hauptprogramm: {e}")
        if listener:
            listener.stop()
        sys.exit(1)
