import socket
import time
import sys
import signal

# Socket Variable global initialisieren
sock = None

def signal_handler(signum, frame):
    """Handler für Ctrl+C"""
    print("\nProgramm wird beendet...")
    if sock:
        sock.close()
    sys.exit(0)

if __name__ == "__main__":
    # Signal Handler für Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Broadcast Socket erstellen
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # An INADDR_ANY binden
        sock.bind(('', 0))  # Beliebiger Port für das Senden
        
        counter = 0
        
        print("Sende Broadcast-Nachrichten... (Ctrl+C zum Beenden)")
        
        while True:
            message = f"Test Broadcast #{counter}".encode('utf-8')
            # Sende an Broadcast-Adresse
            sock.sendto(message, ('255.255.255.255', 27015))
            print(f"Broadcast #{counter} gesendet")
            counter += 1
            time.sleep(2)  # Warte 2 Sekunden zwischen den Broadcasts
            
    except Exception as e:
        print(f"Fehler: {e}")
        if sock:
            sock.close()
        sys.exit(1) 
