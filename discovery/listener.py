import socket
import logging
import yaml
import struct
from typing import Optional, Dict, Any, Callable
import threading
import select

class BroadcastListener:
    def __init__(self, config_path: str = "config/config.yaml", packet_handler: Optional[Callable] = None, use_raw_socket: bool = True, monitor_ports: list = None):
        """
        Initialisiert den UDP Listener.
        
        Args:
            config_path: Pfad zur Konfigurationsdatei
            packet_handler: Callback-Funktion für empfangene UDP-Pakete
            use_raw_socket: Ob RAW Socket verwendet werden soll (erfordert root)
            monitor_ports: Liste von Ports, die zusätzlich überwacht werden sollen
        """
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config(config_path) if config_path else {}
        self.packet_handler = packet_handler
        self.use_raw_socket = use_raw_socket
        self.monitor_ports = monitor_ports or [27015]  # Standard GameServer Ports
        self.running = False
        
        # Sockets
        self.raw_socket: Optional[socket.socket] = None
        self.udp_sockets: Dict[int, socket.socket] = {}
        
        # Threads
        self.threads: list = []
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Lädt die Konfiguration aus der YAML-Datei."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return config
        except Exception as e:
            self.logger.warning(f"Konfigurationsdatei nicht gefunden oder fehlerhaft: {e}")
            return {}
            
    def start(self) -> None:
        """Startet den UDP Listener."""
        if self.running:
            self.logger.warning("UDP Listener läuft bereits")
            return
            
        self.running = True
        
        # RAW Socket starten (falls aktiviert und möglich)
        if self.use_raw_socket:
            self._start_raw_socket()
            
        # Normale UDP Sockets für spezifische Ports starten
        self._start_udp_sockets()
        
        self.logger.info(f"UDP Listener gestartet - RAW Socket: {self.raw_socket is not None}, UDP Ports: {list(self.udp_sockets.keys())}")
            
    def _start_raw_socket(self) -> None:
        """Startet den RAW Socket (falls möglich)."""
        try:
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.raw_socket.bind(('', 0))
            
            # Thread für RAW Socket starten
            raw_thread = threading.Thread(target=self._raw_socket_loop, daemon=True)
            raw_thread.start()
            self.threads.append(raw_thread)
            
            self.logger.info("RAW Socket erfolgreich gestartet")
            
        except PermissionError:
            self.logger.warning("Keine Berechtigung für RAW Socket - läuft ohne RAW Socket")
            self.raw_socket = None
        except Exception as e:
            self.logger.error(f"Fehler beim Starten des RAW Sockets: {e}")
            self.raw_socket = None
            
    def _start_udp_sockets(self) -> None:
        """Startet normale UDP Sockets für spezifische Ports."""
        for port in self.monitor_ports:
            try:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                
                # Versuche an den spezifischen Port zu binden
                udp_sock.bind(('', port))
                self.udp_sockets[port] = udp_sock
                
                # Thread für diesen UDP Socket starten
                udp_thread = threading.Thread(target=self._udp_socket_loop, args=(port, udp_sock), daemon=True)
                udp_thread.start()
                self.threads.append(udp_thread)
                
                self.logger.info(f"UDP Socket für Port {port} gestartet")
                
            except Exception as e:
                self.logger.warning(f"Konnte UDP Socket für Port {port} nicht starten: {e}")
            
    def stop(self) -> None:
        """Stoppt den UDP Listener."""
        self.running = False
        
        # RAW Socket schließen
        if self.raw_socket:
            try:
                self.raw_socket.close()
            except Exception as e:
                self.logger.error(f"Fehler beim Schließen des RAW Sockets: {e}")
                
        # UDP Sockets schließen
        for port, sock in self.udp_sockets.items():
            try:
                sock.close()
            except Exception as e:
                self.logger.error(f"Fehler beim Schließen des UDP Sockets für Port {port}: {e}")
                
        # Auf Threads warten
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
                
        self.logger.info("UDP Listener gestoppt")
            
    def _parse_ip_header(self, packet: bytes) -> tuple:
        """Parst den IP-Header und gibt Quell-IP und Ziel-IP zurück."""
        # IP Header ist mindestens 20 Bytes
        if len(packet) < 20:
            return None, None, None, None
            
        # IP Header parsen (vereinfacht)
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        version_ihl = ip_header[0]
        ihl = version_ihl & 0xF  # Internet Header Length
        header_length = ihl * 4
        
        protocol = ip_header[6]
        source_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return source_ip, dest_ip, header_length, protocol
        
    def _parse_udp_header(self, packet: bytes, ip_header_length: int) -> tuple:
        """Parst den UDP-Header und gibt Port-Informationen zurück."""
        udp_start = ip_header_length
        if len(packet) < udp_start + 8:  # UDP Header ist 8 Bytes
            return None, None, None
            
        # UDP Header parsen
        udp_header = struct.unpack('!HHHH', packet[udp_start:udp_start + 8])
        source_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        
        # UDP Payload extrahieren
        payload_start = udp_start + 8
        payload = packet[payload_start:payload_start + length - 8]
        
        return source_port, dest_port, payload
            
    def _raw_socket_loop(self) -> None:
        """Haupt-Loop für das Empfangen von RAW UDP-Paketen."""
        self.logger.debug("RAW Socket Loop gestartet")
        
        while self.running:
            try:
                # Select verwenden um nicht-blockierend zu sein
                ready = select.select([self.raw_socket], [], [], 1.0)
                if ready[0]:
                    packet, addr = self.raw_socket.recvfrom(65535)
                    
                    # IP Header parsen
                    source_ip, dest_ip, ip_header_length, protocol = self._parse_ip_header(packet)
                    
                    # Nur UDP-Pakete verarbeiten (Protocol 17)
                    if protocol == 17 and source_ip and dest_ip:
                        # UDP Header und Payload parsen
                        source_port, dest_port, payload = self._parse_udp_header(packet, ip_header_length)
                        
                        if source_port is not None and dest_port is not None:
                            self.logger.debug(f"[RAW] UDP Paket: {source_ip}:{source_port} -> {dest_ip}:{dest_port}, {len(payload)} Bytes")
                            
                            # Callback aufrufen
                            self._handle_packet(payload, (source_ip, source_port), "RAW")
                    
            except Exception as e:
                if self.running:
                    self.logger.error(f"Fehler im RAW Socket Loop: {e}")
                    
    def _udp_socket_loop(self, port: int, sock: socket.socket) -> None:
        """Loop für normale UDP Sockets."""
        self.logger.debug(f"UDP Socket Loop für Port {port} gestartet")
        
        while self.running:
            try:
                # Select verwenden um nicht-blockierend zu sein
                ready = select.select([sock], [], [], 1.0)
                if ready[0]:
                    data, addr = sock.recvfrom(65535)
                    
                    self.logger.debug(f"[UDP:{port}] Paket von {addr[0]}:{addr[1]}, {len(data)} Bytes")
                    
                    # Callback aufrufen
                    self._handle_packet(data, addr, f"UDP:{port}")
                    
            except Exception as e:
                if self.running:
                    self.logger.error(f"Fehler im UDP Socket Loop für Port {port}: {e}")
                    
    def _handle_packet(self, payload: bytes, addr: tuple, source: str) -> None:
        """Behandelt empfangene Pakete."""
        if self.packet_handler:
            try:
                # Zusätzliche Info über die Quelle hinzufügen
                extended_addr = (addr[0], addr[1], source)
                self.packet_handler(payload, extended_addr)
            except Exception as e:
                self.logger.error(f"Fehler im Packet Handler: {e}")
                    
    def set_packet_handler(self, handler: Callable) -> None:
        """Setzt den Packet Handler."""
        self.packet_handler = handler
