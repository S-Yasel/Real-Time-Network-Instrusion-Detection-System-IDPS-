# packet_capture.py
import queue, threading, logging
from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP
class PacketCapture:
"""Async packet capture with live/offline support."""
def __init__(self, interface=None, pcap_file=None, queue_size=10000):
self.interface = interface
self.pcap_file = pcap_file
self.pkt_queue = queue.Queue(maxsize=queue_size)
self._stop_evt = threading.Event()
self.stats = {'captured': 0, 'dropped': 0}
self.logger = logging.getLogger(__name__)
def _enqueue(self, pkt):
if not pkt.haslayer(IP):
return # skip non-IP frames
try:
self.pkt_queue.put_nowait(pkt)
self.stats['captured'] += 1
except queue.Full:
self.stats['dropped'] += 1
self.logger.warning('Packet queue full – dropping packet')
def start_live(self):
"""Start async live capture on self.interface."""
self.logger.info(f'Starting live capture on {self.interface}')
self._thread = threading.Thread(
target=sniff,
kwargs={
'iface': self.interface,
'prn': self._enqueue,
'store': False,
'stop_filter': lambda _: self._stop_evt.is_set()
},
daemon=True
)
self._thread.start()
def start_offline(self):
"""Load packets from PCAP file into queue."""
pkts = rdpcap(self.pcap_file)
self.logger.info(f'Loaded {len(pkts)} packets from {self.pcap_file}')
for pkt in pkts:
self._enqueue(pkt)
def stop(self):
self._stop_evt.set()
def get(self, timeout=1.0):
return self.pkt_queue.get(timeout=timeout)