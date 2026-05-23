# feature_extractor.py
import time, collections
from dataclasses import dataclass, field
from typing import Dict, List, Optional
@dataclass
class FlowRecord:
src_ip: str; dst_ip: str
src_port: int; dst_port: int
protocol: str
start_ts: float = field(default_factory=time.time)
pkts_fwd: int = 0; pkts_bwd: int = 0
bytes_fwd: int = 0; bytes_bwd: int = 0
tcp_flags: collections.Counter = field(
default_factory=collections.Counter)
iat_list: List[float] = field(default_factory=list)
last_ts: float = field(default_factory=time.time)
urgent: int = 0
land: int = 0
class FlowExtractor:
SERVICE_MAP = {'80':'http','443':'https','21':'ftp',
'22':'ssh','25':'smtp','53':'dns',
'110':'pop3','143':'imap'}
def __init__(self, flow_timeout=60):
self.flows: Dict[tuple, FlowRecord] = {}
self.timeout: float = flow_timeout
self.history: collections.deque = collections.deque(maxlen=200)
def _key(self, pkt):
ip = pkt['IP']
proto = {6:'tcp', 17:'udp', 1:'icmp'}.get(ip.proto, 'other')
sp = pkt['TCP'].sport if pkt.haslayer('TCP') else (
pkt['UDP'].sport if pkt.haslayer('UDP') else 0)
dp = pkt['TCP'].dport if pkt.haslayer('TCP') else (
pkt['UDP'].dport if pkt.haslayer('UDP') else 0)
return (ip.src, ip.dst, sp, dp, proto)
def update(self, pkt) -> Optional[dict]:
"""Add packet to flow; return features if flow is complete."""
if not pkt.haslayer('IP'):
return None
key = self._key(pkt)
now = pkt.time
if key not in self.flows:
self.flows[key] = FlowRecord(
src_ip=key[0], dst_ip=key[1],
src_port=key[2], dst_port=key[3],
protocol=key[4], start_ts=now, last_ts=now)
if key[0] == key[1]: self.flows[key].land = 1
fr = self.flows[key]
fr.pkts_fwd += 1
fr.bytes_fwd += len(pkt)
fr.iat_list.append(now - fr.last_ts)
fr.last_ts = now
if pkt.haslayer('TCP'):
tcp = pkt['TCP']
fr.urgent += tcp.urgptr
for flag, bit in [('SYN',0x02),('ACK',0x10),
('FIN',0x01),('RST',0x04),
('PSH',0x08)]:
if tcp.flags & bit: fr.tcp_flags[flag] += 1
if tcp.flags & 0x01 or tcp.flags & 0x04: # FIN/RST
return self._finalize(key, fr)
return self._check_timeout(key, fr, now)
def _finalize(self, key, fr) -> dict:
    features = self.extract(fr)
self.history.append(features)
del self.flows[key]
return features
def _check_timeout(self, key, fr, now) -> Optional[dict]:
if now - fr.start_ts > self.timeout:
return self._finalize(key, fr)
return None
def extract(self, fr: FlowRecord) -> dict:
"""Compute 41 NSL-KDD-aligned features from a FlowRecord."""
duration = fr.last_ts - fr.start_ts
iat = fr.iat_list
svc = self.SERVICE_MAP.get(str(fr.dst_port), 'other')
# Count recent connections (last 2 seconds by heuristic)
recent = [h for h in self.history
if h.get('duration', 0) <= 2]
same_host = sum(1 for h in recent
if h.get('dst_ip') == fr.dst_ip)
same_svc = sum(1 for h in recent
if h.get('service') == svc)
return {
# Basic features
'duration': duration,
'protocol_type': fr.protocol,
'service': svc,
'flag': self._derive_flag(fr),
'src_bytes': fr.bytes_fwd,
'dst_bytes': fr.bytes_bwd,
'land': fr.land,
'wrong_fragment': 0,
'urgent': fr.urgent,
# Content features
'hot': 0,
'num_failed_logins': 0,
'logged_in': 1 if fr.bytes_bwd > 1024 else 0,
'num_compromised': 0,
'root_shell': 0,
'su_attempted': 0,
'num_root': 0,
'num_file_creations': 0,
'num_shells': 0,
'num_access_files': 0,
'num_outbound_cmds': 0,
'is_host_login': 0,
'is_guest_login': 0,
# Traffic features
'count': len(recent),
'srv_count': same_svc,
'serror_rate': self._rate(recent, 'flag', 'S0'),
'srv_serror_rate': self._rate(recent, 'flag', 'S0'),
'rerror_rate': self._rate(recent, 'flag', 'REJ'),
'srv_rerror_rate': self._rate(recent, 'flag', 'REJ'),
'same_srv_rate': same_svc / max(len(recent), 1),
'diff_srv_rate': 1 - same_svc / max(len(recent), 1),
'srv_diff_host_rate': 0.0,
'dst_host_count': same_host,
'dst_host_srv_count': same_svc,
'dst_host_same_srv_rate': same_svc / max(same_host, 1),
'dst_host_diff_srv_rate': 0.0,
'dst_host_same_src_port_rate': 0.0,
'dst_host_srv_diff_host_rate': 0.0,
'dst_host_serror_rate': 0.0,
'dst_host_srv_serror_rate': 0.0,
'dst_host_rerror_rate': 0.0,
'dst_host_srv_rerror_rate': 0.0,
# Metadata (not passed to model)
'src_ip': fr.src_ip,
'dst_ip': fr.dst_ip,
'dst_port': fr.dst_port,
}
def _derive_flag(self, fr) -> str:
flags = fr.tcp_flags
if flags['FIN'] and flags['ACK']: return 'SF'
if flags['SYN'] and not flags['ACK']: return 'S0'
if flags['RST']: return 'REJ'
return 'OTH'
def _rate(self, records, field, value) -> float:
if not records: return 0.0
return sum(1 for r in records if r.get(field) == value) / len(records)