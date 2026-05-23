# alert_engine.py
import json, logging, subprocess, datetime, threading
from collections import defaultdict
class AlertEngine:
BLOCK_THRESHOLD = 0.85
BLOCK_DURATION = 600 # seconds
def __init__(self, log_path='alerts.log', enable_prevention=False):
self.enable_prevention = enable_prevention
self.blocked_ips = defaultdict(float)
self.lock = threading.Lock()
handler = logging.FileHandler(log_path)
handler.setFormatter(logging.Formatter('%(message)s'))
self.alert_logger = logging.getLogger('alerts')
self.alert_logger.addHandler(handler)
self.alert_logger.setLevel(logging.INFO)
self.alert_logger.propagate = False
def process(self, result: dict):
if not result or result['label'] == 'Normal':
return
alert = {
    'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
'src_ip': result['src_ip'],
'dst_ip': result['dst_ip'],
'dst_port': result['dst_port'],
'attack_type': result['label'],
'severity': result['severity'],
'confidence':result['confidence'],
'action': 'MONITOR',
}
if (self.enable_prevention
and result['above_threshold']
and result['label_id'] in (1,2,3,4)):
blocked = self._block_ip(result['src_ip'])
alert['action'] = 'BLOCKED' if blocked else 'BLOCK_FAILED'
self.alert_logger.info(json.dumps(alert))
return alert
def _block_ip(self, ip: str) -> bool:
import time
with self.lock:
if time.time() - self.blocked_ips[ip] < self.BLOCK_DURATION:
return True # already blocked
try:
subprocess.run(
['iptables','-I','INPUT','1',
'-s', ip, '-j', 'DROP'],
check=True, capture_output=True)
self.blocked_ips[ip] = time.time()
return True
except subprocess.CalledProcessError as e:
logging.getLogger(__name__).error(
f'iptables error: {e.stderr.decode()}')
return False