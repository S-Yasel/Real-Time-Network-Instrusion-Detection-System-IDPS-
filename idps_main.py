#!/usr/bin/env python3
# idps_main.py – IDPS Main Orchestrator
# Usage: sudo python idps_main.py --interface eth0 \
# --model models/rf_nslkdd.pkl
import argparse, logging, queue, signal, sys, time
from packet_capture import PacketCapture
from feature_extractor import FlowExtractor
from classifier_engine import ClassifierEngine
from alert_engine import AlertEngine
logging.basicConfig(
level=logging.INFO,
format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
handlers=[logging.StreamHandler(),
logging.FileHandler('idps.log')]
)
log = logging.getLogger('idps.main')
def parse_args():
p = argparse.ArgumentParser(description='ML-IDPS Real-Time Engine')
p.add_argument('--interface', '-i', help='Network interface (live capture)')
p.add_argument('--pcap', '-p', help='PCAP file (offline mode)')
p.add_argument('--model', '-m', required=True,
help='Path to trained model artifact (.pkl)')
p.add_argument('--threshold', '-t', type=float, default=0.85,
help='Alert confidence threshold (default: 0.85)')
p.add_argument('--prevent', action='store_true',
help='Enable iptables-based IP blocking')
p.add_argument('--alerts', '-a', default='alerts.json',
help='Alert log file path')
return p.parse_args()
def main():
args = parse_args()
if not args.interface and not args.pcap:
print('[!] Specify --interface or --pcap'); sys.exit(1)
capture = PacketCapture(
interface=args.interface, pcap_file=args.pcap)
extractor = FlowExtractor(flow_timeout=60)
classifier = ClassifierEngine(
args.model, threshold=args.threshold)
alerter = AlertEngine(
log_path=args.alerts,
enable_prevention=args.prevent)
# Graceful shutdown
running = [True]
def _sig(sig, frame):
log.info('Shutting down...')
running[0] = False
capture.stop()
signal.signal(signal.SIGINT, _sig)
signal.signal(signal.SIGTERM, _sig)
if args.interface:
capture.start_live()
log.info(f'Live capture started on {args.interface}')
else:
capture.start_offline()
log.info(f'Offline replay from {args.pcap}')
total = alerts = 0
start = time.time()
log.info('IDPS engine running. Press Ctrl+C to stop.')
while running[0]:
try:
pkt = capture.get(timeout=0.5)
except queue.Empty:
if args.pcap and capture.pkt_queue.empty():
break
continue
features = extractor.update(pkt)
if features is None:
continue
total += 1
result = classifier.classify(features)
if result:
alert = alerter.process(result)
if alert:
alerts += 1
log.warning(
f"ALERT [{alert['severity']}] {alert['attack_type']} "
f"from {alert['src_ip']} "
f"confidence={alert['confidence']:.3f} "
f"action={alert['action']}"
)
elapsed = time.time() - start
log.info(f'Session complete: {total} flows, {alerts} alerts '
f'in {elapsed:.1f}s ({total/elapsed:.0f} flows/sec)')
log.info(f'Capture stats: {capture.stats}')
if __name__ == '__main__':
main()