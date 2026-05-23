# classifier_engine.py
import joblib, numpy as np, pandas as pd, logging
from typing import Optional
CLASS_NAMES = {0:'Normal', 1:'DoS', 2:'Probe', 3:'R2L', 4:'U2R'}
SEVERITY = {0:'INFO', 1:'CRITICAL', 2:'HIGH', 3:'HIGH', 4:'CRITICAL'}
class ClassifierEngine:
def __init__(self, model_path: str, threshold: float = 0.85):
artifact = joblib.load(model_path)
self.model = artifact['model']
self.scaler = artifact['scaler']
self.features = artifact['features']
self.threshold = threshold
self.logger = logging.getLogger(__name__)
self.logger.info(f'Model loaded: {model_path}')
def classify(self, flow: dict) -> Optional[dict]:
"""Classify a single flow dict; return result dict."""
try:
vec = pd.DataFrame([flow])[self.features].fillna(0)
vec_s = self.scaler.transform(vec)
proba = self.model.predict_proba(vec_s)[0]
label = int(np.argmax(proba))
conf = float(proba[label])
return {
'label': CLASS_NAMES[label],
'label_id': label,
'confidence': round(conf, 4),
'severity': SEVERITY[label],
'probabilities': {
CLASS_NAMES[i]: round(float(p), 4)
for i, p in enumerate(proba)},
'above_threshold': conf >= self.threshold,
'src_ip': flow.get('src_ip', 'unknown'),
'dst_ip': flow.get('dst_ip', 'unknown'),
'dst_port':flow.get('dst_port', 0),
}
except Exception as e:
self.logger.error(f'Classification error: {e}')
return None