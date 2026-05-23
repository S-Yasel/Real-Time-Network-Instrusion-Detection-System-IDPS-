# train_model.py
import pandas as pd, numpy as np, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import StratifiedKFold, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
FEATURES = [ # 41 NSL-KDD features (content-only cols dropped)
'duration','protocol_type','service','flag','src_bytes',
'dst_bytes','land','wrong_fragment','urgent','hot',
'num_failed_logins','logged_in','num_compromised','root_shell',
'su_attempted','num_root','num_file_creations','num_shells',
'num_access_files','num_outbound_cmds','is_host_login',
'is_guest_login','count','srv_count','serror_rate',
'srv_serror_rate','rerror_rate','srv_rerror_rate',
'same_srv_rate','diff_srv_rate','srv_diff_host_rate',
'dst_host_count','dst_host_srv_count',
'dst_host_same_srv_rate','dst_host_diff_srv_rate',
'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
'dst_host_serror_rate','dst_host_srv_serror_rate',
'dst_host_rerror_rate','dst_host_srv_rerror_rate'
]
LABEL_MAP = {'normal':0,'dos':1,'probe':2,'r2l':3,'u2r':4}
DOE_ATTACKS = {'neptune','smurf','pod','teardrop','back',
'land','apache2','processtable','udpstorm'}
PROBE_ATTACKS= {'portsweep','ipsweep','nmap','satan','saint','mscan'}
R2L_ATTACKS = {'ftp_write','guess_passwd','imap','multihop',
'phf','spy','warezclient','warezmaster'}
U2R_ATTACKS = {'buffer_overflow','loadmodule','perl','rootkit',
'xterm','ps','sqlattack','httptunnel'}
def map_label(label):
l = label.lower().rstrip('.')
if l == 'normal': return 0
if l in DOE_ATTACKS: return 1
if l in PROBE_ATTACKS: return 2
if l in R2L_ATTACKS: return 3
if l in U2R_ATTACKS: return 4
return 1 # default: DoS
def load_nslkdd(path):
cols = FEATURES + ['label','difficulty']
df = pd.read_csv(path, header=None, names=cols)
for col in ['protocol_type','service','flag']:
df[col] = LabelEncoder().fit_transform(df[col].astype(str))
df['label'] = df['label'].apply(map_label)
return df[FEATURES], df['label']
def train(train_path, test_path, model_out='models/rf_nslkdd.pkl'):
print('[*] Loading NSL-KDD dataset...')
X_train, y_train = load_nslkdd(train_path)
X_test, y_test = load_nslkdd(test_path)
scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)
# SMOTE for minority classes
print('[*] Applying SMOTE oversampling...')
sm = SMOTE(sampling_strategy='minority', random_state=42, k_neighbors=5)
X_res, y_res = sm.fit_resample(X_train_s, y_train)
print(f' After SMOTE: {dict(zip(*np.unique(y_res,
return_counts=True)))}')
# Hyperparameter grid search
param_grid = {
'n_estimators': [100, 200],
'max_features': ['sqrt', 'log2'],
'min_samples_leaf': [1, 2],
}
rf = RandomForestClassifier(
class_weight='balanced', random_state=42, n_jobs=-1)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
gs = GridSearchCV(rf, param_grid, cv=cv,
scoring='f1_macro', n_jobs=-1, verbose=1)
print('[*] Starting GridSearchCV (5-fold)...')
gs.fit(X_res, y_res)
print(f' Best params: {gs.best_params_}')
print(f' Best CV F1 (macro): {gs.best_score_:.4f}')
# Final evaluation
best_rf = gs.best_estimator_
y_pred = best_rf.predict(X_test_s)
print('\n[*] Test Set Classification Report:')
print(classification_report(
y_test, y_pred,
target_names=['Normal','DoS','Probe','R2L','U2R']
))
# Persist model + scaler
joblib.dump({'model': best_rf, 'scaler': scaler,
'features': FEATURES}, model_out)
print(f'[+] Model saved to {model_out}')
if __name__ == '__main__':
train('data/KDDTrain+.csv', 'data/KDDTest+.csv')