# evaluate_model.py – Offline evaluation with plots
import joblib, numpy as np, pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
classification_report, confusion_matrix,
roc_auc_score, ConfusionMatrixDisplay)
from train_model import load_nslkdd, FEATURES
CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']
def evaluate(model_path, test_path):
artifact = joblib.load(model_path)
model, scaler = artifact['model'], artifact['scaler']
X_test, y_test = load_nslkdd(test_path)
X_test_s = scaler.transform(X_test)
y_pred = model.predict(X_test_s)
y_proba = model.predict_proba(X_test_s)
print(classification_report(
y_test, y_pred, target_names=CLASS_NAMES))
# ROC-AUC (macro, one-vs-rest)
auc = roc_auc_score(
y_test, y_proba, multi_class='ovr', average='macro')
print(f'Macro ROC-AUC: {auc:.4f}')
# Confusion matrix heatmap
cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
xticklabels=CLASS_NAMES, yticklabels=CLASS_NAMES, ax=ax)
ax.set_xlabel('Predicted'); ax.set_ylabel('Actual')
ax.set_title('Confusion Matrix – Random Forest (NSL-KDD KDDTest+)')
plt.tight_layout()
plt.savefig('outputs/confusion_matrix.png', dpi=150)
print('Confusion matrix saved to outputs/confusion_matrix.png')
# Feature importance
importances = model.feature_importances_
sorted_idx = np.argsort(importances)[::-1][:20]
fig2, ax2 = plt.subplots(figsize=(10, 6))
ax2.barh([FEATURES[i] for i in sorted_idx[::-1]],
importances[sorted_idx[::-1]], color='steelblue')
ax2.set_title('Top 20 Feature Importances (Random Forest)')
plt.tight_layout()
plt.savefig('outputs/feature_importance.png', dpi=150)
print('Feature importance plot saved.')
if __name__ == '__main__':
evaluate('models/rf_nslkdd.pkl', 'data/KDDTest+.csv')