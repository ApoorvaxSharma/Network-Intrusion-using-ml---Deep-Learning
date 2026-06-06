import matplotlib
matplotlib.use('Agg')
matplotlib.rcParams['figure.dpi'] = 150

import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["ABSL_MIN_LOG_LEVEL"] = "3"
os.chdir(os.path.dirname(os.path.abspath(__file__)))

import warnings
warnings.filterwarnings("ignore")

import numpy as np
import pandas as pd
import pickle
import matplotlib.pyplot as plt
import tensorflow as tf
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, Normalizer
from sklearn.metrics import (
    confusion_matrix, ConfusionMatrixDisplay,
    classification_report, f1_score
)

# ─────────────────────────────────────────────────────────────────
# STEP 1 — Load & preprocess  (mirrors nids_parameter_updated.py)
# ─────────────────────────────────────────────────────────────────
print("Loading data...")
data = pd.read_csv('fs_new validation project.csv')

columns = ['protocol_type','service','flag','logged_in','count',
           'srv_serror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
           'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
           'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
           'dst_host_serror_rate','dst_host_rerror_rate','attack']
data.columns = columns

# ── Use EXACT same encoding maps as nids_parameter_updated.py ──
prot_map  = {'tcp': 1, 'udp': 2, 'icmp': 0}
flag_map  = {'OTH':0,'REJ':1,'RSTO':2,'RSTOS0':3,'RSTR':4,
             'S0':5,'S1':6,'S2':7,'S3':8,'SF':9,'SH':10}
serv_map  = {
    'IRC':0,'X11':1,'Z39_50':2,'http_8001':3,'auth':4,'bgp':5,'courier':6,
    'csnet_ns':7,'ctf':8,'daytime':9,'discard':10,'domain':11,'domain_u':12,
    'echo':13,'eco_i':14,'ecr_i':15,'efs':16,'exec':17,'finger':18,'ftp':19,
    'ftp_data':20,'gopher':21,'harvest':22,'hostnames':23,'http':24,'http_2784':25,
    'http_443':26,'aol':27,'imap4':28,'iso_tsap':29,'klogin':30,'kshell':31,
    'ldap':32,'link':33,'login':34,'mtp':35,'name':36,'netbios_dgm':37,
    'netbios_ns':38,'netbios_ssn':39,'netstat':40,'nnsp':41,'nntp':42,'ntp_u':43,
    'other':44,'pm_dump':45,'pop_2':46,'pop_3':47,'printer':48,'private':49,
    'red_i':50,'remote_job':51,'rje':52,'shell':53,'smtp':54,'sql_net':55,
    'ssh':56,'sunrpc':57,'supdup':58,'systat':59,'telnet':60,'tftp_u':61,
    'tim_i':62,'time':63,'urh_i':64,'urp_i':65,'uucp':66,'uucp_path':67,
    'vmnet':68,'whois':69
}

data['protocol_type'] = data['protocol_type'].str.lower().map(prot_map).fillna(0).astype(int)
data['service']       = data['service'].map(serv_map).fillna(44).astype(int)   # 44 = 'other'
data['flag']          = data['flag'].map(flag_map).fillna(9).astype(int)        # 9  = 'SF'

X     = data.drop(['attack'], axis=1)
y_raw = data['attack'].str.lower().str.strip()

# ── Binary ground truth: 0 = normal, 1 = attack ──
y_binary = (y_raw != 'normal').astype(int).values

# ── Multi-class ground truth: strings matching model output ──
# KNN/RF predict strings; CNN/LSTM use ['dos','normal','probe','r2l','u2r']
# Ground truth must be in the same string space.
dos_attacks = {
    'back','land','neptune','pod','smurf','teardrop','apache2',
    'udpstorm','processtable','worm','mailbomb'
}
probe_attacks = {'ipsweep','nmap','portsweep','satan','mscan','saint'}
r2l_attacks   = {
    'ftp_write','guess_passwd','imap','multihop','phf','spy',
    'warezclient','warezmaster','sendmail','named','snmpgetattack',
    'snmpguess','xlock','xsnoop','httptunnel'
}
u2r_attacks   = {
    'buffer_overflow','loadmodule','perl','rootkit','sqlattack','xterm','ps'
}

def map_category(lbl):
    lbl = str(lbl).lower().strip()
    if lbl == 'normal':          return 'normal'
    if lbl in dos_attacks:       return 'dos'
    if lbl in probe_attacks:     return 'probe'
    if lbl in r2l_attacks:       return 'r2l'
    if lbl in u2r_attacks:       return 'u2r'
    return 'dos'   # unknown attack → treat as DoS

y_multi = y_raw.apply(map_category).values   # string array

print("Label distribution in validation set:")
for lbl, cnt in zip(*np.unique(y_multi, return_counts=True)):
    print(f"  {lbl:8s}: {cnt:,}")

# ── Scale X exactly as nids_parameter_updated.py: Normalizer only ──
X_np   = X.values.astype(float)
X_norm = Normalizer().fit_transform(X_np)   # shape (n, 16)

# ─────────────────────────────────────────────────────────────────
# STEP 2 — Load all 8 models
# ─────────────────────────────────────────────────────────────────
print("Loading models...")
knn_bin    = pickle.load(open('knn_binary_class.sav',          'rb'))
knn_multi  = pickle.load(open('knn_multi_class.sav',           'rb'))
rf_bin     = pickle.load(open('random_forest_binary_class.sav','rb'))
rf_multi   = pickle.load(open('random_forest_multi_class.sav', 'rb'))
cnn_bin    = tf.keras.models.load_model('latest_cnn_bin.h5')
cnn_multi  = tf.keras.models.load_model('latest_cnn_multiclass.h5')
lstm_bin   = tf.keras.models.load_model('lstm_latest_bin.h5')
lstm_multi = tf.keras.models.load_model('lstm_latest_multiclass.h5')

# ─────────────────────────────────────────────────────────────────
# STEP 3 — Predictions  (mirrors inference logic in nids_parameter_updated.py)
# ─────────────────────────────────────────────────────────────────
print("Running predictions (this takes 1-2 min)...")

# ── KNN & RF: predict directly on normalised features ──
pred_knn_b = knn_bin.predict(X_norm)           # int array: 0 or 1
pred_knn_m = knn_multi.predict(X_norm)         # string array: 'dos','normal',...
pred_rf_b  = rf_bin.predict(X_norm)
pred_rf_m  = rf_multi.predict(X_norm)

# ── CNN binary: reshape to (n, 1, 16) ──
X_cnn_bin  = X_norm.reshape(X_norm.shape[0], 1, X_norm.shape[1])
pred_cnn_b = (cnn_bin.predict(X_cnn_bin, verbose=0)[:,0] >= 0.5).astype(int)

# ── CNN multi: reshape to (n, 16, 1) ──
X_cnn_multi   = X_norm.reshape(X_norm.shape[0], X_norm.shape[1], 1)
cnn_m_raw     = cnn_multi.predict(X_cnn_multi, verbose=0)          # (n, 5)
CNN_TYPES     = np.array(['dos','normal','probe','r2l','u2r'])
pred_cnn_m    = CNN_TYPES[cnn_m_raw.argmax(axis=1)]                # string array

# ── LSTM binary: reshape to (n, 1, 16) ──
X_lstm        = X_norm.reshape(X_norm.shape[0], 1, X_norm.shape[1])
pred_lstm_b   = (lstm_bin.predict(X_lstm, verbose=0)[:,0] >= 0.5).astype(int)

# ── LSTM multi: same shape (n, 1, 16) ──
lstm_m_raw    = lstm_multi.predict(X_lstm, verbose=0)              # (n, 5)
LSTM_TYPES    = np.array(['dos','normal','probe','r2l','u2r'])
pred_lstm_m   = LSTM_TYPES[lstm_m_raw.argmax(axis=1)]             # string array

# Ordered label list — consistent across all figures
MULTI_STR = ['dos', 'normal', 'probe', 'r2l', 'u2r']
MULTI_CAP = ['DoS', 'Normal', 'Probe', 'R2L', 'U2R']

# ─────────────────────────────────────────────────────────────────
# STEP 4 — Figure 1: Binary Confusion Matrices
# ─────────────────────────────────────────────────────────────────
print("Saving Figure 1 — binary confusion matrices...")
fig, axes = plt.subplots(1, 4, figsize=(20, 5))
fig.suptitle(
    'Binary Classification – Confusion Matrices  (Validation Set · 8,019 records)',
    fontsize=12, fontweight='bold'
)
for ax, (name, preds) in zip(axes, [
    ('LSTM',          pred_lstm_b),
    ('CNN',           pred_cnn_b),
    ('Random Forest', pred_rf_b),
    ('KNN',           pred_knn_b),
]):
    cm   = confusion_matrix(y_binary, preds, labels=[0, 1])
    disp = ConfusionMatrixDisplay(cm, display_labels=['Normal', 'Attack'])
    disp.plot(ax=ax, colorbar=False, cmap='Blues')
    ax.set_title(name, fontsize=11, fontweight='bold')

plt.tight_layout()
plt.savefig('fig1_confusion_binary.png', bbox_inches='tight')
plt.close()
print("  → saved: fig1_confusion_binary.png")

# ─────────────────────────────────────────────────────────────────
# STEP 5 — Figure 2: Multi-class Confusion Matrices
# ─────────────────────────────────────────────────────────────────
print("Saving Figure 2 — multi-class confusion matrices...")
fig, axes = plt.subplots(1, 4, figsize=(24, 6))
fig.suptitle(
    'Multi-class Classification – Confusion Matrices  (Validation Set · 8,019 records)',
    fontsize=12, fontweight='bold'
)
for ax, (name, preds) in zip(axes, [
    ('LSTM',          pred_lstm_m),
    ('CNN',           pred_cnn_m),
    ('Random Forest', pred_rf_m),
    ('KNN',           pred_knn_m),
]):
    # labels= forces full 5×5 even when a class has 0 predictions
    cm   = confusion_matrix(y_multi, preds, labels=MULTI_STR)
    disp = ConfusionMatrixDisplay(cm, display_labels=MULTI_CAP)
    disp.plot(ax=ax, colorbar=False, cmap='Blues')
    ax.set_title(name, fontsize=11, fontweight='bold')
    ax.tick_params(axis='x', rotation=45)

plt.tight_layout()
plt.savefig('fig2_confusion_multiclass.png', bbox_inches='tight')
plt.close()
print("  → saved: fig2_confusion_multiclass.png")

# ─────────────────────────────────────────────────────────────────
# STEP 6 — Figure 3: Classification Reports (text image)
# ─────────────────────────────────────────────────────────────────
print("Saving Figure 3 — classification reports...")
report_lines = []
for name, preds_b, preds_m in [
    ('LSTM',          pred_lstm_b, pred_lstm_m),
    ('CNN',           pred_cnn_b,  pred_cnn_m),
    ('Random Forest', pred_rf_b,   pred_rf_m),
    ('KNN',           pred_knn_b,  pred_knn_m),
]:
    report_lines.append(f"{'='*58}")
    report_lines.append(f"  {name}  —  BINARY CLASSIFICATION")
    report_lines.append(f"{'='*58}")
    report_lines.append(classification_report(
        y_binary, preds_b,
        target_names=['Normal', 'Attack'], digits=4
    ))
    report_lines.append(f"{'='*58}")
    report_lines.append(f"  {name}  —  MULTI-CLASS CLASSIFICATION")
    report_lines.append(f"{'='*58}")
    report_lines.append(classification_report(
        y_multi, preds_m,
        target_names=MULTI_CAP,
        labels=MULTI_STR,
        digits=4,
        zero_division=0
    ))
    report_lines.append("")

report_text = "\n".join(report_lines)
print(report_text)

fig, ax = plt.subplots(figsize=(14, len(report_lines) * 0.22 + 1))
ax.axis('off')
ax.text(0.01, 0.99, report_text,
        transform=ax.transAxes,
        fontfamily='monospace', fontsize=7.5,
        verticalalignment='top')
plt.tight_layout()
plt.savefig('fig3_classification_reports.png', bbox_inches='tight', dpi=180)
plt.close()
print("  → saved: fig3_classification_reports.png")

# ─────────────────────────────────────────────────────────────────
# STEP 7 — Figure 4: Per-class F1 bar chart (all 4 models)
# ─────────────────────────────────────────────────────────────────
print("Saving Figure 4 — per-class F1 bar chart...")
f1_lstm = f1_score(y_multi, pred_lstm_m, average=None, labels=MULTI_STR, zero_division=0)
f1_cnn  = f1_score(y_multi, pred_cnn_m,  average=None, labels=MULTI_STR, zero_division=0)
f1_rf   = f1_score(y_multi, pred_rf_m,   average=None, labels=MULTI_STR, zero_division=0)
f1_knn  = f1_score(y_multi, pred_knn_m,  average=None, labels=MULTI_STR, zero_division=0)

x = np.arange(len(MULTI_CAP))
w = 0.2
fig, ax = plt.subplots(figsize=(11, 5))
ax.bar(x - 1.5*w, f1_lstm, w, label='LSTM',          color='#2196F3')
ax.bar(x - 0.5*w, f1_cnn,  w, label='CNN',           color='#4CAF50')
ax.bar(x + 0.5*w, f1_rf,   w, label='Random Forest', color='#FF9800')
ax.bar(x + 1.5*w, f1_knn,  w, label='KNN',           color='#9C27B0')
ax.set_xticks(x)
ax.set_xticklabels(MULTI_CAP)
ax.set_ylabel('F1-Score')
ax.set_title('Per-class F1-Score — Multi-class Classification (All 4 Models)', fontweight='bold')
ax.set_ylim(0, 1.05)
ax.legend()
ax.grid(axis='y', alpha=0.3)
plt.tight_layout()
plt.savefig('fig4_perclass_f1.png', bbox_inches='tight')
plt.close()
print("  → saved: fig4_perclass_f1.png")

print("\n✓ Done. 4 figures saved:")
print("   fig1_confusion_binary.png")
print("   fig2_confusion_multiclass.png")
print("   fig3_classification_reports.png")
print("   fig4_perclass_f1.png")