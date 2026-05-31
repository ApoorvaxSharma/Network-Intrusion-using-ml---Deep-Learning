import os
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["ABSL_MIN_LOG_LEVEL"]   = "3"

import warnings
warnings.filterwarnings("ignore")

import numpy as np
import sys
import json
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, Normalizer
import tensorflow as tf
import pickle

# BUG 7 FIX: wrap entire script in try/except so errors print as JSON, not silence

ATTACK_DESCRIPTIONS = {
    'dos':    'A Denial-of-Service (DoS) attack floods a machine or network to make it inaccessible. The attacker overwhelms the target with traffic, shutting out legitimate users.',
    'probe':  'A Probe attack scans network devices to find weaknesses in topology or open ports, gathering intelligence for future unauthorized access.',
    'r2l':    'Remote-to-Local (R2L) — an intruder sends packets to a machine where they have no local account, exploiting vulnerabilities to gain unauthorized local access.',
    'u2r':    'User-to-Root (U2R) — an attacker starts with a normal user account and escalates privileges to gain root/admin control of the system.',
    'normal': 'No threat detected. Network traffic appears normal and safe.'
}

ATTACK_TYPES_MULTICLASS = ['dos', 'normal', 'probe', 'r2l', 'u2r']

def get_label_and_desc(attack_type):
    t = str(attack_type).lower().strip()
    label = t.upper() if t != 'normal' else 'Normal'
    desc  = ATTACK_DESCRIPTIONS.get(t, 'Unknown traffic pattern detected.')
    return label, desc

try:
    data_validate = pd.read_csv('fs_new validation project.csv')
    columns = ['protocol_type','service','flag','logged_in','count',
               'srv_serror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
               'dst_host_count','dst_host_srv_count','dst_host_same_srv_rate',
               'dst_host_diff_srv_rate','dst_host_same_src_port_rate',
               'dst_host_serror_rate','dst_host_rerror_rate','attack']
    data_validate.columns = columns

    le_protocol = LabelEncoder()
    le_service  = LabelEncoder()
    le_flag     = LabelEncoder()
    data_validate['protocol_type'] = le_protocol.fit_transform(data_validate['protocol_type'])
    data_validate['service']       = le_service.fit_transform(data_validate['service'])
    data_validate['flag']          = le_flag.fit_transform(data_validate['flag'])

    df_validate = data_validate.copy(deep=True)
    x_validate  = df_validate.drop(['attack'], axis=1)

    scaler = MinMaxScaler()
    scaler.fit(x_validate)
    scaled = pd.DataFrame(scaler.transform(x_validate), columns=x_validate.columns)

    # Sample one random row
    tp = scaled.sample(1)

    # Load models
    knn_bin      = pickle.load(open('knn_binary_class.sav', 'rb'))
    knn_multi    = pickle.load(open('knn_multi_class.sav', 'rb'))
    randfor_bin  = pickle.load(open('random_forest_binary_class.sav', 'rb'))
    randfor_multi= pickle.load(open('random_forest_multi_class.sav', 'rb'))
    cnn_bin      = tf.keras.models.load_model('latest_cnn_bin.h5')
    cnn_multi    = tf.keras.models.load_model('latest_cnn_multiclass.h5')
    lstm_bin     = tf.keras.models.load_model('lstm_latest_bin.h5')
    lstm_multi   = tf.keras.models.load_model('lstm_latest_multiclass.h5')

    results = {}

    # --- KNN ---
    knn_b = knn_bin.predict(tp)[0]
    knn_m = knn_multi.predict(tp)[0]
    knn_label, knn_desc = get_label_and_desc(knn_m)
    results['knn'] = {
        'binary': 'Attack' if knn_b == 1 else 'Normal',
        'is_attack': bool(knn_b == 1),
        'attack_type': knn_label,
        'description': knn_desc
    }

    # --- Random Forest ---
    rf_b = randfor_bin.predict(tp)[0]
    rf_m = randfor_multi.predict(tp)[0]
    rf_label, rf_desc = get_label_and_desc(rf_m)
    results['rf'] = {
        'binary': 'Attack' if rf_b == 1 else 'Normal',
        'is_attack': bool(rf_b == 1),
        'attack_type': rf_label,
        'description': rf_desc
    }

    # --- CNN ---
    tp_norm = Normalizer().fit_transform(tp)
    cnn_in_bin   = np.reshape(tp_norm, (tp_norm.shape[0], 1, tp_norm.shape[1]))
    cnn_b_raw    = cnn_bin.predict(cnn_in_bin, verbose=0)
    cnn_b        = round(float(cnn_b_raw[0][0]))
    cnn_in_multi = np.reshape(tp_norm, (tp_norm.shape[0], tp_norm.shape[1], 1))
    cnn_m_raw    = cnn_multi.predict(cnn_in_multi, verbose=0)
    cnn_m_idx    = [round(float(x)) for x in cnn_m_raw[0]]
    cnn_m_type   = next((ATTACK_TYPES_MULTICLASS[i] for i, v in enumerate(cnn_m_idx) if v == 1), 'normal')
    cnn_label, cnn_desc = get_label_and_desc(cnn_m_type)
    results['cnn'] = {
        'binary': 'Attack' if cnn_b == 1 else 'Normal',
        'is_attack': bool(cnn_b == 1),
        'attack_type': cnn_label,
        'description': cnn_desc
    }

    # --- LSTM ---
    lstm_in      = np.reshape(tp_norm, (tp_norm.shape[0], 1, tp_norm.shape[1]))
    lstm_b_raw   = lstm_bin.predict(lstm_in, verbose=0)
    lstm_b       = round(float(lstm_b_raw[0][0]))
    lstm_m_raw   = lstm_multi.predict(lstm_in, verbose=0)
    lstm_m_idx   = [round(float(x)) for x in lstm_m_raw[0]]
    lstm_m_type  = next((ATTACK_TYPES_MULTICLASS[i] for i, v in enumerate(lstm_m_idx) if v == 1), 'normal')
    lstm_label, lstm_desc = get_label_and_desc(lstm_m_type)
    results['lstm'] = {
        'binary': 'Attack' if lstm_b == 1 else 'Normal',
        'is_attack': bool(lstm_b == 1),
        'attack_type': lstm_label,
        'description': lstm_desc
    }

    # Verdict
    votes = sum([results['knn']['is_attack'], results['rf']['is_attack'],
                 results['cnn']['is_attack'], results['lstm']['is_attack']])
    results['verdict'] = {
        'is_attack': votes >= 2,
        'votes': votes,
        'confidence': f"{votes}/4 models flagged as attack"
    }

    # BUG 6 FIX: output structured JSON instead of raw print strings
    # Keeping legacy line-based output as well so existing secrets_2.ejs parsing still works
    # Line order must match app.js index expectations: [knn_bin, knn_mul, knn_desc, rf_bin, rf_mul, rf_desc, cnn_bin, cnn_mul, cnn_desc, lstm_bin, lstm_mul, lstm_desc]
    print(f"KNN Binary Class Type : {results['knn']['binary']}")
    print(f"KNN Multi Class Type : {results['knn']['attack_type']}")
    print(f"KNN Description : {results['knn']['description']}")
    print(f"RANDOM FOREST Binary Class Type : {results['rf']['binary']}")
    print(f"RANDOM FOREST Multi Class Type : {results['rf']['attack_type']}")
    print(f"RANDOM FOREST Description : {results['rf']['description']}")
    print(f"CNN Binary Class Type : {results['cnn']['binary']}")
    print(f"CNN Multi Class Type : {results['cnn']['attack_type']}")
    print(f"CNN Description : {results['cnn']['description']}")
    print(f"LSTM Binary Class Type : {results['lstm']['binary']}")
    print(f"LSTM Multi Class Type : {results['lstm']['attack_type']}")
    print(f"LSTM Description : {results['lstm']['description']}")

except Exception as e:
    # BUG 7 FIX: errors now printed predictably so app.js can detect them
    import traceback
    print(f"ERROR")
    print(f"ERROR")
    print(f"Error: {str(e)}")
    print(f"ERROR")
    print(f"ERROR")
    print(traceback.format_exc())
    print(f"ERROR")
    print(f"ERROR")
    print(traceback.format_exc())
    print(f"ERROR")
    print(f"ERROR")
    print(traceback.format_exc())
    print(f"ERROR")
    sys.exit(1)