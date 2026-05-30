import numpy as np
import sys
import json
import pickle
import tensorflow as tf
from sklearn.preprocessing import Normalizer
from sklearn import preprocessing

ATTACK_DESCRIPTIONS = {
    'dos':    'A Denial-of-Service (DoS) attack floods a machine or network to make it inaccessible. The attacker overwhelms the target with traffic, shutting out legitimate users.',
    'probe':  'A Probe attack scans network devices to find weaknesses in topology or open ports, gathering intelligence for future unauthorized access.',
    'r2l':    'Remote-to-Local (R2L) — an intruder sends packets to a machine where they have no local account, exploiting vulnerabilities to gain unauthorized local access.',
    'u2r':    'User-to-Root (U2R) — an attacker starts with a normal user account and escalates privileges to gain root/admin control of the system.',
    'normal': 'No threat detected. Network traffic appears normal and safe.'
}

def get_label_and_desc(attack_type):
    t = str(attack_type).lower().strip()
    label = t.upper() if t != 'normal' else 'Normal'
    desc  = ATTACK_DESCRIPTIONS.get(t, 'Unknown traffic pattern detected.')
    return label, desc

try:
    prot_type_map = {'tcp': 1, 'udp': 2, 'icmp': 0}
    serv_type_map = {
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
    flag_type_map = {
        'OTH':0,'REJ':1,'RSTO':2,'RSTOS0':3,'RSTR':4,
        'S0':5,'S1':6,'S2':7,'S3':8,'SF':9,'SH':10
    }

    prot  = prot_type_map.get(sys.argv[1])
    svc   = serv_type_map.get(sys.argv[2])
    flag  = flag_type_map.get(sys.argv[3])

    if prot is None or svc is None or flag is None:
        raise ValueError(f"Unknown value: protocol={sys.argv[1]}, service={sys.argv[2]}, flag={sys.argv[3]}")

    features = [
        prot, svc, flag,
        int(sys.argv[4]),    float(sys.argv[5]),
        float(sys.argv[6]),  float(sys.argv[7]),
        float(sys.argv[8]),  float(sys.argv[9]),
        int(sys.argv[10]),   int(sys.argv[11]),
        float(sys.argv[12]), float(sys.argv[13]),
        float(sys.argv[14]), float(sys.argv[15]),
        float(sys.argv[16])
    ]

    f_norm = preprocessing.normalize([features])

    knn_bin    = pickle.load(open('knn_binary_class.sav', 'rb'))
    knn_multi  = pickle.load(open('knn_multi_class.sav', 'rb'))
    rf_bin     = pickle.load(open('random_forest_binary_class.sav', 'rb'))
    rf_multi   = pickle.load(open('random_forest_multi_class.sav', 'rb'))
    cnn_bin    = tf.keras.models.load_model('latest_cnn_bin.h5')
    cnn_multi  = tf.keras.models.load_model('latest_cnn_multiclass.h5')
    lstm_bin   = tf.keras.models.load_model('lstm_latest_bin.h5')
    lstm_multi = tf.keras.models.load_model('lstm_latest_multiclass.h5')

    results = {}

    knn_b = knn_bin.predict(f_norm)[0]
    knn_m = knn_multi.predict(f_norm)[0]
    knn_label, knn_desc = get_label_and_desc(knn_m)
    results['knn'] = {'binary': 'Attack' if knn_b == 1 else 'Normal', 'is_attack': bool(knn_b == 1), 'attack_type': knn_label, 'description': knn_desc}

    rf_b = rf_bin.predict(f_norm)[0]
    rf_m = rf_multi.predict(f_norm)[0]
    rf_label, rf_desc = get_label_and_desc(rf_m)
    results['rf'] = {'binary': 'Attack' if rf_b == 1 else 'Normal', 'is_attack': bool(rf_b == 1), 'attack_type': rf_label, 'description': rf_desc}

    cnn_in_bin  = np.reshape(f_norm, (f_norm.shape[0], 1, f_norm.shape[1]))
    cnn_b_raw   = cnn_bin.predict(cnn_in_bin, verbose=0)
    cnn_b       = round(float(cnn_b_raw[0][0]))
    scaler      = Normalizer().fit(f_norm)
    f_cnn_m     = scaler.transform(f_norm)
    cnn_in_multi = np.reshape(f_cnn_m, (f_cnn_m.shape[0], f_cnn_m.shape[1], 1))
    cnn_m_raw   = cnn_multi.predict(cnn_in_multi, verbose=0)
    cnn_m_idx   = [round(float(x)) for x in cnn_m_raw[0]]
    cnn_types   = ['dos','normal','probe','r2l','u2r']
    cnn_m_type  = next((cnn_types[i] for i, v in enumerate(cnn_m_idx) if v == 1), 'normal')
    cnn_label, cnn_desc = get_label_and_desc(cnn_m_type)
    results['cnn'] = {'binary': 'Attack' if cnn_b == 1 else 'Normal', 'is_attack': bool(cnn_b == 1), 'attack_type': cnn_label, 'description': cnn_desc}

    lstm_in     = np.reshape(f_norm, (f_norm.shape[0], 1, f_norm.shape[1]))
    lstm_b_raw  = lstm_bin.predict(lstm_in, verbose=0)
    lstm_b      = round(float(lstm_b_raw[0][0]))
    lstm_m_raw  = lstm_multi.predict(lstm_in, verbose=0)
    lstm_m_idx  = [round(float(x)) for x in lstm_m_raw[0]]
    lstm_types  = ['dos','normal','probe','r2l','u2r']
    lstm_m_type = next((lstm_types[i] for i, v in enumerate(lstm_m_idx) if v == 1), 'normal')
    lstm_label, lstm_desc = get_label_and_desc(lstm_m_type)
    results['lstm'] = {'binary': 'Attack' if lstm_b == 1 else 'Normal', 'is_attack': bool(lstm_b == 1), 'attack_type': lstm_label, 'description': lstm_desc}

    attack_votes = sum([results['knn']['is_attack'], results['rf']['is_attack'], results['cnn']['is_attack'], results['lstm']['is_attack']])
    results['verdict'] = {'is_attack': attack_votes >= 2, 'votes': attack_votes, 'confidence': f"{attack_votes}/4 models flagged as attack"}

    print(json.dumps(results))

except Exception as e:
    print(json.dumps({'error': str(e)}))
    sys.exit(1)