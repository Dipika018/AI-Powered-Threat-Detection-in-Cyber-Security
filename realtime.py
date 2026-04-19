from scapy.all import sniff, IP, TCP, UDP, ICMP
import pickle
import json
import pandas as pd
import numpy as np
from datetime import datetime
import requests
import warnings
warnings.filterwarnings('ignore')

# Load model
with open('model/threat_model_cat.pkl', 'rb') as f:
    model = pickle.load(f)

# Load attack mapping
with open('model/attack_mapping.json', 'r') as f:
    attack_mapping = json.load(f)

# Load feature columns
with open('model/feature_columns.json', 'r') as f:
    feature_columns = json.load(f)

print("✅ Model loaded!")
print("🔍 Starting real-time packet capture...")
print("="*50)

# Track connection states for better feature extraction
connection_tracker = {}

def extract_features(packet):
    features = {col: 0 for col in feature_columns}

    if IP in packet:
        features['sbytes'] = len(packet)
        features['dbytes'] = len(packet)
        features['sttl']   = packet[IP].ttl
        features['dttl']   = packet[IP].ttl
        features['smean']  = len(packet)
        features['dmean']  = len(packet)

        # TTL-based features — normal traffic has standard TTL values
        ttl = packet[IP].ttl
        if ttl > 100:
            features['ct_state_ttl'] = 1  # likely normal
        else:
            features['ct_state_ttl'] = 2

    if TCP in packet:
        features['proto'] = 6
        features['swin']  = packet[TCP].window
        features['dwin']  = packet[TCP].window
        features['spkts'] = 1
        features['dpkts'] = 1
        features['rate']  = 100.0

        flags = str(packet[TCP].flags)

        # SYN only = port scan (Reconnaissance)
        if flags == 'S':
            features['state']        = 2
            features['ct_state_ttl'] = 2
            features['ct_srv_src']   = 10
            features['sbytes']       = 0
            features['dbytes']       = 0
            features['swin']         = 0

        # SYN-ACK = normal response
        elif 'S' in flags and 'A' in flags:
            features['state']        = 1
            features['ct_state_ttl'] = 1
            features['swin']         = packet[TCP].window
            features['synack']       = 0.01

        # FIN = connection closing (normal)
        elif 'F' in flags:
            features['state']        = 3
            features['ct_state_ttl'] = 1

        # ACK = data transfer (normal)
        elif flags == 'A':
            features['state']        = 1
            features['ct_state_ttl'] = 1
            features['swin']         = packet[TCP].window

        # RST = reset (could be scan response)
        elif 'R' in flags:
            features['state']        = 4
            features['ct_state_ttl'] = 2

    elif UDP in packet:
        features['proto'] = 17
        features['spkts'] = 1
        features['dpkts'] = 1
        features['state'] = 1
        features['rate']  = 50.0

    elif ICMP in packet:
        features['proto'] = 1
        features['spkts'] = 1
        features['state'] = 1
        # Large ICMP = ping flood (DoS)
        if len(packet) > 100:
            features['sbytes'] = len(packet)
            features['rate']   = 500.0

    return pd.DataFrame([features], columns=feature_columns)

def detect_threat(packet):
    if IP not in packet:
        return

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    pkt_len  = len(packet)

    if TCP in packet:
        proto = "TCP"
    elif UDP in packet:
        proto = "UDP"
    elif ICMP in packet:
        proto = "ICMP"
    else:
        proto = "OTHER"

    try:
        features_df  = extract_features(packet)
        prediction   = model.predict(features_df)[0]
        attack_name  = attack_mapping.get(str(int(prediction)), 'Unknown')
        status       = "NORMAL" if attack_name == "Normal" else "THREAT"
        time_now     = datetime.now().strftime('%H:%M:%S')

        if status == "THREAT":
            print(f"🚨 [{time_now}] {attack_name} | {src_ip} → {dst_ip} | {proto}")
        else:
            print(f"✅ [{time_now}] NORMAL | {src_ip} → {dst_ip} | {proto}")

        # Send to dashboard
        try:
            requests.post('http://127.0.0.1:5000/add_packet', json={
                'time':        time_now,
                'src_ip':      src_ip,
                'dst_ip':      dst_ip,
                'proto':       proto,
                'status':      status,
                'attack_type': attack_name
            }, timeout=2)
        except Exception:
            pass

    except Exception as e:
        print(f"[ERR] {e}")

# Start sniffing
sniff(iface="eth0", prn=detect_threat, store=False)
