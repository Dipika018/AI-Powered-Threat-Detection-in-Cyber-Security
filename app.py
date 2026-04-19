from flask import Flask, render_template, jsonify, request
import pickle
import json
from datetime import datetime

app = Flask(__name__)

# Load model
with open('model/threat_model.pkl', 'rb') as f:
    model = pickle.load(f)

# Store ALL packets
all_packets = []
threat_packets = []

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/add_packet', methods=['POST'])
def add_packet():
    data = request.json
    all_packets.append(data)
    # Store threats separately
    if data.get('status') == 'THREAT':
        threat_packets.append(data)
        print(f"🚨 THREAT added: {data['src_ip']} → {data['dst_ip']}")
    return jsonify({'status': 'ok'})

@app.route('/status')
def status():
    total   = len(all_packets)
    threats = len(threat_packets)
    normal  = total - threats
    threat_rate = round((threats / total * 100), 1) if total > 0 else 0
    
    # Return last 100 of all packets for display
    return jsonify({
        'all_packets': all_packets[-500:],
        'packets':      threat_packets,
        'total':        total,
        'threats':      threats,
        'normal':       normal,
        'threat_rate':  threat_rate
    })

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
