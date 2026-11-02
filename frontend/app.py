from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response, stream_with_context
from model_logic import WardnAI
from live_monitor import LiveNetworkMonitor
import json
import time

app = Flask(__name__)
app.secret_key = 'wardn_secret_key'

ATTACK_LABELS = {
    0: "BENIGN", 1: "Bot", 2: "BruteForce", 3: "DoS",
    4: "DoS", 5: "Heartbleed", 6: "Infiltration",
    7: "PortScan", 8: "WebAttack"
}

# Load the AI Engine once when the server starts
ai_model = WardnAI('frontend/models/ids_model.pkl')

# Initialize the live monitor
monitor = LiveNetworkMonitor(ai_model)

# Mock User Database
users = {
    "admin@wardn.ai": "password123"
}
@app.before_request
def track_request():
    src_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Strip port if present
    src_ip = src_ip.split(':')[0]
    monitor.record_http_request(src_ip, request.path)
    
@app.route('/')
def index():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', user_email=session['user_email'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email in users and users[email] == password:
            session['user_email'] = email
            return redirect(url_for('index'))
        else:
            flash("Invalid email or password", "error")
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users[email] = password
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_email', None)
    return redirect(url_for('login'))

# ── Live Monitoring Routes ────────────────────────────────────────────────────

@app.route('/monitor/start', methods=['POST'])
def start_monitor():
    monitor.start()
    return jsonify({"status": "started"})

@app.route('/monitor/stop', methods=['POST'])
def stop_monitor():
    monitor.stop()
    return jsonify({"status": "stopped"})

@app.route('/monitor/stream')
def monitor_stream():
    """SSE endpoint — the browser connects here to receive live events."""
    def event_generator():
        last_index = 0
        # Send a heartbeat immediately so browser knows connection is alive
        yield "data: {\"type\":\"connected\"}\n\n"
        while monitor.running:
            events = monitor.get_events_since(last_index)
            for event in events:
                last_index += 1
                yield f"data: {json.dumps(event)}\n\n"
            time.sleep(0.5)
        yield "data: {\"type\":\"stopped\"}\n\n"

    return Response(
        stream_with_context(event_generator()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

# ── Manual Analysis Route ─────────────────────────────────────────────────────

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        result = ai_model.predict_and_explain(data)

        import pandas as pd
        import numpy as np

        full_features = {feature: 0.0 for feature in ai_model.required_features}
        for key, value in data.items():
            if key in full_features:
                full_features[key] = float(value)

        df = pd.DataFrame([full_features])[ai_model.required_features]
        probs = ai_model.model.predict_proba(df)[0]

        benign_prob = probs[0]
        attack_probs = probs[1:]

        if benign_prob < 0.95:
            final_idx = np.argmax(attack_probs) + 1
        else:
            final_idx = 0

        result['result'] = ATTACK_LABELS.get(final_idx, "BENIGN")

        return jsonify(result)

    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)