from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from model_logic import SafeSpectAI

app = Flask(__name__)
app.secret_key = 'safespect_secret_key'

# 1. Define the Label Mapping based on your training data
ATTACK_LABELS = {
    0: "BENIGN",
    1: "Bot",
    2: "BruteForce",
    3: "DDoS",
    4: "Attack",
    5: "Heartbleed",

    6: "Infiltration",
    7: "PortScan",
    8: "WebAttack"
}

# Load the AI Engine once when the server starts
# 


ai_model = SafeSpectAI('frontend/models/ids_model.pkl')

# Mock User Database
users = {
    "admin@safespect.ai": "password123"
}

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

# @app.route('/analyze', methods=['POST'])
# def analyze():
#     try:
#         data = request.json
        
#         # Pre-process: Convert incoming JSON values to floats
#         processed_data = {k: float(v) for k, v in data.items()}
        
#         # Run the AI logic
#         # results usually contains {'result': 0, 'confidence': '...', 'explanation': {...}}
#         results = ai_engine.predict_and_explain(processed_data)
        
#         # 2. Extract the numeric prediction and map it to the Class Name
#         prediction_value = results.get('result')
        
#         # Ensure it's an integer for the dictionary lookup
#         if isinstance(prediction_value, (int, float, str)):
#             prediction_idx = int(float(prediction_value))
#             # Replace the numeric result with the String Label
#             results['result'] = ATTACK_LABELS.get(prediction_idx, f"Unknown ({prediction_idx})")
        
#         return jsonify(results)

#     except Exception as e:
#         return jsonify({"error": str(e)}), 400
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        
        # 1. Get the result from your existing class
        # This handles the 78 features and SHAP internally
        result = ai_model.predict_and_explain(data) 

        # 2. Get the probabilities from your model
        # We need to re-run the 78-feature padding here just for the probability check
        full_features = {feature: 0.0 for feature in ai_model.required_features}
        for key, value in data.items():
            if key in full_features:
                full_features[key] = float(value)
        
        import pandas as pd
        import numpy as np
        df = pd.DataFrame([full_features])[ai_model.required_features]
        probs = ai_model.model.predict_proba(df)[0]
        
        # 3. MAPPING (0=BENIGN, 3=DDoS, etc.)
        attack_labels = {
            0: "BENIGN", 1: "Bot", 2: "BruteForce", 3: "DDoS",
            4: "DOS", 5: "Heartbleed", 6: "Infiltration", 
            7: "PortScan", 8: "WebAttack"
        }

        # 4. SENSITIVITY BOOSTER
        # If Benign is less than 95% sure, look at the other attacks
        benign_prob = probs[0]
        attack_probs = probs[1:] # Index 1 to 8
        
        if benign_prob < 0.95:
            # Pick the strongest attack class index (adding 1 because of the slice)
            final_idx = np.argmax(attack_probs) + 1
        else:
            final_idx = 0

        # Update the result object with the boosted label
        result['result'] = attack_labels.get(final_idx, "BENIGN")
        result['confidence'] = f"{round(float(probs[final_idx]) * 100, 2)}%"
        
        return jsonify(result)
        
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return jsonify({"error": str(e)}), 500



    



if __name__ == '__main__':
    app.run(debug=True)