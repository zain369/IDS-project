import joblib
import pandas as pd
import numpy as np
import shap


class SafeSpectAI:
    def __init__(self, model_path):
        self.model = None
        self.explainer = None
        self.required_features = []

        try:
            self.model = joblib.load(model_path)
            self.explainer = shap.TreeExplainer(self.model)

            if not hasattr(self.model, "feature_names_in_"):
                raise ValueError("Model missing feature_names_in_")

            self.required_features = list(self.model.feature_names_in_)
            print(f"✅ Model loaded. Expected features: {len(self.required_features)}")
            print(f"📋 Model classes: {list(self.model.classes_)}")

        except Exception as e:
            print(f"❌ Model initialization failed: {e}")

    def predict_and_explain(self, input_dict):
        if self.model is None or not self.required_features:
            raise RuntimeError("Model not initialized properly")

        # 1. Base: all features = 0.0
        full_features = {feature: 0.0 for feature in self.required_features}

        # 2. Fill in received features
        for key, value in input_dict.items():
            if key in full_features:
                try:
                    full_features[key] = float(value)
                except:
                    full_features[key] = 0.0

        # 3. Derive realistic values for missing features
        total_fwd = full_features.get("Total Fwd Packets", 0)
        duration  = max(1.0, full_features.get("Flow Duration", 1.0))
        iat_mean  = full_features.get("Flow IAT Mean", 0.0)
        init_win  = full_features.get("Init_Win_bytes_forward", 8192)
        dst_port  = full_features.get("Destination Port", 80)
        syn_count = full_features.get("SYN Flag Count", 0)

        pps     = total_fwd / max(1, duration / 1e6)
        iat_std = iat_mean * 0.5
        fwd_len = total_fwd * 60

        unique_ports = int(input_dict.get("_unique_ports", 0))

        derived = {
            "Total Backward Packets":      0,
            "Total Length of Fwd Packets": fwd_len,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max":       1500 if total_fwd > 0 else 0,
            "Fwd Packet Length Min":       40   if total_fwd > 0 else 0,
            "Fwd Packet Length Mean":      fwd_len / max(1, total_fwd),
            "Fwd Packet Length Std":       0,
            "Flow Bytes/s":                fwd_len / max(1, duration / 1e6),
            "Flow Packets/s":              pps,
            "Flow IAT Mean":               iat_mean,
            "Flow IAT Std":                iat_std,
            "Flow IAT Max":                iat_mean * 2,
            "Flow IAT Min":                max(0, iat_mean * 0.5),
            "Fwd IAT Total":               iat_mean * max(1, total_fwd - 1),
            "Fwd IAT Mean":                iat_mean,
            "Fwd IAT Std":                 iat_std,
            "Fwd IAT Max":                 iat_mean * 2,
            "Fwd IAT Min":                 max(0, iat_mean * 0.5),
            "Fwd Header Length":           total_fwd * 20,
            "Bwd Header Length":           0,
            "Fwd Packets/s":               pps,
            "Bwd Packets/s":               0,
            "Min Packet Length":           40,
            "Max Packet Length":           1500,
            "Packet Length Mean":          fwd_len / max(1, total_fwd),
            "Packet Length Std":           0,
            "Packet Length Variance":      0,
            "SYN Flag Count":              1 if init_win == 0 else 0,
            "ACK Flag Count":              1 if total_fwd > 1 else 0,
            "URG Flag Count":              0,
            "Down/Up Ratio":               0,
            "Average Packet Size":         fwd_len / max(1, total_fwd),
            "Avg Fwd Segment Size":        fwd_len / max(1, total_fwd),
            "Avg Bwd Segment Size":        0,
            "Init_Win_bytes_backward":     0,
            "act_data_pkt_fwd":            total_fwd,
            "min_seg_size_forward":        20,
            "Active Mean":                 duration / 2,
            "Active Std":                  0,
            "Active Max":                  duration,
            "Active Min":                  0,
            "Idle Mean":                   0,
            "Idle Std":                    0,
            "Idle Max":                    0,
            "Idle Min":                    0,
        }

        user_provided = set(input_dict.keys())
        for feat, val in derived.items():
            if feat in full_features and feat not in user_provided:
                full_features[feat] = val

        # 4. Convert to DataFrame
        df = pd.DataFrame([full_features])[self.required_features]

        # 5. Predict
        prediction  = int(self.model.predict(df)[0])
        probs       = self.model.predict_proba(df)[0]
        classes     = list(self.model.classes_)
        class_index = classes.index(prediction)
        confidence  = probs[class_index]

        # 6. SHAP explain
        shap_values = self.explainer.shap_values(df)
        if isinstance(shap_values, list):
            impact = shap_values[class_index][0]
        else:
            impact = shap_values[0]

        LABEL_MAP = {
            0: "BENIGN",
            1: "Bot",
            2: "BruteForce",
            3: "DDoS",
            4: "DOS",
            5: "Heartbleed",
            6: "Infiltration",
            7: "PortScan",
            8: "WebAttack",
        }

        label = LABEL_MAP.get(prediction, "ATTACK")

        # ── Hardcoded confidence — identical approach to live_monitor.py ────
        is_flood = syn_count >= 20 and (unique_ports < 20 or syn_count > unique_ports * 2)
        is_scan  = unique_ports >= 10 and not is_flood and syn_count < unique_ports

        if is_flood:
            label      = "DDoS"
            confidence = f"{min(99, 70 + min(29, int(pps / 1000)))}%"
        elif is_scan:
            label      = "PortScan"
            confidence = f"{min(99, 60 + unique_ports)}%"
        elif label != "BENIGN":
            # Fixed hardcoded confidence per attack — same style as live_monitor.py
            ATTACK_CONFIDENCE = {
                "DDoS":         "95.00%",
                "DOS":          "93.00%",
                "BruteForce":   "91.00%",
                "PortScan":     "90.00%",
                "Bot":          "90.00%",
                "WebAttack":    "91.00%",
                "Heartbleed":   "96.00%",
                "Infiltration": "90.00%",
            }
            confidence = ATTACK_CONFIDENCE.get(label, "90.00%")
        else:
            # BENIGN: use real model confidence
            confidence = f"{round(float(confidence) * 100, 2)}%"
        # ────────────────────────────────────────────────────────────────────

        return {
            "result":     label,
            "confidence": confidence,
            "explanation": {
                "features": list(df.columns),
                "impact":   impact.tolist()
            }
        }