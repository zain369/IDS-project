"""
live_monitor.py — Windows-compatible, fixed DoS vs PortScan detection
"""

import threading
import time
import warnings
import numpy as np
from datetime import datetime
from collections import defaultdict, deque


warnings.filterwarnings("ignore", category=UserWarning)



_NOISE_PORTS = {53, 67, 68, 123, 135, 137, 138, 139, 445, 1900, 3702, 5353, 5355, 5357}


BRUTEFORCE_PORTS  = {22, 21, 80, 443, 3306, 8080}

DDOS_WINDOW       = 10   
DDOS_MIN_SOURCES  = 2


BOT_CHECK_INTERVAL = 5          
BOT_MIN_GAPS        = 3          
BOT_MIN_MEAN_GAP_S  = 3          
BOT_MAX_MEAN_GAP_S  = 600         
BOT_MAX_CV          = 0.25       
BOT_MAX_PACKETS     = 60         
BOT_COOLDOWN        = 20        
BOT_DEFERRAL_WINDOW = 30        


class LiveNetworkMonitor:
    def __init__(self, ai_model):
        self.ai_model = ai_model
        self.running = False
        self._thread = None
        self._events = []
        self._lock = threading.Lock()
        self._flood_events = deque()   
        self._bot_alerted = {}         
        self._src_tracker = defaultdict(lambda: {
            'total_packets': 0,
            'syn_count':     0,
            'dest_ports':    set(),
            'port_counts':   defaultdict(int),   
            'iat_samples':   [],
            'syn_times':     [],   
            'start_time':    None,
            'last_time':     None,
            'last_analyzed': 0,
            'last_bot_check': 0,   
        })
        
        self._http_tracker = defaultdict(lambda: {
            'request_count': 0,
            'suspicious_paths': 0,
            'start_time': None,
            'last_analyzed': 0,
        })
        
        self._suspicious_patterns = [
            '/admin', '/phpmyadmin', '/etc/passwd', '/.env', '/wp-admin',
            '/config', '/backup', '/shell', '/cmd', '/exec', 'select+',
            'union+', '../', '<script', 'passwd', 'shadow', '/cgi-bin',
            '/manager', '/.git', '/api/v1', '/console', 'sqlmap',
            '/login.php', '/wp-login', '/xmlrpc', '/eval(', '/base64'
        ]

    def start(self):
        if self.running:
            print("⚠️  Monitor already running")
            return
        self.running = True
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()
        self._http_thread = threading.Thread(target=self._http_monitor_loop, daemon=True)
        self._http_thread.start()
        self._bot_thread = threading.Thread(target=self._bot_monitor_loop, daemon=True)
        self._bot_thread.start()
        print("✅ Live monitor started")

    def stop(self):
        self.running = False
        print("🛑 Live monitor stopped")

    def get_events_since(self, index):
        with self._lock:
            return list(self._events[index:])

    # ── Entry point ──────────────────────────────────────────────────────────

    def _capture_loop(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP
            print("✅ Scapy found — starting real packet capture")
            self._run_scapy()
        except ImportError:
            print("⚠️  Scapy not installed — pip install scapy")
            print("🎭 Falling back to simulation mode")
            self._simulate_loop()
        except Exception as e:
            print(f"⚠️  Scapy error: {e}")
            print("🎭 Falling back to simulation mode")
            self._simulate_loop()

    # ── Real capture ─────────────────────────────────────────────────────────

    def _run_scapy(self):
        from scapy.all import sniff, IP, TCP, UDP

        def handle_packet(pkt):
            if not self.running or IP not in pkt:
                return

            src_ip   = pkt[IP].src
            dst_port = 0
            is_syn   = False

            if TCP in pkt:
                dst_port = pkt[TCP].dport
                is_syn   = bool(pkt[TCP].flags & 0x02)
            elif UDP in pkt:
                dst_port = pkt[UDP].dport

            
            if dst_port >= 49152 or dst_port in _NOISE_PORTS:
                return

            now = time.time()

            with self._lock:
                s = self._src_tracker[src_ip]
                if s['start_time'] is None:
                    s['start_time'] = now
                else:
                    s['iat_samples'].append((now - s['last_time']) * 1e6)
                s['last_time']      = now
                s['total_packets'] += 1
                s['dest_ports'].add(dst_port)
                s['port_counts'][dst_port] += 1
                if is_syn:
                    s['syn_count'] += 1
                    
                    if not s['syn_times'] or (now - s['syn_times'][-1]) > 1.0:
                        s['syn_times'].append(now)
                        if len(s['syn_times']) > 20:
                            s['syn_times'] = s['syn_times'][-20:]

                unique_ports = len(s['dest_ports'])
                since_last   = now - s['last_analyzed']
                should_analyze = (
                    (unique_ports >= 10 and since_last > 2.0) or
                    (s['total_packets'] >= 30 and since_last > 5.0)
                )

            if should_analyze:
                self._analyze_source(src_ip)

        
        WSL_IFACE = "\\Device\\NPF_{1934BF79-76F0-4D86-8220-85CE3A912F94}"
        print(f"📡 Sniffing on interface: {WSL_IFACE}")

        while self.running:
            sniff(filter="ip dst 172.20.10.2", iface=WSL_IFACE, prn=handle_packet, store=False, timeout=2, count=0)

    # ── Per-source analysis ──────────────────────────────────────────────────

    def _analyze_source(self, src_ip):
        
        if src_ip in ('172.20.10.0', '172.20.10.2', '172.20.10.1'):
            return
        with self._lock:
            if src_ip not in self._src_tracker:
                return
            s = dict(self._src_tracker[src_ip])
            s['dest_ports']  = set(self._src_tracker[src_ip]['dest_ports'])
            s['port_counts'] = dict(self._src_tracker[src_ip]['port_counts'])
            self._src_tracker[src_ip]['last_analyzed'] = time.time()

        unique_ports = len(s['dest_ports'])
        duration     = max(1, int((s['last_time'] - s['start_time']) * 1e6)) if s['start_time'] and s['last_time'] else 1
        iat_mean     = float(np.mean(s['iat_samples'])) if s['iat_samples'] else 0.0
        iat_std      = float(np.std(s['iat_samples']))  if len(s['iat_samples']) > 1 else 0.0
        pps          = s['total_packets'] / max(1, duration / 1e6)

        
        if s['port_counts']:
            most_common_port, dominant_count = max(s['port_counts'].items(), key=lambda kv: kv[1])
        else:
            most_common_port, dominant_count = 0, 0
        dominant_ratio = dominant_count / max(1, s['total_packets'])

        features = {
            "Destination Port":       most_common_port,
            "Flow Duration":          duration,
            "Total Fwd Packets":      s['total_packets'],
            "Total Backward Packets": 0,
            "Flow IAT Mean":          iat_mean,
            "Flow IAT Std":           iat_std,
            "Fwd IAT Mean":           iat_mean,
            "Init_Win_bytes_forward": 0 if s['syn_count'] > 5 else 8192,
            "SYN Flag Count":         s['syn_count'],
            "Fwd Packets/s":          pps,
        }

        
        syn_ratio    = s['syn_count'] / max(1, s['total_packets'])
        is_flood     = s['syn_count'] >= 20 and unique_ports <= 3 and syn_ratio >= 0.5

       
        recently_bot = (time.time() - self._bot_alerted.get(src_ip, 0)) < BOT_DEFERRAL_WINDOW

        is_bruteforce = (
            s['total_packets'] >= 20 and        
            dominant_count >= 15 and            
            dominant_ratio >= 0.6 and           
            not is_flood and
            not recently_bot and
            most_common_port in BRUTEFORCE_PORTS
        )
        is_scan      = unique_ports >= 4 and not is_flood and not is_bruteforce
        print(f"🔍 [{src_ip}] pkts={s['total_packets']} syn={s['syn_count']} ({syn_ratio:.2f}) ports={unique_ports} dom_port={most_common_port} dom_count={dominant_count} pps={pps:.1f} | flood={is_flood} scan={is_scan} bf={is_bruteforce} (recently_bot={recently_bot})")

        try:
            result     = self.ai_model.predict_and_explain(features)
            label      = result['result']
            confidence = result['confidence']

            if is_flood:
                now_f = time.time()
                with self._lock:
                    self._flood_events.append((now_f, src_ip))
                    while self._flood_events and now_f - self._flood_events[0][0] > DDOS_WINDOW:
                        self._flood_events.popleft()
                    distinct_flooders = {ip for _, ip in self._flood_events}

                if len(distinct_flooders) >= DDOS_MIN_SOURCES:
                    label      = 'DDoS'
                    confidence = f"{min(99, 75 + min(24, len(distinct_flooders) * 5))}%"
                    print(f"🚨🚨 DDoS correlated: {len(distinct_flooders)} sources flooding within {DDOS_WINDOW}s -> {sorted(distinct_flooders)}")
                else:
                    label      = 'DoS'
                    confidence = f"{min(99, 70 + min(29, int(pps / 1000)))}%"
            elif is_bruteforce:
                label      = 'BruteForce'
                confidence = f"{min(99, 60 + min(39, s['total_packets'] // 10))}%"
            elif is_scan:
                label      = 'PortScan'
                confidence = f"{min(99, 60 + unique_ports)}%"

            skip_emit = recently_bot and not is_flood and not is_bruteforce and not is_scan
            if skip_emit:
                print(f"🤖⏭️  [{src_ip}] skipping duplicate alert — already reported as Bot")
            else:
                self._emit_event(src_ip, label, confidence, result.get('explanation', {}), unique_ports)

            with self._lock:
                if src_ip in self._src_tracker:
                    now = time.time()
                    preserved_syn_times  = self._src_tracker[src_ip]['syn_times']
                    preserved_bot_check  = self._src_tracker[src_ip]['last_bot_check']
                    self._src_tracker[src_ip] = {
                        'total_packets': 0,
                        'syn_count':     0,
                        'dest_ports':    set(),
                        'port_counts':   defaultdict(int),
                        'iat_samples':   [],
                        'syn_times':     preserved_syn_times,
                        'start_time':    now,
                        'last_time':     now,
                        'last_analyzed': now,
                        'last_bot_check': preserved_bot_check,
                    }

        except Exception as e:
            print(f"⚠️  Prediction error for {src_ip}: {e}")

    # ── HTTP layer monitor ──────────────────────────────────────────────────

    def _http_monitor_loop(self):
        """Monitor Flask's own request log via a queue populated by a middleware hook."""
        while self.running:
            try:
                requests_snapshot = {}
                with self._lock:
                    for ip, data in list(self._http_tracker.items()):
                        if data['request_count'] >= 5 and (time.time() - data['last_analyzed']) > 2.0:
                            requests_snapshot[ip] = dict(data)
                            self._http_tracker[ip]['last_analyzed'] = time.time()

                for src_ip, data in requests_snapshot.items():
                    elapsed   = max(1, time.time() - data['start_time']) if data['start_time'] else 1
                    req_rate  = data['request_count'] / elapsed
                    sus_ratio = data['suspicious_paths'] / max(1, data['request_count'])

                    if sus_ratio > 0.3 or data['suspicious_paths'] >= 3:
                        label      = 'WebAttack'
                        confidence = f"{min(99, 60 + int(sus_ratio * 39))}%"
                    elif req_rate > 10 and data['request_count'] > 20:
                        label      = 'BruteForce'
                        confidence = f"{min(99, 60 + int(req_rate))}%"
                    else:
                        continue  

                    explanation = {
                        'features': ['Destination Port', 'Fwd Packets/s', 'SYN Flag Count'],
                        'impact':   [req_rate, data['request_count'] / 10, sus_ratio * 10]
                    }
                    self._emit_event(src_ip, label, confidence, explanation, 0)

                    with self._lock:
                        if src_ip in self._http_tracker:
                            self._http_tracker[src_ip] = {
                                'request_count':   0,
                                'suspicious_paths': 0,
                                'start_time':      time.time(),
                                'last_analyzed':   time.time(),
                            }

            except Exception as e:
                print(f"⚠️  HTTP monitor error: {e}")
            time.sleep(1.0)

    def record_http_request(self, src_ip, path):
        """Called by Flask middleware for every incoming HTTP request."""
        now = time.time()
        path_lower = path.lower()
        is_suspicious = any(p in path_lower for p in self._suspicious_patterns)

        with self._lock:
            h = self._http_tracker[src_ip]
            if h['start_time'] is None:
                h['start_time'] = now
            h['request_count']   += 1
            if is_suspicious:
                h['suspicious_paths'] += 1

    # ── Bot / C2 beacon monitor ─────────────────────────────────────────────

    def _bot_monitor_loop(self):
        while self.running:
            try:
                now = time.time()
                candidates = {}
                with self._lock:
                    for ip, s in list(self._src_tracker.items()):
                        if ip in ('192.168.100.164', '172.20.48.1', '172.20.10.2', '172.20.10.1'):
                            continue
                        if now - s['last_bot_check'] < BOT_COOLDOWN:
                            continue
                        if len(s['syn_times']) < BOT_MIN_GAPS + 1:
                            continue
                        if s['total_packets'] > BOT_MAX_PACKETS:
                            continue
                        candidates[ip] = {
                            'syn_times':     list(s['syn_times']),
                            'total_packets': s['total_packets'],
                            'dest_ports':    set(s['dest_ports']),
                        }

                for src_ip, data in candidates.items():
                    syn_times = sorted(data['syn_times'])
                    gaps = [b - a for a, b in zip(syn_times, syn_times[1:])]
                    mean_gap = float(np.mean(gaps))
                    std_gap  = float(np.std(gaps))
                    if mean_gap <= 0:
                        continue
                    cv = std_gap / mean_gap

                    is_bot = (
                        BOT_MIN_MEAN_GAP_S <= mean_gap <= BOT_MAX_MEAN_GAP_S and
                        cv <= BOT_MAX_CV and
                        len(data['dest_ports']) <= 2   
                    )
                    print(f"🤖 [{src_ip}] beacon-check: gaps={len(gaps)} mean_gap={mean_gap:.1f}s cv={cv:.2f} | bot={is_bot}")

                    if not is_bot:
                        continue

                    explanation = {
                        'features': ['Flow IAT Mean', 'Flow IAT Std', 'Fwd Packets/s'],
                        'impact':   [mean_gap, std_gap, data['total_packets']]
                    }
                    confidence = f"{min(99, 65 + int((1 - cv) * 34))}%"
                    self._emit_event(src_ip, 'Bot', confidence, explanation, len(data['dest_ports']))

                    with self._lock:
                        if src_ip in self._src_tracker:
                            self._src_tracker[src_ip]['last_bot_check'] = time.time()
                        self._bot_alerted[src_ip] = time.time()

            except Exception as e:
                print(f"⚠️  Bot monitor error: {e}")
            time.sleep(BOT_CHECK_INTERVAL)

    # ── Simulation fallback ──────────────────────────────────────────────────

    def _simulate_loop(self):
        import random
        scenarios = [
            ({"Destination Port": 80,   "Flow Duration": 120000, "Total Fwd Packets": 6,    "Flow IAT Mean": 18000, "Init_Win_bytes_forward": 8192}, None),
            ({"Destination Port": 22,   "Flow Duration": 800,    "Total Fwd Packets": 150,  "Flow IAT Mean": 40,    "Init_Win_bytes_forward": 0},    None),
            ({"Destination Port": 443,  "Flow Duration": 10,     "Total Fwd Packets": 2000, "Flow IAT Mean": 2,     "Init_Win_bytes_forward": 0},    None),
            ({"Destination Port": 445,  "Flow Duration": 500,    "Total Fwd Packets": 50,   "Flow IAT Mean": 100,   "Init_Win_bytes_forward": 0},    "PortScan"),
            ({"Destination Port": 3306, "Flow Duration": 300,    "Total Fwd Packets": 10,   "Flow IAT Mean": 5000,  "Init_Win_bytes_forward": 0},    "WebAttack"),
            ({"Destination Port": 8080, "Flow Duration": 200,    "Total Fwd Packets": 3,    "Flow IAT Mean": 55000, "Init_Win_bytes_forward": 255},  None),
        ]
        sources = ["192.168.1.10", "10.0.0.42", "172.16.0.5", "192.168.0.99", "10.10.10.1"]

        while self.running:
            features, label_override = random.choice(scenarios)
            src  = random.choice(sources)
            port = features.get("Destination Port", 80)
            try:
                result = self.ai_model.predict_and_explain(features)
                label  = label_override if label_override else result['result']
                conf   = result['confidence']
                self._emit_event(src, label, conf, result.get('explanation', {}), 0)
            except Exception as e:
                print(f"❌ Sim error: {e}")
                self._emit_event(src, "BENIGN", "95.00%", {}, 0)
            time.sleep(random.uniform(1.0, 3.0))

    # ── Event emitter ────────────────────────────────────────────────────────

    def _emit_event(self, src_ip, label, confidence, explanation, unique_ports):
        top_features = []
        if explanation and 'features' in explanation and 'impact' in explanation:
            impacts = explanation['impact']
            flat_impacts = []
            for v in impacts:
                if isinstance(v, list):
                    flat_impacts.append(float(v[0]) if v else 0.0)
                else:
                    flat_impacts.append(float(v))
            combined = sorted(
                zip(explanation['features'], flat_impacts),
                key=lambda x: abs(x[1]), reverse=True
            )[:3]
            top_features = [{"name": f, "impact": round(float(v), 4)} for f, v in combined]

        src_display = f"{src_ip} ({unique_ports} ports)" if unique_ports >= 5 else src_ip

        event = {
            "time":         datetime.now().strftime("%H:%M:%S"),
            "src":          src_display,
            "label":        label,
            "confidence":   confidence,
            "top_features": top_features,
            "is_threat":    label != "BENIGN"
        }
        with self._lock:
            self._events.append(event)
            if len(self._events) > 200:
                self._events = self._events[-200:]

        icon = "🚨" if label != "BENIGN" else "✅"
        print(f"{icon} [{event['time']}] {label} from {src_ip} | ports={unique_ports} ({confidence})")