import requests
import time
import joblib
import pandas as pd
import shap
from flask import Flask, request, jsonify
from flask_cors import CORS
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import sqlite3
from datetime import datetime
import csv
from os.path import exists
import urllib.parse
from tldextract import extract
from data_preprocessing import download_and_process_data
import socket

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Permite todos los orígenes

class ModelTrainer:
    def __init__(self):
        self.feature_names = [
            'having_IP_Address', 'URL_Length', 'Shortining_Service',
            'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
            'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
            'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
            'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
            'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
            'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
        ]
    
    def load_data(self):
        df = pd.read_csv('phishing_dataset_clean.csv')
        if 'label' not in df.columns:
            for col_name in ['Result', 'class']:
                if col_name in df.columns:
                    return df.rename(columns={col_name: 'label'})
            raise ValueError("Dataset no contiene columna target")
        return df
    
    def train_model(self, df):
        X = df[self.feature_names]
        y = df['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        joblib.dump(self.model, 'modelo_entrenado.pkl')
        return self.model.score(X_test, y_test)

class PhishingDetector:
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/urls"
        self.history_file = 'phishing_analyses.csv'
        self._initialize_resources()
    
    def _initialize_resources(self):
        try:
            self.model = joblib.load('modelo_entrenado.pkl')
            self.model_loaded = True
        except Exception as e:
            print(f"⚠️ Modelo no cargado. Error: {str(e)}")
            self.model_loaded = False
            self.model = None
        self._init_db()
        self._init_csv()
    
    def _init_db(self):
        with sqlite3.connect('phishing_db.sqlite') as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                malicious INTEGER,
                suspicious INTEGER,
                total_engines INTEGER,
                is_phishing BOOLEAN,
                risk_level TEXT,
                country TEXT,
                domain_age TEXT,
                has_ssl BOOLEAN,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    def _init_csv(self):
        if not exists(self.history_file):
            with open(self.history_file, 'w', newline='') as f:
                csv.writer(f).writerow([
                    'timestamp', 'url', 'malicious', 'suspicious',
                    'total_engines', 'is_phishing', 'risk_level',
                    'country', 'domain_age', 'has_ssl'
                ])
    
    def scan_url(self, url):
        """Versión simulada para desarrollo sin API real"""
        print(f"Escaneando URL (simulado): {url}")
        return {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 5 if 'paypal' in url.lower() else 0,
                        'suspicious': 2 if 'paypal' in url.lower() else 0,
                        'harmless': 65
                    },
                    'url': url,
                    'creation_date': time.time() - (365 * 2 * 86400),
                    'last_https_certificate': {'valid': True},
                    'country': 'US'
                }
            }
        }
    
    def analyze_report(self, report):
        if not report:
            return {"error": "No se pudo obtener reporte"}
        
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        analysis = {
            "url": report.get('data', {}).get('attributes', {}).get('url', ''),
            "malicious": stats.get('malicious', 0),
            "suspicious": stats.get('suspicious', 0),
            "total_engines": sum(stats.values()),
            "details": self.extract_url_details(report),
            "is_phishing": False
        }
        
        if self.model_loaded:
            features = self.extract_features(analysis)
            analysis["is_phishing"] = self.predict_with_model(features)
            analysis["model_prediction"] = {
                "risk_level": self.calculate_risk_level(analysis),
                "features_importance": self.get_feature_importance(features)
            }
        
        self.save_analysis(analysis)
        return analysis
    
    def extract_url_details(self, report):
        attributes = report.get('data', {}).get('attributes', {})
        return {
            "country": attributes.get('country', 'Desconocido'),
            "domain_age": self.format_domain_age(attributes.get('creation_date', 0)),
            "has_ssl": attributes.get('last_https_certificate', {}).get('valid', False)
        }
    
    def format_domain_age(self, timestamp):
        if not timestamp:
            return "Desconocida"
        return f"{(datetime.now() - datetime.fromtimestamp(timestamp)).days} días"
    
    def _has_ip_address(self, url):
        try:
            domain = urllib.parse.urlparse(url).netloc.split(':')[0]
            socket.inet_aton(domain)
            return True
        except:
            return False
    
    def extract_features(self, analysis):
        extracted = extract(analysis['url'])
        return {
            'having_IP_Address': int(self._has_ip_address(analysis['url'])),
            'URL_Length': len(analysis['url']),
            'Shortining_Service': int(any(x in analysis['url'] for x in ['bit.ly', 'goo.gl', 'tinyurl'])),
            'having_At_Symbol': int('@' in analysis['url']),
            'double_slash_redirecting': int(analysis['url'].count('//') > 1),
            'has_ssl': int(analysis['details']['has_ssl']),
            'domain_age_days': int(analysis['details']['domain_age'].split()[0]) if analysis['details']['domain_age'] != 'Desconocida' else 0,
            'having_Sub_Domain': int(bool(extracted.subdomain)),
            'Prefix_Suffix': int('-' in extracted.domain)
        }
    
    def predict_with_model(self, features):
        if not self.model_loaded:
            return False
        try:
            feature_vector = [features.get(col, 0) for col in self.model.feature_names_in_]
            return bool(self.model.predict([feature_vector])[0])
        except Exception as e:
            print(f"Error en predicción: {e}")
            return False
    
    def calculate_risk_level(self, analysis):
        risk_score = (analysis['malicious'] / analysis['total_engines']) * 100
        return "Alto" if risk_score > 70 else "Medio" if risk_score > 30 else "Bajo"
    
    def get_feature_importance(self, features):
        return {k: 0.5 for k in features.keys()}
    
    def save_analysis(self, analysis):
        self._save_to_db(analysis)
        self._save_to_csv(analysis)
    
    def _save_to_db(self, analysis):
        try:
            with sqlite3.connect('phishing_db.sqlite') as conn:
                conn.execute('''
                    INSERT INTO analyses 
                    (url, malicious, suspicious, total_engines, is_phishing, risk_level, country, domain_age, has_ssl)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', (
                    analysis['url'], analysis['malicious'], analysis['suspicious'],
                    analysis['total_engines'], analysis['is_phishing'],
                    analysis.get('model_prediction', {}).get('risk_level', 'N/A'),
                    analysis['details']['country'], analysis['details']['domain_age'],
                    analysis['details']['has_ssl']
                ))
        except Exception as e:
            print(f"Error al guardar en DB: {e}")

    def _save_to_csv(self, analysis):
        try:
            with open(self.history_file, 'a', newline='') as f:
                csv.writer(f).writerow([
                    datetime.now().isoformat(),
                    analysis['url'],
                    analysis['malicious'],
                    analysis['suspicious'],
                    analysis['total_engines'],
                    analysis['is_phishing'],
                    analysis.get('model_prediction', {}).get('risk_level', ''),
                    analysis['details']['country'],
                    analysis['details']['domain_age'],
                    analysis['details']['has_ssl']
                ])
        except Exception as e:
            print(f"Error al guardar en CSV: {e}")

# Configuración
detector = PhishingDetector()

@app.route('/analyze', methods=['POST'])
def analyze():
    if not request.is_json:
        return jsonify({"error": "Se requiere JSON"}), 400
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Se requiere URL"}), 400
    
    try:
        url = data['url'].strip()
        print(f"🔍 Analizando URL: {url}")  # ✅ Verifica que el backend reciba la URL
        report = detector.scan_url(url)
        analysis = detector.analyze_report(report)
        
        print("📊 Resultado del análisis:", analysis)  # ✅ Verifica los datos antes de enviarlos
        
        return jsonify({
            "url": url,
            "is_phishing": analysis.get('is_phishing', False),
            "malicious": analysis.get('malicious', 0),
            "suspicious": analysis.get('suspicious', 0),
            "total_engines": analysis.get('total_engines', 0),
            "details": analysis.get('details', {}),
            "model_prediction": analysis.get('model_prediction', {})
        })
    except Exception as e:
        print("❌ Error en /analyze:", str(e))
        return jsonify({"error": str(e)}), 500
@app.route('/train', methods=['POST'])
def train():
    try:
        trainer = ModelTrainer()
        df = download_and_process_data()
        accuracy = trainer.train_model(df)
        return jsonify({"status": "success", "accuracy": accuracy})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
