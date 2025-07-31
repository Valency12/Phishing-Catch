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
from scipy.io.arff import loadarff
from data_preprocessing import download_and_process_data

app = Flask(__name__)
CORS(app)

class ModelTrainer:
    def __init__(self):
        self.model = None
        self.explainer = None
        self.feature_names = [
            'malicious_engines',
            'suspicious_engines',
            'total_engines',
            'domain_age_days',
            'has_ssl',
            'is_subdomain',
            'special_chars'
        ]
    
    def load_data(self, filepath=None):
        """Carga directamente el CSV limpio"""
        df = pd.read_csv('phishing_dataset_clean.csv')
        
        if 'label' not in df.columns:
            # Verifica nombres alternativos por si acaso
            if 'Result' in df.columns:
                df.rename(columns={'Result': 'label'}, inplace=True)
            elif 'class' in df.columns:
                df.rename(columns={'class': 'label'}, inplace=True)
            else:
                raise ValueError("Dataset no contiene columna target ('label', 'Result' o 'class')")
        
        return df
    
    def train_model(self, df):
        """Entrena el modelo y el explainer SHAP"""
        X = df[self.feature_names]
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Crear explainer SHAP
        self.explainer = shap.TreeExplainer(self.model)
        shap_values = self.explainer.shap_values(X_test)
        shap.summary_plot(shap_values, X_test, plot_type="bar")
        
        accuracy = self.model.score(X_test, y_test)
        print(f"Precisión del modelo: {accuracy:.2f}")
        
        # Guardar modelo entrenado
        joblib.dump(self.model, 'modelo_entrenado.pkl')
        return accuracy

class PhishingDetector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/urls"
        
        try:
            self.model = joblib.load('modelo_entrenado.pkl')
            self.model_loaded = True
        except Exception as e:
            print(f"⚠️ Modelo no cargado (pero funciona sin IA). Error: {str(e)}")
            self.model_loaded = False
            self.model = None  # Asegurar que esté definido

    
    def _init_db(self):
        """Inicializa la base de datos SQLite"""
        conn = sqlite3.connect('phishing_db.sqlite')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
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
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def _init_csv(self):
        """Inicializa el archivo CSV si no existe"""
        if not exists(self.history_file):
            with open(self.history_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'url', 'malicious', 
                    'suspicious', 'total_engines', 'is_phishing', 
                    'risk_level', 'country', 'domain_age', 'has_ssl'
                ])
    
    def _save_to_db(self, analysis):
        """Guarda el análisis en la base de datos SQLite"""
        try:
            conn = sqlite3.connect('phishing_db.sqlite')
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analyses 
                (url, malicious, suspicious, is_phishing, risk_level, country, domain_age, has_ssl)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis.get('url', ''),
                analysis.get('malicious', 0),
                analysis.get('suspicious', 0),
                analysis.get('is_phishing', False),
                analysis.get('model_prediction', {}).get('risk_level', 'N/A'),  # Maneja None
                analysis.get('details', {}).get('country', ''),
                analysis.get('details', {}).get('domain_age', ''),
                analysis.get('details', {}).get('has_ssl', False)
            ))
            conn.commit()
        except Exception as e:
            print(f"Error al guardar en DB: {str(e)}")
        finally:
            conn.close()
    def _save_to_csv(self, analysis):
        """Guarda el análisis en el archivo CSV"""
        try:
            with open(self.history_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
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
            print(f"Error al guardar en CSV: {str(e)}")
    
    def save_analysis(self, analysis):
        """Guarda el análisis en ambos formatos (DB y CSV)"""
        self._save_to_db(analysis)
        self._save_to_csv(analysis)
    
    def extract_features(self, vt_data, details):
        """Extrae características para el modelo de IA"""
        return {
            'malicious_engines': vt_data.get('malicious', 0),
            'suspicious_engines': vt_data.get('suspicious', 0),
            'total_engines': vt_data.get('total_engines', 0),
            'domain_age_days': details.get('domain_age_days', 0),
            'has_ssl': int(details.get('has_ssl', False)),
            'is_subdomain': int(details.get('is_subdomain', False)),
            'special_chars': details.get('special_chars', 0)
        }
    
    def predict_with_model(self, features):
        """Realiza predicción con el modelo de IA"""
        if not self.model_loaded:
            return None
            
        # Convertir features a formato adecuado
        features_list = [features[col] for col in [
            'malicious_engines',
            'suspicious_engines',
            'total_engines',
            'domain_age_days',
            'has_ssl',
            'is_subdomain',
            'special_chars'
        ]]
        
        prediction = self.model.predict([features_list])[0]
        probabilities = self.model.predict_proba([features_list])[0]
        
        # Obtener importancia de características
        if hasattr(self.model, 'feature_importances_'):
            importance = dict(zip([
                'Motores maliciosos',
                'Motores sospechosos',
                'Total motores',
                'Antigüedad dominio',
                'Tiene SSL',
                'Es subdominio',
                'Caracteres especiales'
            ], self.model.feature_importances_))
        else:
            importance = None
            
        return {
            'risk_level': prediction,
            'probabilities': dict(zip(self.model.classes_, probabilities)),
            'features_importance': importance
        }
    
    def scan_url(self, url):
        """Escanea una URL con VirusTotal"""
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"url": url}
        
        try:
            response = requests.post(self.base_url, headers=headers, data=data)
            response.raise_for_status()
            
            scan_data = response.json()
            scan_id = scan_data.get("data", {}).get("id")
            
            if not scan_id:
                return {"error": "No se obtuvo ID de análisis", "api_error": True}
            
            report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            time.sleep(15)  # Espera inicial
            
            for _ in range(3):  # Reintentar 3 veces
                report_response = requests.get(report_url, headers=headers)
                if report_response.status_code == 200:
                    report = report_response.json()
                    report['scanned_url'] = url
                    return report
                time.sleep(10)
                
            return {"error": "Tiempo de espera agotado", "api_error": True}
            
        except Exception as e:
            return {"error": str(e), "api_error": True}
    
    def analyze_report(self, report):
        """Analiza el reporte de VirusTotal"""
        if not isinstance(report, dict):
            return {"error": "Formato de respuesta inválido", "api_error": False}
            
        if report.get("api_error", False):
            return report
            
        if "error" in report:
            return report
            
        if "data" not in report or "attributes" not in report["data"]:
            return {"error": "Estructura de datos faltante", "api_error": False}
        
        attributes = report["data"]["attributes"]
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})
        
        # Datos básicos de VT
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_engines = malicious + suspicious + stats.get("harmless", 0) + stats.get("undetected", 0)
        
        # Datos adicionales (simulados - deberías extraerlos de otras APIs)
        details = {
            'country': "Desconocido",
            'domain_age': "Desconocida",
            'has_ssl': False,
            'is_subdomain': False,
            'special_chars': 0
        }
        
        # Análisis básico
        is_phishing = (malicious >= 2) or ((malicious + suspicious) >= 3)
        
        # Predicción con modelo de IA si está disponible
        model_prediction = None
        if self.model_loaded:
            features = self.extract_features({
                'malicious': malicious,
                'suspicious': suspicious,
                'total_engines': total_engines
            }, details)
            model_prediction = self.predict_with_model(features)
        
        analysis_result = {
            "url": report.get('scanned_url', ''),
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total_engines,
            "is_phishing": is_phishing,
            "details": {
                "country": details['country'],
                "domain_age": details['domain_age'],
                "has_ssl": details['has_ssl']
            },
            "model_prediction": model_prediction,
            "error": None
        }
        
        # Guardar el análisis
        self.save_analysis(analysis_result)
        
        return analysis_result

# Configuración inicial
API_KEY = "2efaf5c68368a30d86ef65cf13f434b48aa9bd5d79097670c0152240fcaa7ecd"
detector = PhishingDetector(API_KEY)

# Ruta para análisis
@app.route('/analyze', methods=['POST'])
def analyze():
    if not request.is_json:
        return jsonify({"error": "Se requiere un cuerpo JSON"}), 400
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Se requiere una URL"}), 400
    
    url = data['url'].strip()
    
    try:
        report = detector.scan_url(url)
        analysis = detector.analyze_report(report)
        
        if analysis.get("error"):
            return jsonify(analysis), 400
            
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Ruta para entrenar el modelo (opcional)
@app.route('/train', methods=['POST'])
def train():
    try:
        trainer = ModelTrainer()
        df = trainer.load_data()
        accuracy = trainer.train_model(df)
        return jsonify({"status": "success", "accuracy": accuracy})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)