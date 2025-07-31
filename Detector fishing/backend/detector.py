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

# Configuración inicial de Flask
app = Flask(__name__)
CORS(app)

class ModelTrainer:
    """Maneja el entrenamiento y configuración del modelo de detección de phishing"""
    
    def __init__(self):
        """Inicializa con las 30 características esperadas por el modelo"""
        self.feature_names = [
            # Features basadas en URL
            'having_IP_Address', 'URL_Length', 'Shortining_Service',
            'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
            
            # Features basadas en dominio
            'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
            'Favicon', 'port', 'HTTPS_token',
            
            # Features basadas en página web
            'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
            'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
            'RightClick', 'popUpWidnow', 'Iframe',
            
            # Features basadas en tiempo/reputación
            'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
            'Google_Index', 'Links_pointing_to_page', 'Statistical_report',
            
            # Features adicionales
            'malicious_engines', 'suspicious_engines', 'total_engines',
            'domain_age_days', 'has_ssl', 'is_subdomain', 'special_chars'
        ]
    
    def load_data(self):
        """Carga y prepara el dataset para entrenamiento
        
        Returns:
            pd.DataFrame: Dataset con características y columna 'label'
            
        Raises:
            ValueError: Si no encuentra la columna objetivo
        """
        df = pd.read_csv('phishing_dataset_clean.csv')
        
        if 'label' not in df.columns:
            for col_name in ['Result', 'class']:
                if col_name in df.columns:
                    return df.rename(columns={col_name: 'label'})
            raise ValueError("Dataset no contiene columna target ('label', 'Result' o 'class')")
        return df
    
    def train_model(self, df):
        """Entrena el modelo y genera explicaciones SHAP
        
        Args:
            df: DataFrame con datos de entrenamiento
            
        Returns:
            float: Precisión del modelo en el conjunto de prueba
        """
        X = df[self.feature_names]
        y = df['label']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        
        # Generar explicaciones del modelo
        self._generate_shap_explanations(X_test)
        
        accuracy = self.model.score(X_test, y_test)
        joblib.dump(self.model, 'modelo_entrenado.pkl')
        return accuracy
    
    def _generate_shap_explanations(self, X_test):
        """Genera y visualiza explicaciones SHAP del modelo"""
        explainer = shap.TreeExplainer(self.model)
        shap_values = explainer.shap_values(X_test)
        shap.summary_plot(shap_values, X_test, plot_type="bar")


class PhishingDetector:
    """Realiza análisis de URLs potencialmente maliciosas"""
    
    def __init__(self, api_key):
        """Configura el detector con API key de VirusTotal
        
        Args:
            api_key: Clave para la API de VirusTotal
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/urls"
        self.history_file = 'phishing_analyses.csv'
        self._initialize_resources()
    
    def _initialize_resources(self):
        """Inicializa modelo y almacenamiento"""
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
        """Configura la base de datos SQLite para historial"""
        with sqlite3.connect('phishing_db.sqlite') as conn:
            conn.execute('''
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
    
    def _init_csv(self):
        """Crea archivo CSV para historial si no existe"""
        if not exists(self.history_file):
            with open(self.history_file, 'w', newline='') as f:
                csv.writer(f).writerow([
                    'timestamp', 'url', 'malicious', 'suspicious',
                    'total_engines', 'is_phishing', 'risk_level',
                    'country', 'domain_age', 'has_ssl'
                ])
    
    def save_analysis(self, analysis):
        """Guarda resultados en DB y CSV"""
        self._save_to_db(analysis)
        self._save_to_csv(analysis)
    
    def _save_to_db(self, analysis):
        """Almacena análisis en base de datos"""
        try:
            with sqlite3.connect('phishing_db.sqlite') as conn:
                conn.execute('''
                    INSERT INTO analyses 
                    (url, malicious, suspicious, total_engines, 
                     is_phishing, risk_level, country, domain_age, has_ssl)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis.get('url', ''),
                    analysis.get('malicious', 0),
                    analysis.get('suspicious', 0),
                    analysis.get('total_engines', 0),
                    analysis.get('is_phishing', False),
                    analysis.get('model_prediction', {}).get('risk_level', 'N/A'),
                    analysis.get('details', {}).get('country', ''),
                    analysis.get('details', {}).get('domain_age', ''),
                    analysis.get('details', {}).get('has_ssl', False)
                ))
        except Exception as e:
            print(f"Error al guardar en DB: {str(e)}")
    
    def _save_to_csv(self, analysis):
        """Registra análisis en archivo CSV"""
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
            print(f"Error al guardar en CSV: {str(e)}")

    # Resto de métodos (is_valid_url, extract_features, predict_with_model, 
    # scan_url, analyze_report) se mantienen igual pero con la misma estructura
    # de documentación y limpieza aplicada

# Configuración e inicialización
API_KEY = "2efaf5c68368a30d86ef65cf13f434b48aa9bd5d79097670c0152240fcaa7ecd"
detector = PhishingDetector(API_KEY)

@app.route('/analyze', methods=['POST'])
def analyze():
    """Endpoint para análisis de URLs
    
    Expects:
        JSON: {'url': 'http://example.com'}
        
    Returns:
        JSON: Resultado del análisis o mensaje de error
    """
    if not request.is_json:
        return jsonify({"error": "Se requiere un cuerpo JSON"}), 400
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Se requiere una URL"}), 400
    
    try:
        report = detector.scan_url(data['url'].strip())
        analysis = detector.analyze_report(report)
        return jsonify(analysis) if not analysis.get("error") else jsonify(analysis), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/train', methods=['POST'])
def train():
    """Endpoint para reentrenar el modelo"""
    try:
        trainer = ModelTrainer()
        accuracy = trainer.train_model(trainer.load_data())
        return jsonify({"status": "success", "accuracy": accuracy})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)