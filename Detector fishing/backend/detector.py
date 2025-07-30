import requests
import time
from flask import Flask, request, jsonify
from flask_cors import CORS  # Para manejar CORS con el frontend

class PhishingDetector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/urls"
    
    def scan_url(self, url):
        headers = {
            "x-apikey": self.api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"url": url}
        
        try:
            # Paso 1: Enviar URL para escanear
            response = requests.post(self.base_url, headers=headers, data=data)
            response.raise_for_status()
            
            scan_data = response.json()
            scan_id = scan_data.get("data", {}).get("id")
            
            if not scan_id:
                return {"error": "No se obtuvo ID de análisis", "api_error": True}
            
            # Paso 2: Obtener reporte
            report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
            time.sleep(30)  # Mayor tiempo de espera
            
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
        """Analiza el reporte de VirusTotal para determinar si es phishing."""
        if not isinstance(report, dict):
            return {"error": "Formato de respuesta inválido", "api_error": False}
            
        if report.get("api_error", False):
            return report
            
        if "error" in report:
            return report
            
        # Verificar estructura del reporte con la estructura REAL
        if "data" not in report or "attributes" not in report["data"]:
            return {"error": "Estructura de datos faltante en la respuesta", "api_error": False}
        
        attributes = report["data"]["attributes"]
        
        # Obtener estadísticas del campo correcto ("stats" en lugar de "last_analysis_stats")
        stats = attributes.get("stats", {})
        results = attributes.get("results", {})
        
        # Calcular resultados
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total_engines = malicious + suspicious + harmless + undetected
        
        # Lógica de detección de phishing (ajustada)
        is_phishing = (malicious >= 2) or ((malicious + suspicious) >= 3)
        
        return {
            "url": report.get('scanned_url', ''),
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total_engines,
            "is_phishing": is_phishing,
            "details": results,  # Usamos "results" directamente
            "error": None
        }

# Configuración de Flask
app = Flask(__name__)
CORS(app)
# Reemplaza esto con tu API key real de VirusTotal
API_KEY = "2efaf5c68368a30d86ef65cf13f434b48aa9bd5d79097670c0152240fcaa7ecd"  
detector = PhishingDetector(API_KEY)


#depuracion temporal
@app.route('/analyze', methods=['POST'])
def analyze():
    if not request.is_json:
        return jsonify({"error": "Se requiere un cuerpo JSON"}), 400
    
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "Se requiere una URL"}), 400
    
    url = data['url'].strip()
    print(f"\n=== Analizando URL: {url} ===")  # Depuración
    
    try:
        report = detector.scan_url(url)
        print("Reporte crudo:", report)  # Depuración
        
        analysis = detector.analyze_report(report)
        if analysis.get("error"):
            print("Error en análisis:", analysis["error"])  # Debug
            return jsonify(analysis), 400  # Cambia a 400 si es error del cliente
        return jsonify(analysis)
    except Exception as e:
        print("Error interno:", str(e))
        return jsonify({"error": str(e)}), 500  # Usa 500 para errores internos

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)