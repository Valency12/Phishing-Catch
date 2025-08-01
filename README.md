# 🛡️ Phishing Catch - Detector Avanzado de Phishing

## 🔍 ¿Qué es Phishing Catch?
Herramienta web que combina:
- API de VirusTotal (70+ motores antivirus)
- Modelo de Machine Learning (RandomForest)
- Explicabilidad con SHAP
para detectar URLs maliciosas en tiempo real.

## 🚀 Características Principales
✔ Análisis de 30+ características técnicas
✔ Score de riesgo (0-100%) con explicación
✔ Historial de análisis (SQLite + CSV)
✔ Panel visual interactivo
✔ Ejemplos prácticos integrados

## ⚙️ Requisitos Técnicos
- Python 3.8+
- Node.js 16+
- Redis (opcional para cache)
- API Key de VirusTotal

## 🛠️ Instalación Paso a Paso

### 1. Configuración del Backend
```bash
git clone https://github.com/tu-usuario/phishshield.git
cd phishshield/backend

python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

pip install -r requirements.txt
echo "VT_API_KEY=tu_clave" > .env
flask run --host=0.0.0.0 --port=5000
```

### 1. Configuración del Frontend
```bash
cd ../frontend
npm install
npm start
```

### 📡 Endpoints Clave
```bash
POST /analyze
Body: {"url": "https://ejemplo.com"}

Response:
{
"is_phishing": boolean,
"risk_score": float,
"features_importance": {feature: value}
}

GET /history - Historial de análisis
POST /train - Reentrenar modelo (admin)
```
### 1. Ejemplo de uso
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://www.ejemplo-sospechoso.com"}'
```

### 📊 Arquitectura del Sistema
```bash
Frontend (React) → Backend (Flask) → VirusTotal API
↓
Modelo ML (RandomForest)
↓
Base de Datos (SQLite/CSV)
```

### 🐛 Solución de Problemas
Error "VT_API_KEY no configurada":

Verificar archivo .env en /backend
Ejecutar: export VT_API_KEY="tu_clave"
Error "Modelo no encontrado":
Ejecutar: python train_model.py
Problemas CORS:
Verificar configuración en backend/app.py
Asegurar URLs permitidas

### 🤝 Cómo Contribuir
✔ Reporta bugs en Issues
✔ Propone nuevas features
✔ Mejora la documentación