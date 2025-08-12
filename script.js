/**
 * Script principal para el detector de phishing
 * Maneja la interacción con la UI y comunicación con el backend
 */
document.addEventListener('DOMContentLoaded', () => {
    // Elementos del DOM
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultSection = document.getElementById('result-section');
    const resultContent = document.getElementById('result-content'); // 👈 Nuevo contenedor interno
    const exampleLinks = document.querySelectorAll('.example-link');

    // Configuración del backend
    const BACKEND_URL = 'http://localhost:5000/analyze';

    // Inicialización
    resultSection.style.display = 'none';

    // Event Listeners
    analyzeBtn.addEventListener('click', (e) => {
        e.preventDefault();
        analyzeUrl();
    });

    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeUrl();
    });

    // Validación en tiempo real
    urlInput.addEventListener('input', () => {
        analyzeBtn.disabled = !urlInput.checkValidity();
    });

    exampleLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            urlInput.value = link.getAttribute('data-url');
            analyzeBtn.disabled = false;
            analyzeUrl();
        });
    });

    /**
     * Analiza la URL ingresada por el usuario
     */
async function analyzeUrl() {
    const url = urlInput.value.trim();
    if (!url) {
        showError('Por favor ingresa una URL');
        return;
    }

    showLoading();

    // ----- SIMULACIÓN (COMENTA EL FETCH ORIGINAL) -----
    const mockData = {
        url: url, // Usa la URL ingresada por el usuario
        is_phishing: true,
        malicious: 5,
        suspicious: 2,
        total_engines: 70,
        details: {
            country: "US",
            domain_age: "30 días",
            has_ssl: false
        },
        model_prediction: {
            risk_level: "Alto",
            features_importance: {
                "having_IP_Address": 0.8,
                "URL_Length": 0.6,
                "Shortining_Service": 0.9
            }
        }
    };

    /*try {
        console.log("Enviando solicitud a:", BACKEND_URL); // ✅ Verifica la URL
        const response = await fetch(BACKEND_URL, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ url: normalizeUrl(url) })
        });

        console.log("Respuesta recibida:", response); // ✅ Verifica la respuesta HTTP

        if (!response.ok) {
            let errorMsg = 'Error en el servidor';
            try {
                const errorData = await response.json();
                errorMsg = errorData.error || errorMsg;
            } catch {}
            throw new Error(errorMsg);
        }

        const data = await response.json();
        console.log("Datos del análisis:", data); // ✅ Verifica los datos recibidos

        displayResults(data);

    } catch (error) {
        console.error('Error completo:', error);
        showError(`Error al analizar: ${error.message}`);
    }*/
}

    /**
     * Normaliza la URL agregando protocolo si falta
     */
    function normalizeUrl(url) {
        return !url.startsWith('http') ? `http://${url}` : url;
    }

    /**
     * Muestra estado de carga durante el análisis
     */
    function showLoading() {
        resultSection.style.display = 'block';
        resultSection.className = 'result-section';
        resultSection.classList.remove('has-results');
        resultContent.innerHTML = `
            <div class="loading">
                <div class="loading-spinner"></div>
                <p>Analizando URL...</p>
            </div>
        `;
    }

    /**
     * Muestra los resultados del análisis
     */
    function displayResults(data) {
        console.log("Datos recibidos:", data);
        const riskScore = calculateRiskScore(data);
        const riskLevel = getRiskLevel(riskScore);

        resultSection.className = `result-section ${data.is_phishing ? 'result-malicious' : 'result-safe'} has-results`;
        resultContent.innerHTML = buildResultsHTML(data, riskScore, riskLevel);

        if (data.model_prediction) {
            renderFeatureImportanceChart(data.model_prediction.features_importance);
        }
    }

    function calculateRiskScore(data) {
        return Math.min(100, Math.round((data.malicious / data.total_engines) * 100)) || 0;
    }

    function getRiskLevel(score) {
        return score >= 70 ? "Alto Riesgo" : score >= 30 ? "Medio" : "Bajo";
    }

    function buildResultsHTML(data, riskScore, riskLevel) {
        const details = data.details || {};
        const prediction = data.model_prediction || {};
    
        return `
        <div class="result-content-inner">
            <h3>Resultados para: <span class="url-display">${data.url || 'URL desconocida'}</span></h3>
            
            <div class="top-metrics">
                <div class="risk-score-section">
                    <h4>Score de Riesgo</h4>
                    <div class="risk-gauge" data-score="${riskScore}">
                        <div class="gauge-fill"></div>
                        <span class="gauge-value">${riskScore}%</span>
                    </div>
                    <p class="risk-level ${riskLevel.toLowerCase().replace(' ', '-')}">${riskLevel}</p>
                </div>
                
                <div class="vt-reputation">
                    <h4>Reputación en VirusTotal</h4>
                    <div class="engine-stats">
                        <div class="stat-box malicious">
                            <span class="stat-value">${data.malicious || 0}</span>
                            <span class="stat-label">Maliciosos</span>
                        </div>
                        <div class="stat-box suspicious">
                            <span class="stat-value">${data.suspicious || 0}</span>
                            <span class="stat-label">Sospechosos</span>
                        </div>
                        <div class="stat-box total">
                            <span class="stat-value">${data.total_engines || 0}</span>
                            <span class="stat-label">Total Motores</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="metadata-section">
                <h4>Metadata</h4>
                <div class="metadata-grid">
                    <div class="meta-item">
                        <span class="meta-label">País del Host:</span>
                        <span class="meta-value">${details.country || "Desconocido"}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Antigüedad:</span>
                        <span class="meta-value">${details.domain_age || "Desconocida"}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">SSL:</span>
                        <span class="meta-value ${details.has_ssl ? 'safe' : 'unsafe'}">
                            ${details.has_ssl ? "✅ Válido" : "❌ No válido"}
                        </span>
                    </div>
                </div>
            </div>
            
            ${prediction ? `
            <div class="features-importance">
                <h4>¿Qué factores afectaron el score?</h4>
                <canvas id="featuresChart"></canvas>
            </div>
            ` : ''}
            
            <div class="conclusion-section">
                <h4>Conclusión</h4>
                <p class="conclusion ${data.is_phishing ? 'malicious' : 'safe'}">
                    ${data.is_phishing ? '⚠️ URL POTENCIALMENTE MALICIOSA' : '✅ URL SEGURA'}
                </p>
            </div>
        </div>
        `;
    }

    function renderFeatureImportanceChart(featuresData) {
        const ctx = document.getElementById('featuresChart');
        if (!ctx || !featuresData) return;

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(featuresData),
                datasets: [{
                    label: 'Influencia en el riesgo',
                    data: Object.values(featuresData),
                    backgroundColor: '#e74c3c',
                    borderColor: '#c0392b',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: 'Importancia' } },
                    x: { title: { display: true, text: 'Características' } }
                }
            }
        });
    }

    function showError(message) {
        resultSection.style.display = 'block';
        resultSection.className = 'result-section result-error has-results';
        resultContent.innerHTML = `<div class="result-content"><p>${message}</p></div>`;
    }
});
