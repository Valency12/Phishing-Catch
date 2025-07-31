/**
 * Script principal para el detector de phishing
 * Maneja la interacción con la UI y comunicación con el backend
 */
document.addEventListener('DOMContentLoaded', () => {
    // Elementos del DOM
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultSection = document.getElementById('result-section');
    const exampleLinks = document.querySelectorAll('.example-link');
    
    // Configuración del backend
    const BACKEND_URL = 'http://localhost:5000/analyze';

    // Event Listeners
    analyzeBtn.addEventListener('click', analyzeUrl);
    urlInput.addEventListener('keypress', (e) => e.key === 'Enter' && analyzeUrl());
    
    exampleLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            urlInput.value = link.getAttribute('data-url');
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
        
        try {
            const response = await fetch(BACKEND_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: normalizeUrl(url) })
            });

            const data = await response.json();
            
            if (!response.ok || data.error) {
                throw new Error(data.error || 'Error en el servidor');
            }

            displayResults(data);
        } catch (error) {
            console.error('Error completo:', error);
            showError(`Error al analizar: ${error.message}`);
        }
    }

    /**
     * Normaliza la URL agregando protocolo si falta
     * @param {string} url - URL a normalizar
     * @returns {string} URL normalizada
     */
    function normalizeUrl(url) {
        return !url.startsWith('http') ? `http://${url}` : url;
    }

    /**
     * Muestra estado de carga durante el análisis
     */
    function showLoading() {
        resultSection.innerHTML = `
            <div class="loading">
                <div class="loading-spinner"></div>
                <p>Analizando URL...</p>
            </div>
        `;
        resultSection.className = 'result-section';
    }

    /**
     * Muestra los resultados del análisis
     * @param {object} data - Datos de respuesta del backend
     */
    function displayResults(data) {
        const riskScore = calculateRiskScore(data);
        const riskLevel = getRiskLevel(riskScore);
        
        resultSection.className = `result-section ${data.is_phishing ? 'result-malicious' : 'result-safe'}`;
        resultSection.innerHTML = buildResultsHTML(data, riskScore, riskLevel);

        if (data.model_prediction) {
            renderFeatureImportanceChart(data.model_prediction.features_importance);
        }
    }

    /**
     * Calcula el score de riesgo (0-100)
     * @param {object} data - Datos del análisis
     * @returns {number} Puntaje de riesgo
     */
    function calculateRiskScore(data) {
        return Math.min(100, Math.round((data.malicious / data.total_engines) * 100)) || 0;
    }

    /**
     * Determina el nivel de riesgo basado en el score
     * @param {number} score - Puntaje de riesgo
     * @returns {string} Nivel de riesgo (Alto/Medio/Bajo)
     */
    function getRiskLevel(score) {
        return score >= 70 ? "Alto Riesgo" : score >= 30 ? "Medio" : "Bajo";
    }

    /**
     * Genera el HTML para mostrar los resultados
     */
    function buildResultsHTML(data, riskScore, riskLevel) {
        return `
        <div class="result-content">
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
                        <span class="meta-value">${data.details?.country || "Desconocido"}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">Antigüedad:</span>
                        <span class="meta-value">${data.details?.domain_age || "Desconocida"}</span>
                    </div>
                    <div class="meta-item">
                        <span class="meta-label">SSL:</span>
                        <span class="meta-value ${data.details?.has_ssl ? 'safe' : 'unsafe'}">
                            ${data.details?.has_ssl ? "✅ Válido" : "❌ No válido"}
                        </span>
                    </div>
                </div>
            </div>
            
            ${data.model_prediction ? `
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

    /**
     * Renderiza el gráfico de importancia de características
     * @param {object} featuresData - Datos de características del modelo
     */
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

    /**
     * Muestra mensaje de error al usuario
     * @param {string} message - Mensaje de error a mostrar
     */
    function showError(message) {
        resultSection.className = 'result-section result-error';
        resultSection.innerHTML = `<div class="result-content"><p>${message}</p></div>`;
    }
});