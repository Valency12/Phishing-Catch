document.addEventListener('DOMContentLoaded', function () {
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultSection = document.getElementById('result-section');
    const exampleLinks = document.querySelectorAll('.example-link');

    // Configura el endpoint de tu backend Flask
    const BACKEND_URL = 'http://localhost:5000/analyze';

    // Manejar clic en botón de análisis
    analyzeBtn.addEventListener('click', analyzeUrl);

    // Manejar Enter en el input
    urlInput.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            analyzeUrl();
        }
    });

    // Manejar ejemplos
    exampleLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            const url = this.getAttribute('data-url');
            urlInput.value = url;
            analyzeUrl();
        });
    });

    function analyzeUrl() {
        const url = urlInput.value.trim();

        if (!url) {
            showError('Por favor ingresa una URL');
            return;
        }

        // Mostrar estado de carga
        showLoading();

        // Enviar la URL al backend Flask
        fetch(BACKEND_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: prepareUrl(url) })
        })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(err => {
                        throw new Error(err.error || 'Error en la respuesta del servidor');
                    });
                }
                return response.json();
            })
            .then(data => {
                if (data.error) {
                    throw new Error(data.error);
                }
                displayResults(data);
            })
            .catch(error => {
                console.error('Error completo:', error);
                let errorMsg = error.message;
                if (error.response) {  // Si hay respuesta del servidor
                    errorMsg = error.response.data.error || errorMsg;
                }
                showError(`Error al analizar la URL: ${errorMsg}`);
            });
    }

    function prepareUrl(url) {
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return 'http://' + url;
        }
        return url;
    }

    function showLoading() {
        resultSection.innerHTML = `
            <div class="loading">
                <div class="loading-spinner"></div>
                <p style="margin-left: 15px;">Analizando URL...</p>
            </div>
        `;
        resultSection.className = 'result-section';
    }

    function displayResults(data) {
        const isPhishing = data.is_phishing;
        resultSection.className = `result-section ${isPhishing ? 'result-malicious' : 'result-safe'}`;

        const riskScore = Math.min(100, Math.round((data.malicious / data.total_engines) * 100)) || 0;
        const riskLevel = riskScore >= 70 ? "Alto Riesgo" : riskScore >= 30 ? "Medio" : "Bajo";

        resultSection.innerHTML = `
        <div class="result-content">
            <h3>Resultados para: <span class="url-display">${data.url || 'URL desconocida'}</span></h3>
            
            <!-- Contenedor flex para Score y Reputación -->
            <div class="top-metrics">
                <!-- Score de Riesgo (Izquierda) -->
                <div class="risk-score-section">
                    <h4>Score de Riesgo</h4>
                    <div class="risk-gauge" data-score="${riskScore}">
                        <div class="gauge-fill"></div>
                        <span class="gauge-value">${riskScore}%</span>
                    </div>
                    <p class="risk-level ${riskLevel.toLowerCase().replace(' ', '-')}">${riskLevel}</p>
                </div>
                
                <!-- Reputación en VirusTotal (Derecha) -->
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
            
            <!-- Metadata -->
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
            
            <!-- Sección de importancia de features (solo si hay datos del modelo) -->
            ${data.model_prediction ? `
            <div class="features-importance">
                <h4>¿Qué factores afectaron el score?</h4>
                <canvas id="featuresChart"></canvas>
            </div>
            ` : ''}
            
            <!-- Conclusión -->
            <div class="conclusion-section">
                <h4>Conclusión</h4>
                <p class="conclusion ${isPhishing ? 'malicious' : 'safe'}">
                    ${isPhishing ? '⚠️ URL POTENCIALMENTE MALICIOSA (Phishing)' : '✅ URL SEGURA'}
                </p>
            </div>
        </div>
        `;

        // Inicializar gráfica si hay datos del modelo
        if (data.model_prediction) {
            renderFeatureImportanceChart(data.model_prediction.features_importance);
        }
    }

    function renderFeatureImportanceChart(featuresData) {
        const ctx = document.getElementById('featuresChart');
        if (!ctx) return;

        const labels = Object.keys(featuresData);
        const values = Object.values(featuresData);

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Influencia en el riesgo',
                    data: values,
                    backgroundColor: '#e74c3c',
                    borderColor: '#c0392b',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Importancia'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'Características'
                        }
                    }
                }
            }
        });
    }

    function showError(message) {
        resultSection.className = 'result-section result-error';
        resultSection.innerHTML = `
            <div class="result-content">
                <p style="color: #e74c3c;">${message}</p>
            </div>
        `;
    }
});