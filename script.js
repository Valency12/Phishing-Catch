document.addEventListener('DOMContentLoaded', () => {
    // Elementos del DOM
    const urlInput = document.getElementById('url-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultSection = document.getElementById('result-section');
    const resultContent = document.getElementById('result-content');
    const exampleLinks = document.querySelectorAll('.example-link');

    // Configuración del backend
    const BACKEND_URL = 'http://localhost:5000/analyze';

    // Inicialización
    resultSection.style.display = 'none';

    // Event Listeners
    analyzeBtn.addEventListener('click', analyzeUrl); // ← pasamos la función directo

    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') analyzeUrl(e); // ← ahora sí le pasamos el evento
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
            analyzeUrl(); // ← sin evento; la función ya lo maneja
        });
    });

    // ---------- FUNCIONES ----------

    // Evento opcional: si viene, lo usamos; si no, no pasa nada
    async function analyzeUrl(ev) {
        if (ev && ev.preventDefault) ev.preventDefault();

        const url = urlInput.value.trim();
        if (!url) {
            showError('Por favor ingresa una URL');
            return;
        }

        showLoading();

        try {
            const normalizedUrl = normalizeUrl(url);
            const response = await fetch(BACKEND_URL, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: normalizedUrl })
            });

            // Intentamos parsear JSON siempre
            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                const msg = (data && data.error) ? data.error : `Error del servidor: ${response.status}`;
                showError(msg);
                return;
            }

            if (data.error) {
                showError(data.error);
                return;
            }

            displayResults(data);
        } catch (error) {
            console.error('Error al analizar URL:', error);
            showError('No se pudo conectar con el servidor.');
        }
    }

    function normalizeUrl(url) {
        return /^(https?:)?\/\//i.test(url) ? url : `http://${url}`;
    }

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

    function displayResults(data) {
        console.log("Datos recibidos:", data);

        const riskScore = calculateRiskScore(data);
        const riskLevel = getRiskLevel(riskScore);

        resultSection.className = `result-section ${data.is_phishing ? 'result-malicious' : 'result-safe'} has-results`;
        resultContent.innerHTML = buildResultsHTML(data, riskScore, riskLevel);

        const fi = data?.model_prediction?.features_importance;
        if (fi && Object.keys(fi).length) {
            renderFeatureImportanceChart(fi);
        }
    }

    // Evita Infinity cuando total_engines = 0
    function calculateRiskScore(data) {
        const total = Number(data.total_engines) || 0;
        const mal = Number(data.malicious) || 0;
        if (total <= 0) return 0;
        return Math.min(100, Math.round((mal / total) * 100));
    }

    function getRiskLevel(score) {
        return score >= 70 ? "Alto Riesgo" : score >= 30 ? "Medio" : "Bajo";
    }

    function buildResultsHTML(data, riskScore, riskLevel) {
        const details = data.details || {};
        const hasFI = data?.model_prediction?.features_importance
                      && Object.keys(data.model_prediction.features_importance).length;

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
            
            ${hasFI ? `
            <div class="features-importance">
                <h4>¿Qué factores afectaron el score?</h4>
                <canvas id="featuresChart"></canvas>
            </div>
            ` : '' }
            
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
