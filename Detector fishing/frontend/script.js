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

        resultSection.innerHTML = `
            <div class="result-content" style="display: block;">
                <h3>Resultado para ${data.url || 'la URL'}</h3>
                <div class="result-stats">
                    <p><strong>Motores maliciosos:</strong> ${data.malicious || 0}</p>
                    <p><strong>Motores sospechosos:</strong> ${data.suspicious || 0}</p>
                    <p><strong>Total de motores:</strong> ${data.total_engines || 0}</p>
                </div>
                <div class="result-conclusion">
                    <p><strong>Conclusión:</strong> ${isPhishing ?
                '<span style="color: #e74c3c;">⚠️ POSIBLE PHISHING ⚠️</span>' :
                '<span style="color: #2ecc71;">✅ Parece segura</span>'}</p>
                </div>
                ${data.details ? `
                <div class="result-details">
                    <button id="toggle-details" class="details-btn">Mostrar detalles</button>
                    <div id="details-content" style="display: none; margin-top: 10px;">
                        <pre>${JSON.stringify(data.details, null, 2)}</pre>
                    </div>
                </div>
                ` : ''}
            </div>
        `;

        // Agregar evento para mostrar/ocultar detalles
        const toggleBtn = document.getElementById('toggle-details');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', function () {
                const detailsContent = document.getElementById('details-content');
                if (detailsContent.style.display === 'none') {
                    detailsContent.style.display = 'block';
                    this.textContent = 'Ocultar detalles';
                } else {
                    detailsContent.style.display = 'none';
                    this.textContent = 'Mostrar detalles';
                }
            });
        }
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