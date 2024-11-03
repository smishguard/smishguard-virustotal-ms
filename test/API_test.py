import requests

BASE_URL = "http://localhost:5000"  # Cambia la URL si usas otro puerto o servidor

def test_ping():
    """Prueba el endpoint /ping para verificar que el servicio está activo."""
    response = requests.get(f"{BASE_URL}/ping")
    assert response.status_code == 200
    assert response.json().get("message") == "pong"

def test_analyze_url_positive():
    """Prueba el endpoint /analyze-url con un URL malicioso simulado."""
    # Simular el análisis de una URL maliciosa
    url_data = {"url": "http://malicious.com"}
    response = requests.post(f"{BASE_URL}/analyze-url", json=url_data)
    assert response.status_code == 200
    assert "POSITIVO: ES MALICIOSO" in response.json().get("overall_result")

def test_analyze_url_negative():
    """Prueba el endpoint /analyze-url con un URL no malicioso simulado."""
    # Simular el análisis de una URL no maliciosa
    url_data = {"url": "http://safe.com"}
    response = requests.post(f"{BASE_URL}/analyze-url", json=url_data)
    assert response.status_code == 200
    assert "NEGATIVO: NO ES MALICIOSO" in response.json().get("overall_result")

def test_analyze_url_no_url_provided():
    """Prueba el endpoint /analyze-url cuando no se proporciona una URL."""
    response = requests.post(f"{BASE_URL}/analyze-url", json={})
    assert response.status_code == 400
    assert "No URL provided" in response.json().get("error")

def test_analyze_url_api_key_error():
    """Prueba el endpoint /analyze-url para manejar un error de API Key faltante."""
    # Aquí, podríamos simular que la API Key está ausente o es inválida.
    # Esta prueba puede necesitar configurar una clave inválida en el entorno.
    url_data = {"url": "http://example.com"}
    response = requests.post(f"{BASE_URL}/analyze-url", json=url_data)
    assert response.status_code == 400
    assert "API key" in response.json().get("error")
