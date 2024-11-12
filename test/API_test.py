import requests
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, analyze_url, get_report, is_report_positive

BASE_URL = "https://smishguard-virustotal-ms.onrender.com"  # Cambia la URL si usas otro puerto o servidor

def test_ping():
    """Prueba el endpoint /ping para verificar que el servicio está activo."""
    response = requests.get(f"{BASE_URL}/ping")
    assert response.status_code == 200
    assert response.json().get("message") == "pong"

def test_analyze_url_positive():
    """Prueba el endpoint /analyze-url con un URL malicioso simulado."""
    # Simular el análisis de una URL maliciosa
    url_data = {"url": "http://www.malicious.com/"}
    response = requests.post(f"{BASE_URL}/analyze-url", json=url_data)
    assert response.status_code == 200
    assert "POSITIVO: ES MALICIOSO" in response.json().get("overall_result")

def test_analyze_url_negative():
    """Prueba el endpoint /analyze-url con un URL no malicioso simulado."""
    # Simular el análisis de una URL no maliciosa
    url_data = {"url": "http://www.google.com"}
    response = requests.post(f"{BASE_URL}/analyze-url", json=url_data)
    assert response.status_code == 200
    assert "NEGATIVO: NO ES MALICIOSO" in response.json().get("overall_result")

def test_analyze_url_no_url_provided():
    """Prueba el endpoint /analyze-url cuando no se proporciona una URL."""
    response = requests.post(f"{BASE_URL}/analyze-url", json={})
    assert response.status_code == 400
    assert "No URL provided" in response.json().get("error")


