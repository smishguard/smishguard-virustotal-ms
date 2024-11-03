import unittest
import requests_mock
from app import app

class VirusTotalIntegrationTest(unittest.TestCase):

    def setUp(self):
        # Configurar el cliente de prueba para el servicio Flask
        self.app = app.test_client()
        self.app.testing = True

    @requests_mock.Mocker()
    def test_full_integration_positive_url(self, mock_request):
        # Simular la respuesta de análisis de URL de VirusTotal
        mock_request.post("https://www.virustotal.com/vtapi/v2/url/scan", json={"scan_id": "12345"})
        
        # Simular la respuesta de reporte de VirusTotal como positivo (malicioso)
        mock_request.get("https://www.virustotal.com/vtapi/v2/url/report", json={
            "scans": {
                "ScannerA": {"detected": True},
                "ScannerB": {"detected": False}
            }
        })

        # Hacer una solicitud POST al endpoint /analyze-url
        response = self.app.post('/analyze-url', json={"url": "http://example.com"})

        # Comprobaciones de integración
        self.assertEqual(response.status_code, 200)
        self.assertIn("POSITIVO: ES MALICIOSO", response.json["overall_result"])

    @requests_mock.Mocker()
    def test_full_integration_negative_url(self, mock_request):
        # Simular la respuesta de análisis de URL de VirusTotal
        mock_request.post("https://www.virustotal.com/vtapi/v2/url/scan", json={"scan_id": "12345"})
        
        # Simular la respuesta de reporte de VirusTotal como negativo (no malicioso)
        mock_request.get("https://www.virustotal.com/vtapi/v2/url/report", json={
            "scans": {
                "ScannerA": {"detected": False},
                "ScannerB": {"detected": False}
            }
        })

        # Hacer una solicitud POST al endpoint /analyze-url
        response = self.app.post('/analyze-url', json={"url": "http://example.com"})

        # Comprobaciones de integración
        self.assertEqual(response.status_code, 200)
        self.assertIn("NEGATIVO: NO ES MALICIOSO", response.json["overall_result"])

    @requests_mock.Mocker()
    def test_full_integration_missing_url_error(self, mock_request):
        # Hacer una solicitud POST sin proporcionar la URL
        response = self.app.post('/analyze-url', json={})

        # Comprobaciones de integración para el caso de error
        self.assertEqual(response.status_code, 400)
        self.assertIn("No URL provided", response.json["error"])

    @requests_mock.Mocker()
    def test_full_integration_error_from_virustotal(self, mock_request):
        # Simular una respuesta de error desde VirusTotal (por ejemplo, API Key inválida)
        mock_request.post("https://www.virustotal.com/vtapi/v2/url/scan", json={"error": "API key invalid"})

        # Hacer una solicitud POST al endpoint /analyze-url
        response = self.app.post('/analyze-url', json={"url": "http://example.com"})

        # Comprobaciones de integración para el caso de error en VirusTotal
        self.assertEqual(response.status_code, 400)
        self.assertIn("API key invalid", response.json["error"])

    @requests_mock.Mocker()
    def test_ping_endpoint(self, mock_request):
        # Prueba de integración para el endpoint de ping
        response = self.app.get('/ping')
        self.assertEqual(response.status_code, 200)
        self.assertIn("pong", response.json["message"])

if __name__ == '__main__':
    unittest.main()
