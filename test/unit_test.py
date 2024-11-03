import unittest
from unittest.mock import patch, MagicMock
from app import app, analyze_url, get_report, is_report_positive

class VirusTotalServiceTest(unittest.TestCase):

    def setUp(self):
        # Configurar el cliente de prueba para el servicio Flask
        self.app = app.test_client()
        self.app.testing = True

    @patch('app.analyze_url')
    @patch('app.get_report')
    def test_analyze_and_report_url_positive(self, mock_get_report, mock_analyze_url):
        # Simulación de la respuesta de VirusTotal para un URL positivo (malicioso)
        mock_analyze_url.return_value = {"scan_id": "12345"}
        mock_get_report.return_value = {
            "scans": {
                "ScannerA": {"detected": True},
                "ScannerB": {"detected": False}
            }
        }

        # Realizar la solicitud POST a /analyze-url
        response = self.app.post('/analyze-url', json={"url": "http://example.com"})

        # Comprobaciones
        self.assertEqual(response.status_code, 200)
        self.assertIn("POSITIVO: ES MALICIOSO", response.json["overall_result"])

    @patch('app.analyze_url')
    @patch('app.get_report')
    def test_analyze_and_report_url_negative(self, mock_get_report, mock_analyze_url):
        # Simulación de la respuesta de VirusTotal para un URL negativo (no malicioso)
        mock_analyze_url.return_value = {"scan_id": "12345"}
        mock_get_report.return_value = {
            "scans": {
                "ScannerA": {"detected": False},
                "ScannerB": {"detected": False}
            }
        }

        # Realizar la solicitud POST a /analyze-url
        response = self.app.post('/analyze-url', json={"url": "http://example.com"})

        # Comprobaciones
        self.assertEqual(response.status_code, 200)
        self.assertIn("NEGATIVO: NO ES MALICIOSO", response.json["overall_result"])

    def test_analyze_and_report_url_no_url_provided(self):
        # Realizar la solicitud POST sin URL
        response = self.app.post('/analyze-url', json={})

        # Comprobaciones
        self.assertEqual(response.status_code, 400)
        self.assertIn("No URL provided", response.json["error"])

    @patch('app.analyze_url')
    def test_analyze_url_error_response(self, mock_analyze_url):
        # Simulación de una respuesta de error de la API
        mock_analyze_url.return_value = {"error": "API key missing"}

        # Realizar la solicitud POST a /analyze-url
        response = self.app.post('/analyze-url', json={"url": "http://example.com"})

        # Comprobaciones
        self.assertEqual(response.status_code, 400)
        self.assertIn("API key missing", response.json["error"])

    def test_ping(self):
        # Prueba para el endpoint /ping
        response = self.app.get('/ping')

        # Comprobaciones
        self.assertEqual(response.status_code, 200)
        self.assertIn("pong", response.json["message"])

    @patch('app.is_report_positive')
    def test_is_report_positive_function(self, mock_is_report_positive):
        # Prueba unitaria directa para verificar si la función is_report_positive detecta contenido malicioso
        report_data = {
            "scans": {
                "ScannerA": {"detected": True},
                "ScannerB": {"detected": False}
            }
        }
        # Comprobar que el resultado es positivo
        self.assertTrue(is_report_positive(report_data))

        report_data = {
            "scans": {
                "ScannerA": {"detected": False},
                "ScannerB": {"detected": False}
            }
        }
        # Comprobar que el resultado es negativo
        self.assertFalse(is_report_positive(report_data))

if __name__ == '__main__':
    unittest.main()
