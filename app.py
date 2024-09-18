from flask import Flask, request, jsonify
import requests
from dotenv import load_dotenv
import os

# Cargar las variables de entorno del archivo .env
load_dotenv()

# Obtener la API Key desde las variables de entorno
API_KEY = os.getenv('API_KEY')

app = Flask(__name__)

def analyze_url(url):
    base_url = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {'apikey': API_KEY, 'url': url}
    response = requests.post(base_url, data=params)
    return response.json()

def get_report(url):
    base_url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': API_KEY, 'resource': url, 'scan': 1}
    response = requests.get(base_url, params=params)
    return response.json()

def is_report_positive(report):
    scans = report.get('scans', {})
    for scan_result in scans.values():
        if scan_result['detected']:
            return True
    return False

@app.route('/analyze-url', methods=['POST'])
def analyze_and_report_url():
    url = request.json.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # Analizar el URL
    analysis_result = analyze_url(url)
    
    if 'error' in analysis_result:
        return jsonify({"error": analysis_result['error']}), 400

    # Obtener el reporte del análisis
    report = get_report(url)

    # Verificar si el reporte es positivo o negativo
    overall_result = "POSITIVO: ES MALICIOSO" if is_report_positive(report) else "NEGATIVO: NO ES MALICIOSO"

    return jsonify({"overall_result": overall_result})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
