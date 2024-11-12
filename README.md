# MICROSERVICIO_VIRUSTOTAL

## Servicio de Análisis de URLs con VirusTotal

Este servicio en Flask permite analizar URLs utilizando la API de VirusTotal para determinar si una URL es maliciosa o no.

## Requisitos

- Python 3.9 o superior
- Una cuenta en [VirusTotal](https://www.virustotal.com/) para obtener una API Key
- Librerías especificadas en el archivo `requirements.txt`

## Instalación

1. Clona el repositorio y navega al directorio del proyecto.
   
   ```bash
   git clone <URL_DEL_REPOSITORIO>
   cd <NOMBRE_DEL_REPOSITORIO>
   ```

2. Instala las dependencias:

   ```bash
   pip install -r requirements.txt
   ```

3. Crea un archivo `.env` en el directorio raíz del proyecto y añade tu API Key de VirusTotal:

   ```plaintext
   API_KEY=tu_api_key_de_virustotal
   ```

## Uso

1. Ejecuta el servidor Flask:

   ```bash
   python app.py
   ```

   

## Endpoints

### Análisis de URL

- **URL:** `/analyze-url`
- **Método:** `POST`
- **Descripción:** Analiza la URL proporcionada y devuelve un informe indicando si es maliciosa o no.

#### Parámetros de entrada:

- `url` (en JSON): URL a analizar.

#### Ejemplo de solicitud:

   ```json
   POST /analyze-url
   {
       "url": "http://example.com"
   }
   ```

#### Ejemplo de respuesta:

   ```json
   {
       "overall_result": "POSITIVO: ES MALICIOSO"
   }
   ```

### Verificación de Conexión

- **URL:** `/ping`
- **Método:** `GET`
- **Descripción:** Verifica que el servidor esté funcionando correctamente.

#### Ejemplo de respuesta:

   ```json
   {
       "message": "pong"
   }
   ```

## Pruebas

Este proyecto incluye pruebas unitarias y de integración que pueden ejecutarse con `pytest`.

### Ejecutar Pruebas

1. Asegúrate de que las dependencias para las pruebas están instaladas. Puedes instalar `pytest` ejecutando:

   ```bash
   pip install pytest pytest-asyncio requests-mock
   ```

2. Ejecuta las pruebas usando `pytest`:

   ```bash
   pytest test/API_test.py
   pytest test/unit_test.py
   ```

   Los resultados de las pruebas mostrarán si cada prueba pasó o falló. Aquí tienes un ejemplo de salida de las pruebas:

#### Prueba de API (`API_test.py`)

![Resultado Prueba de API](test/Resultado%20prueba%20de%20API.png)

#### Prueba Unitaria (`unit_test.py`)

![Resultado Prueba Unitaria](test/Resultado%20prueba%20unitaria.png)

## Notas

La configuración predeterminada para las pruebas asíncronas en `pytest-asyncio` está configurada para funcionar en el alcance de la función. Si es necesario, ajusta `asyncio_default_fixture_loop_scope` para evitar advertencias en futuras versiones.

## Despliegue en Render
Este servicio está desplegado en Render. Al realizar una solicitud a cualquiera de los endpoints documentados, asegúrate de usar la URL de despliegue proporcionada por Render.

La API está disponible en: https://smishguard-virustotal-ms.onrender.com.

## Licencia

Este proyecto está licenciado bajo la MIT License.