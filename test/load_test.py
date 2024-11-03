from locust import HttpUser, TaskSet, task, between

class UserBehavior(TaskSet):
    @task(1)
    def analyze_url(self):
        # Realizar una solicitud POST al endpoint /analyze-url
        # Cambia el "http://example.com" por una URL válida o usa URLs generadas
        self.client.post("/analyze-url", json={"url": "http://example.com"})

    @task(2)
    def ping(self):
        # Realizar una solicitud GET al endpoint /ping para verificar el estado
        self.client.get("/ping")

class WebsiteUser(HttpUser):
    tasks = [UserBehavior]
    # Tiempo de espera entre tareas de un usuario
    wait_time = between(1, 5)
