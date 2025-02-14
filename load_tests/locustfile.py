from locust import HttpUser, task

class WebsiteUser(HttpUser):
    host = "http://localhost:8080"

    @task
    def load_test(self):
        self.client.get("/")
