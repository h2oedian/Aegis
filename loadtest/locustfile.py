from locust import HttpUser, between, task


class ApiUser(HttpUser):
    """Hits the one endpoint that exists in this repo and passes through
    the full middleware stack -- Aegis protects other people's business
    endpoints (the Marketplace API demo), not itself, so /api/health/ is
    the honest thing to load-test here.
    """

    wait_time = between(0.05, 0.2)

    @task
    def health(self):
        self.client.get("/api/health/", name="/api/health/")
