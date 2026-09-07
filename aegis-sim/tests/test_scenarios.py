import unittest

from aegis_sim.scenarios import (
    brute_force,
    id_enumeration,
    injection_probes,
    product_scrape,
)


class ScenarioTests(unittest.TestCase):
    def test_brute_force_changes_password_each_attempt(self):
        requests = brute_force("target", "guess-")
        first = next(requests)
        second = next(requests)
        self.assertEqual(first.path, "/api/auth/login/")
        self.assertEqual(first.json["password"], "guess-1")
        self.assertEqual(second.json["password"], "guess-2")

    def test_scraper_increments_pages(self):
        requests = product_scrape()
        self.assertEqual(next(requests).params, {"page": "1"})
        self.assertEqual(next(requests).params, {"page": "2"})

    def test_id_enumeration_increments_ids_and_adds_token(self):
        requests = id_enumeration(7, "access-token")
        first = next(requests)
        second = next(requests)
        self.assertEqual(first.path, "/api/orders/7/")
        self.assertEqual(second.path, "/api/orders/8/")
        self.assertEqual(first.headers, {"Authorization": "Bearer access-token"})

    def test_injection_probes_cycle_payloads(self):
        requests = injection_probes()
        payloads = [next(requests).params["search"] for _ in range(5)]
        self.assertEqual(payloads[0], payloads[4])
        self.assertTrue(any("script" in payload for payload in payloads))
        self.assertTrue(any("UNION" in payload for payload in payloads))


if __name__ == "__main__":
    unittest.main()

