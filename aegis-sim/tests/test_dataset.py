import unittest

from aegis_sim.dataset import build_campaign_plan
from aegis_sim.scenarios import ATTACK_SCENARIOS


class CampaignPlanTests(unittest.TestCase):
    def test_plan_alternates_normal_and_attack_windows(self):
        plan = build_campaign_plan(
            total_seconds=3600,
            normal_share=0.8,
            attack_burst_s=120,
            seed=1,
        )
        labels = [window.label for window in plan]
        self.assertEqual(labels[0], "normal")
        self.assertEqual(labels[-1], "normal")
        self.assertEqual(labels.count("normal"), labels.count("attack") + 1)

    def test_plan_uses_only_known_attack_scenarios(self):
        plan = build_campaign_plan(
            total_seconds=1800,
            normal_share=0.7,
            attack_burst_s=60,
            seed=2,
        )
        attack_scenarios = {window.scenario for window in plan if window.label == "attack"}
        self.assertTrue(attack_scenarios.issubset(set(ATTACK_SCENARIOS)))

    def test_plan_duration_sums_to_total(self):
        total_seconds = 2400
        plan = build_campaign_plan(
            total_seconds=total_seconds,
            normal_share=0.75,
            attack_burst_s=90,
            seed=3,
        )
        self.assertAlmostEqual(
            sum(window.duration_s for window in plan), total_seconds, places=6
        )

    def test_plan_is_deterministic_for_a_given_seed(self):
        first = build_campaign_plan(
            total_seconds=1200, normal_share=0.6, attack_burst_s=30, seed=42
        )
        second = build_campaign_plan(
            total_seconds=1200, normal_share=0.6, attack_burst_s=30, seed=42
        )
        self.assertEqual(first, second)

    def test_rejects_invalid_normal_share(self):
        with self.assertRaises(ValueError):
            build_campaign_plan(total_seconds=100, normal_share=1.5, attack_burst_s=10)


if __name__ == "__main__":
    unittest.main()
