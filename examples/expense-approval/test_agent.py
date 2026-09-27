import unittest
from pathlib import Path

from agent import load_skill, permitted_action


class ExpenseAgentTests(unittest.TestCase):
    def test_generated_skill_identifies_installed_policy(self):
        skill = Path(__file__).parent / "skill" / "juardrails-expense-demo-expense-approval"
        namespace, policy_id, instructions, snapshot = load_skill(skill)
        self.assertEqual((namespace, policy_id), ("expense-demo", "expense-approval"))
        self.assertIn("decision` is exactly `allow", instructions)
        self.assertIn("delegated_limit", snapshot)

    def test_only_explicit_allow_and_approval_proposal_can_approve(self):
        for decision in ("block", "review", "error", None):
            with self.subTest(decision=decision):
                self.assertEqual(permitted_action({"action": "approve"}, {"decision": decision}), "send_to_human_review")
        self.assertEqual(permitted_action({"action": "escalate"}, {"decision": "allow"}), "send_to_human_review")
        self.assertEqual(permitted_action({"action": "approve"}, {"decision": "allow"}), "approve_in_simulation")


if __name__ == "__main__":
    unittest.main()
