import unittest
from unittest.mock import patch

from server_fastapi import main as control


class CallPolicyInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous_state = control.STATE
        control.STATE = control.default_state()
        self.device_id = next(iter(control.STATE["devices"]))

    def tearDown(self) -> None:
        control.STATE = self.previous_state

    def test_migration_repairs_contact_only_policy_and_queues_android_apply(self) -> None:
        state = control.default_state()
        device_id = next(iter(state["devices"]))
        state["devices"][device_id]["policy_version"] = 69
        state["basic_policies"][device_id].update({
            "call_screening_enabled": False,
            "contacts_only_calls": True,
        })
        rows = {row["key"]: row for row in state["settings"][device_id]}
        rows["call_screening_enabled"]["value"] = False
        rows["contacts_only_calls"]["value"] = True

        control.migrate_state(state)

        self.assertTrue(state["basic_policies"][device_id]["call_screening_enabled"])
        self.assertTrue(rows["call_screening_enabled"]["value"])
        self.assertEqual(rows["call_screening_enabled"]["status"], "pending")
        self.assertEqual(state["devices"][device_id]["policy_version"], 70)

    def test_basic_policy_cannot_disable_master_while_contacts_only_is_on(self) -> None:
        with patch.object(control, "save_state"):
            control.update_basic_policy(self.device_id, {
                "call_screening_enabled": False,
                "contacts_only_calls": True,
            }, None)

        policy = control.STATE["basic_policies"][self.device_id]
        self.assertTrue(policy["contacts_only_calls"])
        self.assertTrue(policy["call_screening_enabled"])
        rows = {row["key"]: row for row in control.STATE["settings"][self.device_id]}
        self.assertTrue(rows["call_screening_enabled"]["value"])
        self.assertEqual(rows["call_screening_enabled"]["status"], "pending")

    def test_owner_policy_and_basic_policy_share_call_settings(self) -> None:
        request = control.PolicyUpdate(settings=[
            {"key": "call_screening_enabled", "value": False},
            {"key": "contacts_only_calls", "value": True},
        ])
        with patch.object(control, "save_state"):
            control.update_owner_policy(self.device_id, request, None)

        policy = control.STATE["basic_policies"][self.device_id]
        rows = {row["key"]: row for row in control.STATE["settings"][self.device_id]}
        self.assertTrue(policy["contacts_only_calls"])
        self.assertTrue(policy["call_screening_enabled"])
        self.assertTrue(rows["call_screening_enabled"]["value"])
        self.assertTrue(rows["contacts_only_calls"]["value"])


if __name__ == "__main__":
    unittest.main()
