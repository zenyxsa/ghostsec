import unittest

from agents import OSINTAgent, ReconAgent, ReportAgent, VulnerabilityAgent
from ai_core.orchestrator import GhostSecOrchestrator, OrchestrationError
from ai_core.tools import ToolContext, ToolError, ToolRegistry, ToolSpec


class FakeClient:
    def __init__(self, response):
        self.response = response

    def chat(self, messages):
        return self.response


class ToolRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = ToolRegistry()
        self.calls = []
        self.registry.register(ToolSpec(
            name="inventory",
            description="Read a test asset inventory.",
            handler=lambda target: self.calls.append(target) or {"target": target},
            required_args=("target",),
            allowed_args=("target",),
        ))

    def test_requires_confirmation_and_authorized_scope(self):
        with self.assertRaises(ToolError):
            self.registry.execute("inventory", {"target": "lab.local"})
        with self.assertRaises(ToolError):
            self.registry.execute(
                "inventory", {"target": "other.local"},
                ToolContext(authorized_targets=("lab.local",), user_confirmed=True),
            )
        result = self.registry.execute(
            "inventory", {"target": "lab.local"},
            ToolContext(authorized_targets=("lab.local",), user_confirmed=True),
        )
        self.assertEqual(result, {"target": "lab.local"})
        self.assertEqual(self.calls, ["lab.local"])

    def test_rejects_unknown_and_extra_arguments(self):
        with self.assertRaises(ToolError):
            self.registry.execute("shell", {"command": "id"}, ToolContext(user_confirmed=True))
        with self.assertRaises(ToolError):
            self.registry.execute(
                "inventory", {"target": "lab.local", "command": "id"},
                ToolContext(authorized_targets=("lab.local",), user_confirmed=True),
            )


class OrchestratorTests(unittest.TestCase):
    def test_validates_model_plan_without_executing(self):
        registry = ToolRegistry()
        registry.register(ToolSpec(
            name="inventory", description="inventory", handler=lambda target: target,
            required_args=("target",), allowed_args=("target",),
        ))
        client = FakeClient('{"summary":"Review lab asset","actions":[{"tool":"inventory","arguments":{"target":"lab.local"}}]}')
        orchestrator = GhostSecOrchestrator(client=client, registry=registry)
        plan = orchestrator.plan("Review lab.local")
        self.assertEqual(plan["actions"][0]["tool"], "inventory")

    def test_rejects_unregistered_tool(self):
        client = FakeClient('{"summary":"bad","actions":[{"tool":"shell","arguments":{"command":"id"}}]}')
        with self.assertRaises(OrchestrationError):
            GhostSecOrchestrator(client=client).plan("run something")

    def test_agents_expose_distinct_prompts(self):
        agents = [ReconAgent(), VulnerabilityAgent(), OSINTAgent(), ReportAgent()]
        prompts = [agent.system_prompt() for agent in agents]
        self.assertEqual(len(set(prompts)), 4)
        self.assertTrue(all("explicitly authorized" in prompt for prompt in prompts))


if __name__ == "__main__":
    unittest.main()
