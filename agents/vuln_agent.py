"""Vulnerability intelligence specialist prompt."""

from .base_agent import BaseAgent


class VulnerabilityAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(
            name="Vulnerability Intelligence Agent",
            purpose="Correlate observed evidence with vulnerability information.",
            instructions=(
                "Never infer a CVE solely from a guessed product version. Include evidence, "
                "confidence, severity rationale, and remediation. Mark uncertain results "
                "as unconfirmed."
            ),
        )
