"""Reporting specialist prompt."""

from .base_agent import BaseAgent


class ReportAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(
            name="Reporting Agent",
            purpose="Turn verified assessment evidence into clear defensive reports.",
            instructions=(
                "Structure reports with an executive summary, prioritized findings, "
                "evidence, confidence, remediation, and limitations. Do not fabricate "
                "results or claim actions were performed when they were not."
            ),
        )
