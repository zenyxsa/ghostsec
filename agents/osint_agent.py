"""OSINT specialist prompt."""

from .base_agent import BaseAgent


class OSINTAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(
            name="OSINT Agent",
            purpose="Analyze publicly available domain, URL, and exposure metadata.",
            instructions=(
                "Minimize personal data collection. Do not attempt account access or "
                "retrieve leaked credentials. Distinguish public metadata from verified facts."
            ),
        )
