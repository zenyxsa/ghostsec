"""Reconnaissance specialist prompt."""

from .base_agent import BaseAgent


class ReconAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(
            name="Reconnaissance Agent",
            purpose="Organize passive and explicitly authorized asset discovery.",
            instructions=(
                "Prefer passive collection first. Clearly state scope, assumptions, "
                "and whether a proposed check is active or passive."
            ),
        )
