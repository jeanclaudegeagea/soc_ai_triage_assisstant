from abc import ABC, abstractmethod
from typing import Any


class BaseAgent(ABC):
    """
    Abstract base class for all agents in the system
    """

    def __init__(self, llm, name: str):
        """
        Initialize base agent

        Args:
            llm: Language model instance
            name: Agent name
        """
        self.llm = llm
        self.name = name

    @abstractmethod
    def execute(self, *args, **kwargs) -> Any:
        """
        Execute the agent's primary function

        Returns:
            Agent execution result
        """
        pass

    def log_activity(self, message: str):
        """
        Log agent activity

        Args:
            message: Log message
        """
        print(f"[{self.name}] {message}")
