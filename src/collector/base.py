from abc import ABC, abstractmethod


class BaseCollector(ABC):
    name: str = "base"

    @abstractmethod
    def start(self):
        ...

    @abstractmethod
    def stop(self):
        ...
