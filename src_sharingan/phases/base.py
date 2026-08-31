from abc import ABC, abstractmethod


class PhaseModule(ABC):
    """Common interface for the framework's phase modules.

    Inspired by Metasploit's modules: each phase of the pentest methodology
    (recon, scan, vulnerability analysis, ...) implements this interface so
    it can be discovered and run uniformly by the console.

    Subclasses must define `name` and `description` and implement `run`.
    """

    name: str = ''
    description: str = ''

    @abstractmethod
    def run(self, **options):
        """Runs the module with the given options and returns the result."""
        raise NotImplementedError
