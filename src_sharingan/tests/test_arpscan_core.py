import importlib
import sys


def test_importing_arpscan_core_does_not_run_a_scan(monkeypatch):
    """Importing core.arpscan_core must not trigger a real ARP scan.

    Before the fix, the module ran `ArpScan.arp_scan(sys.argv[1], sys.argv[2])`
    at module level, so any import (including in tests) tried to run a real
    scan using the current process's sys.argv.
    """
    monkeypatch.setattr(sys, 'argv', ['pytest'])
    sys.modules.pop('core.arpscan_core', None)

    module = importlib.import_module('core.arpscan_core')

    assert hasattr(module, 'ArpScan')
