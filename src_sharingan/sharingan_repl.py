#!/usr/bin/env python
from view.console import InteractiveConsole
import sys
import os

# Adds src_sharingan to path so imports work correctly
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == '__main__':
    console = InteractiveConsole()
    console.run()
