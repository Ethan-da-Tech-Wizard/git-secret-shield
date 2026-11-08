"""
===============================================================================
SecretShield - Package Main Entry Point
===============================================================================

Enables running SecretShield directly as an executable Python module:
    $ python3 -m secretshield scan
    $ python3 -m secretshield install-hook
    $ python3 -m secretshield redact .env
"""

import sys
from secretshield.cli import main

if __name__ == "__main__":
    sys.exit(main())
