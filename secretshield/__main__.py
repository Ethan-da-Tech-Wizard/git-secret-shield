"""
Program: Git Secret Shield - Package Executable Main Entry Point
Programmer: Ethan Kilmer
Last Modified: 11/08/2026
Purpose: Enable direct execution of the SecretShield module via 'python3 -m secretshield', dispatching CLI commands and returning POSIX-compliant status codes.
"""

from __future__ import annotations

## ---------------------------------------------------------------------------
## Standard Library Imports
## ---------------------------------------------------------------------------
## sys: Access system-specific parameters and exit function to propagate return codes
import sys

## ---------------------------------------------------------------------------
## Internal Imports
## ---------------------------------------------------------------------------
## main: Primary entry-point dispatcher function from the CLI module
from secretshield.cli import main

## ---------------------------------------------------------------------------
## Top-Level Script Environment Execution Guard
## ---------------------------------------------------------------------------
## Ensure main is only invoked when this script is executed directly via python -m
if __name__ == "__main__":
    ## Execute CLI workflow and exit process with the returned integer status code
    ## 0 indicates success / clean scan; 1 indicates findings or failure; 2 indicates usage error
    sys.exit(main())
