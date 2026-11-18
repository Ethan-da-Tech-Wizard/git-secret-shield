# ==============================================================================
# Program: __main__.py
# Programmer: Ethan-da-Tech-Wizard
# Last Modified: November 18, 2026
# Purpose: Direct execution entrypoint for Git Secret Shield.
#          Inputs: Command line arguments supplied via sys.argv.
#          Outputs: POSIX-compliant status code propagated upon CLI execution.
#          Design Rationale: Enables direct invocation via `python3 -m secretshield`
#                            conforming to standard Python package CLI execution idioms.
# ==============================================================================

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
