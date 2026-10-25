#!/usr/bin/env python3
"""Start the AssetVault dashboard: python bin/dashboard.py (uses $ASSETVAULT_PASSPHRASE, optional $ASSETVAULT_ROOT)."""
import os, sys, runpy
runpy.run_path(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "app.py"), run_name="__main__")
