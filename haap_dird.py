#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convenience launcher for the HAAP directory (``python haap_dird.py``).

Equivalent to the installed ``haap-dird`` console script. Adds ``src`` to
``sys.path`` so it also works from a source checkout without installation.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from haap_directory.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
