#!/usr/bin/env python3
"""Final UHCON Deadband solver entry point.

The implementation lives in root_deadband_cdata_manifest_chain.py so the
captured E1-E5 exchange artifacts and the reusable solver execute identical
code.
"""

from root_deadband_cdata_manifest_chain import main


if __name__ == "__main__":
    main()
