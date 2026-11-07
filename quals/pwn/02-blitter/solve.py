#!/usr/bin/env python3
"""Standard entry point for the verified blitter exploit.

With no arguments this uses the supplied loader, libc, and local challenge
binary.  A network connection is made only when ``--remote HOST:PORT`` is
passed explicitly; all options are implemented by :mod:`exploit`.
"""

from exploit import main


if __name__ == "__main__":
    main()
