"""Enable ``python -m ranbval_sdk.cli`` (the installed ``ranbval`` script uses ``cli:main``)."""

import sys

from ranbval_sdk.cli import main

if __name__ == "__main__":
    sys.exit(main())
