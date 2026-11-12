"""Create an ephemeral runtime secret outside the git working tree."""
import os
import pathlib
import secrets
import sys

destination = pathlib.Path(sys.argv[1])
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('APP_SECRET=' + secrets.token_hex(48) + '\n')
