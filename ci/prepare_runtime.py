"""Create ephemeral test credentials outside the git working tree."""
import hashlib
import os
from pathlib import Path
import secrets
import sys


def runtime_values():
    password = secrets.token_urlsafe(32)
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=32768, r=8,
                            p=1, maxmem=64*1024*1024).hex()
    username = 'qa-' + secrets.token_hex(6)
    return {'APP_SECRET':secrets.token_hex(48), 'ADMIN_USERNAME':username,
            'ADMIN_PASSWORD_HASH':f'scrypt:32768:8:1${salt}${digest}',
            'GS_ZAP_USERNAME':username, 'GS_ZAP_PASSWORD':password}


def write_runtime(destination):
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        for key,value in runtime_values().items():
            stream.write(key+'='+value+'\n')


if __name__ == '__main__':
    write_runtime(Path(sys.argv[1]))
