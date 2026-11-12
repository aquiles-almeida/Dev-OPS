"""Install pinned CLI archives after SHA256 verification."""
import hashlib
import json
import os
import pathlib
import tarfile
import tempfile
import urllib.request

versions=json.loads((pathlib.Path(__file__).parent/'tools.json').read_text())
destination=pathlib.Path(os.environ.get('RUNNER_TEMP', '/tmp'))/'gs-bin'
destination.mkdir(exist_ok=True)
for name,tool in versions.items():
    with tempfile.TemporaryDirectory() as directory:
        archive=pathlib.Path(directory)/'tool.tar.gz'
        urllib.request.urlretrieve(tool['url'],archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest()!=tool['sha256']:
            raise SystemExit(f'Invalid checksum for {name}')
        with tarfile.open(archive) as stream:
            member=next(m for m in stream.getmembers() if m.name==name)
            (destination/name).write_bytes(stream.extractfile(member).read())
        (destination/name).chmod(0o755)
if os.environ.get('GITHUB_PATH'):
    with open(os.environ['GITHUB_PATH'],'a') as stream:
        stream.write(str(destination)+'\n')
print(destination)
