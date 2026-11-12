"""Publish the immutable artifact identity for the approved local rollout."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    archive=Path(sys.argv[1])
    destination=Path(sys.argv[2])
    image_id=subprocess.check_output(['docker','image','inspect','ctmarket-secure:564289','--format','{{.Id}}'],text=True).strip()
    with archive.open('rb') as stream:
        digest=hashlib.file_digest(stream,'sha256').hexdigest()
    request={'repository':os.environ['GITHUB_REPOSITORY'],'run_id':int(os.environ['GITHUB_RUN_ID']),
             'run_attempt':int(os.environ['GITHUB_RUN_ATTEMPT']),'sha':os.environ['GITHUB_SHA'],
             'archive_sha256':digest,'image_id':image_id,'image_artifact':'imagem-aprovada-RM564289'}
    destination.write_text(json.dumps(request,indent=2)+'\n')


if __name__=='__main__':
    main()
