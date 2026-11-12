"""Verify canonical image content across Docker classic and containerd stores."""
import hashlib
import json
import tarfile


def archive_identity(path):
    with tarfile.open(path,'r:*') as archive:
        manifests=json.load(archive.extractfile('manifest.json'))
        if len(manifests)!=1:
            raise ValueError('Expected exactly one saved image.')
        raw=archive.extractfile(manifests[0]['Config']).read()
        config=json.loads(raw)
    return {'config_digest':'sha256:'+hashlib.sha256(raw).hexdigest(),
            'runtime_config':config['config'],'diff_ids':config['rootfs']['diff_ids'],
            'architecture':config['architecture'],'os':config['os']}


def verify_loaded_image(identity, inspected):
    if inspected['RootFS']['Layers']!=identity['diff_ids']:
        raise ValueError('Loaded filesystem layers differ from the approved image.')
    if inspected['Architecture']!=identity['architecture'] or inspected['Os']!=identity['os']:
        raise ValueError('Loaded image platform differs.')
    keys=['Env','Cmd','Entrypoint','WorkingDir','User','ExposedPorts','Volumes','Labels','StopSignal','Shell','OnBuild']
    for key in keys:
        expected=identity['runtime_config'].get(key) or None
        actual=inspected['Config'].get(key) or None
        if actual!=expected:
            raise ValueError('Loaded runtime configuration differs: '+key)
    for key,value in identity['runtime_config'].get('Healthcheck',{}).items():
        if inspected['Config'].get('Healthcheck',{}).get(key)!=value:
            raise ValueError('Loaded healthcheck differs: '+key)
    return inspected['Id']
