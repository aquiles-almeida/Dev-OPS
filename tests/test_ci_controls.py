"""Regression checks for ephemeral scanner authentication and local rollout."""
from werkzeug.security import check_password_hash

from ci.prepare_runtime import runtime_values, write_runtime
from ci.deploy_wsl import validate_run
import pytest
import hashlib
import io
import zipfile
import tarfile
import json
from ci.image_identity import archive_identity, verify_loaded_image


def test_runtime_password_is_random_and_compatible():
    one,two=runtime_values(),runtime_values()
    assert one['APP_SECRET']!=two['APP_SECRET']
    assert one['GS_ZAP_PASSWORD']!=two['GS_ZAP_PASSWORD']
    assert one['ADMIN_USERNAME']==one['GS_ZAP_USERNAME']
    assert check_password_hash(one['ADMIN_PASSWORD_HASH'],one['GS_ZAP_PASSWORD'])


def test_runtime_file_permissions(tmp_path):
    destination=tmp_path/'test.env'
    write_runtime(destination)
    assert destination.stat().st_mode & 0o777 == 0o600
    assert 'ADMIN_PASSWORD_HASH=' in destination.read_text()


def approved_run():
    commit='a'*40
    run={'head_sha':commit,'head_branch':'main','event':'push',
         'head_repository':{'full_name':'aquiles-almeida/Dev-OPS'},
         'path':'.github/workflows/devsecops-rm564289.yml'}
    jobs=[{'name':f'{n} - Gate','conclusion':'success','status':'completed'} for n in range(1,8)]
    jobs.append({'name':'8 - Deploy no WSL','status':'in_progress','conclusion':None})
    return run,jobs,commit


def test_deploy_requires_exact_approved_run():
    run,jobs,commit=approved_run()
    validate_run(run,jobs,commit)
    with pytest.raises(ValueError):
        validate_run(run,jobs,'b'*40)


@pytest.mark.parametrize('field,value',[('head_branch','feature'),('event','pull_request'),('path','other.yml')])
def test_deploy_rejects_other_workflow_or_event(field,value):
    run,jobs,commit=approved_run()
    run[field]=value
    with pytest.raises(ValueError):
        validate_run(run,jobs,commit)


def test_deploy_rejects_failed_gate_and_unapproved_deploy():
    run,jobs,commit=approved_run()
    jobs[0]['conclusion']='failure'
    with pytest.raises(ValueError):
        validate_run(run,jobs,commit)
    jobs[0]['conclusion']='success'
    jobs[-1]['status']='waiting'
    with pytest.raises(ValueError):
        validate_run(run,jobs,commit)


def test_deploy_artifact_integrity(monkeypatch):
    from ci import deploy_wsl
    output=io.BytesIO()
    with zipfile.ZipFile(output,'w') as archive:
        archive.writestr('request.json','{}')
    data=output.getvalue()
    artifact={'expired':False,'size_in_bytes':len(data),'id':1,
              'digest':'sha256:'+hashlib.sha256(data).hexdigest()}
    monkeypatch.setattr(deploy_wsl,'gh_api',lambda *args,**kwargs:data)
    assert deploy_wsl.read_artifact(artifact,'request.json')==b'{}'
    artifact['digest']='sha256:'+'0'*64
    with pytest.raises(ValueError):
        deploy_wsl.read_artifact(artifact,'request.json')


def test_archive_uses_canonical_configuration_digest(tmp_path):
    config={'config':{'User':'10001:10001'},'rootfs':{'diff_ids':['sha256:'+'a'*64]},'architecture':'amd64','os':'linux'}
    raw=json.dumps(config).encode()
    path=tmp_path/'image.tar'
    with tarfile.open(path,'w') as archive:
        for name,data in [('manifest.json',json.dumps([{'Config':'config.json'}]).encode()),('config.json',raw)]:
            info=tarfile.TarInfo(name)
            info.size=len(data)
            archive.addfile(info,io.BytesIO(data))
    identity=archive_identity(path)
    assert identity['config_digest']=='sha256:'+hashlib.sha256(raw).hexdigest()


def test_loaded_image_identity_rejects_different_content():
    identity={'config_digest':'sha256:'+'a'*64,'runtime_config':{'User':'10001:10001','Cmd':['app']},
              'diff_ids':['sha256:'+'b'*64],'architecture':'amd64','os':'linux'}
    inspected={'Id':'sha256:'+'c'*64,'Config':dict(identity['runtime_config']),
               'RootFS':{'Layers':list(identity['diff_ids'])},'Architecture':'amd64','Os':'linux'}
    assert verify_loaded_image(identity,inspected)==inspected['Id']
    inspected['Config']['User']='root'
    with pytest.raises(ValueError):
        verify_loaded_image(identity,inspected)
    inspected['Config']['User']='10001:10001'
    inspected['RootFS']['Layers']=['sha256:'+'d'*64]
    with pytest.raises(ValueError):
        verify_loaded_image(identity,inspected)
