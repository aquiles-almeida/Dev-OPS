"""Regression checks for ephemeral scanner authentication and local rollout."""
from werkzeug.security import check_password_hash

from ci.prepare_runtime import runtime_values, write_runtime
from ci.deploy_wsl import validate_run
import pytest
import hashlib
import io
import zipfile


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
