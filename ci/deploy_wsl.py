"""Deploy one explicitly selected, protected GitHub run to this WSL host."""
import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import urlopen
import zipfile

if __package__:
    from .prepare_runtime import runtime_values
else:
    from prepare_runtime import runtime_values

REPOSITORY='aquiles-almeida/Dev-OPS'
WORKFLOW='.github/workflows/devsecops-rm564289.yml'
ROOT=Path('/opt/gs/deploy')
CONTAINER='gs-secure-564289'
DOCKER='/usr/bin/docker'
GH=shutil.which('gh') or '/mnt/c/Program Files/GitHub CLI/gh.exe'


def gh_api(path, body=None, binary=False):
    arguments=[GH,'api',path]
    payload=None
    if body is not None:
        arguments+=['--method','POST','--input','-']
        payload=json.dumps(body).encode()
    result=subprocess.run(arguments,input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    return result.stdout if binary else json.loads(result.stdout)


def docker(*arguments, capture=False):
    result=subprocess.run([DOCKER,*map(str,arguments)],check=True,stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE)
    return result.stdout.decode().strip() if capture else None


def validate_run(run, jobs, expected_sha):
    if not re.fullmatch(r'[0-9a-f]{40}',expected_sha):
        raise ValueError('Invalid expected commit.')
    if run['head_sha']!=expected_sha or run['head_branch']!='main' or run['event']!='push':
        raise ValueError('Only the selected push to main may deploy.')
    if run['head_repository']['full_name'].lower()!=REPOSITORY.lower() or run['path']!=WORKFLOW:
        raise ValueError('Unexpected repository or workflow.')
    for number in range(1,8):
        selected=[j for j in jobs if j['name'].startswith(f'{number} - ')]
        if len(selected)!=1 or selected[0]['conclusion']!='success':
            raise ValueError(f'Security phase {number} has not passed.')
    selected=[j for j in jobs if j['name'].startswith('8 - ')]
    if len(selected)!=1 or selected[0]['status']!='in_progress':
        raise ValueError('The protected deployment job is not running.')


def read_artifact(artifact, filename):
    if artifact['expired'] or artifact['size_in_bytes']>1024*1024*1024:
        raise ValueError('Unavailable or oversized artifact.')
    data=gh_api(f'repos/{REPOSITORY}/actions/artifacts/{artifact["id"]}/zip',binary=True)
    expected=artifact.get('digest','')
    if expected!='sha256:'+hashlib.sha256(data).hexdigest():
        raise ValueError('GitHub artifact digest does not match.')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        info=archive.getinfo(filename)
        if info.file_size>2*1024*1024*1024:
            raise ValueError('Artifact entry is too large.')
        return archive.read(info)


def health(url, timeout=45):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            with urlopen(url,timeout=3) as response:
                if response.status==200 and json.load(response).get('status')=='ok':
                    return
        except (URLError,TimeoutError,OSError,ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('Application healthcheck failed.')


def prepare_host():
    owner=pwd.getpwnam('cib3r')
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    ROOT.chmod(0o700)
    os.chown(ROOT,owner.pw_uid,owner.pw_gid)
    data=ROOT/'data'
    data.mkdir(mode=0o700,exist_ok=True)
    os.chown(data,10001,10001)
    environment=ROOT/'app.env'
    if not environment.exists():
        values=runtime_values()
        values['ADMIN_USERNAME']='aquiles'
        values['LOJA_DB']='/data/market.db'
        fd=os.open(environment,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as stream:
            for key,value in values.items():
                if not key.startswith('GS_ZAP_'):
                    stream.write(key+'='+value+'\n')
        access=ROOT/'acesso-local.txt'
        fd=os.open(access,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as stream:
            stream.write('Usuario: '+values['ADMIN_USERNAME']+'\nSenha: '+values['GS_ZAP_PASSWORD']+'\n')
        os.chown(access,owner.pw_uid,owner.pw_gid)
    os.chown(environment,owner.pw_uid,owner.pw_gid)
    environment.chmod(0o600)


def launch(name, image_id, ports, sha):
    arguments=['run','-d','--name',name,'--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m',
               '--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001',
               '--memory','512m','--cpus','1','--pids-limit','128','--env-file',str(ROOT/'app.env'),
               '--mount',f'type=bind,src={ROOT}/data,dst=/data','--label','org.opencontainers.image.revision='+sha]
    if name==CONTAINER:
        arguments+=['--restart','unless-stopped']
    for port in ports:
        arguments+=['--publish',port]
    docker(*arguments,image_id)


def rollout(image_id, sha, run_id, attempt):
    address=json.loads(subprocess.check_output(['ip','-j','-4','route','get','1.1.1.1'],text=True))[0]['prefsrc']
    if ipaddress.ip_address(address).version!=4:
        raise ValueError('The deployment needs the current WSL IPv4 address.')
    prepare_host()
    candidate=f'{CONTAINER}-candidate-{run_id}-{attempt}'
    backup=f'{CONTAINER}-rollback-{run_id}-{attempt}'
    launch(candidate,image_id,['127.0.0.1::8231'],sha)
    try:
        assigned=docker('port',candidate,'8231/tcp',capture=True)
        port=int(assigned.rsplit(':',1)[1])
        health(f'http://127.0.0.1:{port}/health')
    finally:
        docker('rm','-f',candidate)
    existing=CONTAINER in docker('ps','-a','--format','{{.Names}}',capture=True).splitlines()
    if existing:
        docker('stop',CONTAINER)
        docker('rename',CONTAINER,backup)
    try:
        launch(CONTAINER,image_id,['127.0.0.1:8232:8231',address+':8232:8231'],sha)
        health('http://127.0.0.1:8232/health')
        deadline=time.monotonic()+45
        while docker('inspect',CONTAINER,'--format','{{.State.Health.Status}}',capture=True)!='healthy':
            if time.monotonic()>deadline:
                raise RuntimeError('Container HEALTHCHECK did not pass.')
            time.sleep(1)
    except Exception:
        current=docker('ps','-a','--format','{{.Names}}',capture=True).splitlines()
        if CONTAINER in current:
            docker('rm','-f',CONTAINER)
        if existing:
            docker('rename',backup,CONTAINER)
            docker('start',CONTAINER)
        raise
    return 'http://'+address+':8232/'


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run',required=True,type=int)
    parser.add_argument('--sha',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0:
        raise SystemExit('Use wsl -d Ubuntu -u root -- python3 ci/deploy_wsl.py ...')
    endpoint=f'repos/{REPOSITORY}/actions/runs/{args.run}'
    deadline=time.monotonic()+15*60
    request=None
    while time.monotonic()<deadline:
        run=gh_api(endpoint)
        if run['head_sha']!=args.sha or run['event']!='push' or run['head_branch']!='main':
            raise SystemExit('Unexpected workflow run.')
        if run['status']=='completed' and run['conclusion']!='success':
            raise SystemExit('The pipeline failed before deployment.')
        artifacts=gh_api(endpoint+'/artifacts?per_page=100')['artifacts']
        selected=[a for a in artifacts if a['name']==f'deploy-request-RM564289-{run["run_attempt"]}']
        if selected:
            jobs=gh_api(endpoint+'/jobs?per_page=100')['jobs']
            validate_run(run,jobs,args.sha)
            request=json.loads(read_artifact(selected[0],'request.json'))
            break
        time.sleep(5)
    if request is None:
        raise SystemExit('No approved deployment request within 15 minutes.')
    attempt=run['run_attempt']
    if (request['repository'].lower()!=REPOSITORY.lower() or request['sha']!=args.sha or
        request['run_id']!=args.run or request['run_attempt']!=attempt):
        raise SystemExit('Deployment request does not match the selected run.')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',request['image_id']):
        raise SystemExit('Invalid immutable image identifier.')
    deployments=gh_api(f'repos/{REPOSITORY}/deployments?sha={args.sha}&environment=producao&per_page=30')
    if not deployments:
        raise SystemExit('Protected deployment record is absent.')
    deployment_id=max(d['id'] for d in deployments)
    prefix=f'WSL RM564289 run:{args.run} attempt:{attempt}'
    status_endpoint=f'repos/{REPOSITORY}/deployments/{deployment_id}/statuses'
    try:
        images=[a for a in artifacts if a['name']=='imagem-aprovada-RM564289']
        if len(images)!=1:
            raise ValueError('Expected one approved image artifact.')
        archive=read_artifact(images[0],'market-image.tar')
        if hashlib.sha256(archive).hexdigest()!=request['archive_sha256']:
            raise ValueError('Approved image archive hash does not match.')
        with tempfile.NamedTemporaryFile(suffix='.tar') as stream:
            stream.write(archive)
            stream.flush()
            docker('load','-i',stream.name)
        inspected=docker('image','inspect','ctmarket-secure:564289','--format','{{.Id}}',capture=True)
        if inspected!=request['image_id']:
            raise ValueError('Loaded image differs from the approved image.')
        url=rollout(request['image_id'],args.sha,args.run,attempt)
        evidence={'repository':REPOSITORY,'run_id':args.run,'run_attempt':attempt,'sha':args.sha,
                  'image_id':request['image_id'],'archive_sha256':request['archive_sha256'],
                  'environment_url':url,'health':'healthy','deployed_at':datetime.now(timezone.utc).isoformat()}
        (ROOT/'deployment.json').write_text(json.dumps(evidence,indent=2)+'\n')
        gh_api(status_endpoint,{'state':'success','description':prefix+': healthy','environment_url':url,
                               'log_url':f'https://github.com/{REPOSITORY}/actions/runs/{args.run}','auto_inactive':False})
        print(json.dumps(evidence,indent=2))
    except Exception:
        gh_api(status_endpoint,{'state':'failure','description':prefix+': failed','auto_inactive':False})
        raise


if __name__=='__main__':
    main()
