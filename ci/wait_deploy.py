"""The deployment job succeeds only after the WSL healthcheck is confirmed."""
import json
import os
import subprocess
import time


def api(path):
    return json.loads(subprocess.check_output(['gh','api',path],text=True))


def main():
    repo=os.environ['GITHUB_REPOSITORY']
    run=os.environ['GITHUB_RUN_ID']
    attempt=os.environ['GITHUB_RUN_ATTEMPT']
    sha=os.environ['GITHUB_SHA']
    prefix=f'WSL RM564289 run:{run} attempt:{attempt}'
    deadline=time.monotonic()+12*60
    while time.monotonic()<deadline:
        deployments=api(f'repos/{repo}/deployments?sha={sha}&environment=producao&per_page=30')
        for deployment in deployments:
            statuses=api(f'repos/{repo}/deployments/{deployment["id"]}/statuses?per_page=30')
            for status in statuses:
                if status['creator']['login'].lower()!=repo.split('/')[0].lower():
                    continue
                if status['description']==prefix+': healthy' and status['state']=='success':
                    url=status['environment_url']
                    with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
                        stream.write('environment_url='+url+'\n')
                    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:
                        stream.write(f'Deploy executado no WSL, imagem do commit `{sha}`. Saúde confirmada: {url}\n')
                    print('WSL deployment and healthcheck confirmed.')
                    return
                if status['description']==prefix+': failed' and status['state'] in {'failure','error'}:
                    raise SystemExit('The WSL deployment failed. Check the local deployment evidence.')
        time.sleep(5)
    raise SystemExit('No WSL healthcheck confirmation within 12 minutes.')


if __name__=='__main__':
    main()
