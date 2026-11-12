"""Scan both complete git history and working tree and fail for any finding."""
import pathlib
import subprocess

pathlib.Path('reports').mkdir(exist_ok=True)
codes=[]
for source,arguments in [('git',['git','--log-opts=--all']),('tree',['dir'])]:
    output=f'reports/segredos-{source}.json'
    result=subprocess.run(['gitleaks',*arguments,'--config','ci/gitleaks.toml','--report-format','json',
                           '--report-path',output,'--redact=100','.'],check=False)
    codes.append(result.returncode)
    if not pathlib.Path(output).is_file():
        raise SystemExit('Missing secrets report')
raise SystemExit(1 if any(codes) else 0)
