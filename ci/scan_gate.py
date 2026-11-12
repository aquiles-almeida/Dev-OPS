"""Fail on scanner errors or high-risk findings; retain original JSON evidence."""
import json
import pathlib
import subprocess
import sys

kind, output, *command = sys.argv[1:]
result = subprocess.run(command, check=False)
report = pathlib.Path(output)
if not report.is_file() or not report.stat().st_size:
    raise SystemExit('Scanner did not generate a report.')
data = json.loads(report.read_text())
if kind == 'zap':
    # Full scan: 2 denotes alerts at WARN level, not a scanner failure.
    if result.returncode not in (0, 2):
        raise SystemExit(f'ZAP failed: {result.returncode}')
    sites = data.get('site', [])
    if not sites:
        raise SystemExit('ZAP report has no target site.')
    high = [alert for site in sites for alert in site.get('alerts', []) if int(alert['riskcode']) >= 3]
    print(f'ZAP: {len(high)} high-risk alerts')
    raise SystemExit(1 if high else 0)
raise SystemExit(f'Unsupported scanner: {kind}')
