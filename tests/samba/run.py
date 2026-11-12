"""Run a disposable, real SMB 3 read/restart test. No real NAS data or credentials."""
import os
from pathlib import Path
import secrets
import subprocess
import uuid

root = Path(__file__).resolve().parent
prefix = 'smb-test-' + uuid.uuid4().hex[:10]
image = os.environ.get('APPLIANCE_TEST_IMAGE', 'visiondoc-smb:prod-arm64')
env = dict(os.environ, FIXTURE_PASSWORD=secrets.token_urlsafe(24))

def run(*args, **kwargs):
    return subprocess.run(['docker', *args], check=True, **kwargs)

try:
    run('build', '-t', prefix, str(root))
    run('network', 'create', prefix)
    run('run', '-d', '--name', prefix, '--network', prefix, '--network-alias', 'fixture', '-e', 'FIXTURE_PASSWORD', prefix, env=env)
    # Wait for Samba to finish account setup, without printing its environment.
    import time
    for _ in range(30):
        probe = subprocess.run(['docker', 'exec', prefix, 'test', '-f', '/run/samba/smbd.pid'], capture_output=True)
        if probe.returncode == 0:
            break
        time.sleep(1)
    for script in ['integration.py', 'restart.py']:
        run('run', '--rm', '--network', prefix, '-e', 'FIXTURE_PASSWORD', '-v', prefix + ':/data',
            '-v', str(root / script) + ':/tmp/test.py:ro', image, 'python', '/tmp/test.py', env=env)
finally:
    for args in [('rm', '-f', prefix), ('network', 'rm', prefix), ('volume', 'rm', prefix), ('image', 'rm', prefix)]:
        subprocess.run(['docker', *args], capture_output=True)
