"""Offline real-pip checks: synthetic wheel, actual dependency-step shell guard."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
WORKFLOW=ROOT/'.github/workflows/hosted-reader-acceptance.yml'


def install_step():
    text=WORKFLOW.read_text()
    section=text.split('      - name: Verify and install hash-locked Python dependencies without credentials\n',1)[1]
    block=section.split('        run: |\n',1)[1].split('      - name:',1)[0]
    return '\n'.join(line[10:] for line in block.splitlines())+'\n'


class DependencyIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ogden-hash-fixture-')
        self.root=Path(self.temp.name)
        self.wheels=self.root/'wheels';self.wheels.mkdir()
        self.wheel=self.wheels/'ogden_integrity_fixture-1.0-py3-none-any.whl'
        with zipfile.ZipFile(self.wheel,'w') as z:
            prefix='ogden_integrity_fixture-1.0.dist-info/'
            z.writestr(prefix+'METADATA','Metadata-Version: 2.1\nName: ogden-integrity-fixture\nVersion: 1.0\n')
            z.writestr(prefix+'WHEEL','Wheel-Version: 1.0\nGenerator: synthetic-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
            z.writestr(prefix+'RECORD','')
        self.sha=hashlib.sha256(self.wheel.read_bytes()).hexdigest()
        self.env={k:os.environ[k] for k in ('PATH','HOME','LANG') if k in os.environ}
        self.env.update(RUNNER_TEMP=str(self.root),GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',PIP_CONFIG_FILE=os.devnull)
        (self.root/'control').mkdir()
    def tearDown(self):self.temp.cleanup()
    def stage(self,sha):
        (self.root/'control/requirements-reader.txt').write_text('ogden-integrity-fixture==1.0 --hash=sha256:'+sha+'\n')
        step=install_step().replace('python3.12',shlex.quote(sys.executable)).replace('--index-url https://pypi.org/simple','--no-index --find-links '+shlex.quote(str(self.wheels)))
        marker=self.root/'synthetic-credential-phase'
        # The runner's success dependency is modeled with set -e; no actual secret.
        command='set -e\nbash -c '+shlex.quote(step)+'\nprintf reached > '+shlex.quote(str(marker))
        result=subprocess.run(['bash','-c',command],cwd=self.root,env=self.env,capture_output=True,text=True,timeout=40)
        return result,marker
    def test_incorrect_hash_blocks_credential_phase(self):
        result,marker=self.stage('0'*64)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(marker.exists())
        self.assertIn('Dependency setup failed; no credential step executed.',result.stdout)
    def test_correct_hash_allows_only_synthetic_next_phase(self):
        result,marker=self.stage(self.sha)
        self.assertEqual(result.returncode,0,'Synthetic hash-locked wheel installation should succeed')
        self.assertTrue(marker.exists())
    def test_missing_hash_fails_real_pip(self):
        req=self.root/'missing.txt';req.write_text('ogden-integrity-fixture==1.0\n')
        result=subprocess.run([sys.executable,'-m','pip','install','--dry-run','--ignore-installed','--disable-pip-version-check','--no-index','--find-links',str(self.wheels),'--require-hashes','--only-binary=:all:','-r',str(req)],env=self.env,capture_output=True,text=True,timeout=30)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('hash',result.stderr.lower())
    def test_manifest_and_requirements_are_complete_and_exact(self):
        manifest=json.loads((ROOT/'docs/READER-DEPENDENCY-HASHES.json').read_text())
        pins={}
        for line in (ROOT/'requirements-reader.txt').read_text().splitlines():
            match=re.match(r'^([A-Za-z]+)==([0-9.]+)',line)
            if match:package=match[1];pins[package]={'version':match[2],'hashes':set()}
            match=re.search(r'--hash=sha256:([a-f0-9]{64})',line)
            if match:pins[package]['hashes'].add(match[1])
        self.assertEqual({p:v['version'] for p,v in pins.items()},{'PyJWT':'2.13.0','cryptography':'50.0.0','cffi':'2.1.1','pycparser':'3.0'})
        for package,pin in pins.items():
            distributions=[x for x in manifest['distributions'] if x['package']==package]
            self.assertEqual(pin['hashes'],{x['sha256'] for x in distributions})
            self.assertTrue(distributions)
            for entry in distributions:
                self.assertEqual(entry['version'],pin['version'])
                self.assertTrue(entry['filename'].endswith('.whl'))
                self.assertTrue(entry['url'].startswith('https://files.pythonhosted.org/'))
    def test_workflow_key_scope_and_fail_closed_flags(self):
        text=WORKFLOW.read_text()
        prefix,secret_step=text.split('      - name: Validate Reader and collect sanitized acceptance evidence\n',1)
        self.assertNotIn('secrets.',prefix)
        self.assertNotIn('OGDEN_READER_PRIVATE_KEY',prefix)
        self.assertNotIn('continue-on-error',text)
        self.assertIn('        if: success()',secret_step.split('      - name:',1)[0])
        self.assertIn('python3.12 -m venv',prefix)
        step=install_step()
        for flag in ('--require-hashes','--only-binary=:all:','--no-cache-dir'):
            self.assertIn(flag,step)
        self.assertIn('exit 1',step)
        self.assertEqual(re.findall(r'secrets\.([A-Z_]+)',text),['PROVISIONING_READER_APP_PRIVATE_KEY'])


if __name__=='__main__':unittest.main()
