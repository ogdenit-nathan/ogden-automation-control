"""Public controller: narrow source bootstrap, then the reviewed private CLI.

Never prints raw exceptions, child output, private reports, keys, JWTs or tokens.
No repository mutation routes exist in this bootstrap. No Apply command exists.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request

SOURCE = 'ogdenit-nathan/ogden-repository-automation'
SOURCE_ID = 1460409730
SOURCE_SHA = 'a5b7963071dcf48984c26a3b956202947ddc930e'
SOURCE_TREE = '4edfad3cf866f42b2ec848eeafefeba85d8907c8'
TARGET = 'ogdenit-nathan/ogden-toolkit-releases'
TARGET_ID = 1460330267
APP_ID, INSTALLATION_ID = 5789924, 182698516
APP_NAME = 'Ogden Repo Provisioning Reader'
READ = {p: 'read' for p in ('administration','contents','issues','pull_requests','metadata')}
FETCH_PERMISSIONS = {'contents': 'read', 'metadata': 'read'}
REPOS = {SOURCE: SOURCE_ID, TARGET: TARGET_ID}
CONFIG = 'examples/toolkit-public.json'
AUTH = 'examples/auth/provisioning-reader.json'


class Stop(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Stop('BOOTSTRAP_FAILED')


class HTTP:
    def request(self, method, path, bearer, body=None):
        # Closed routes and verbs; writes can only mint/revoke this App's tokens.
        allowed = (method == 'GET' and (path in ('/app', f'/app/installations/{INSTALLATION_ID}',
                     '/installation/repositories?per_page=100') or
                     re.fullmatch('/repos/'+re.escape(SOURCE)+r'/git/(?:commits|trees|blobs)/[a-f0-9]{40}(?:\?recursive=1)?',path)))
        allowed = allowed or (method,path) in (
            ('POST',f'/app/installations/{INSTALLATION_ID}/access_tokens'),
            ('DELETE','/installation/token'))
        if not allowed or not isinstance(bearer,str) or not bearer or any(ord(c)<33 or ord(c)>126 for c in bearer):
            raise Stop('BOOTSTRAP_FAILED')
        try:
            request=urllib.request.Request('https://api.github.com'+path,
                data=json.dumps(body).encode() if body is not None else None,
                headers={'Authorization':'Bearer '+bearer,'Accept':'application/vnd.github+json',
                         'X-GitHub-Api-Version':'2022-11-28','User-Agent':'Ogden-Reader-Acceptance'},method=method)
            with urllib.request.build_opener(NoRedirect()).open(request,timeout=20) as response:
                raw=response.read(2_000_001)
                if len(raw)>2_000_000:raise Stop('BOOTSTRAP_FAILED')
                return json.loads(raw) if raw else None
        except Exception:
            raise Stop('BOOTSTRAP_FAILED') from None


def demand(condition, code='REPORT_INVALID'):
    if not condition:raise Stop(code)


def token_text(value):
    return isinstance(value,str) and bool(value) and all(33<=ord(c)<=126 for c in value)


class Bootstrap:
    """Bootstrap only: fetch this reviewed source with a one-repository read token.
    Normal authentication/Plan/Verify use the private implementation, unchanged.
    """
    def __init__(self, key_path, http=None):
        self.key_path=key_path
        self.http=http or HTTP()
        self.token=None

    def open(self):
        import jwt
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        key=serialization.load_pem_private_key(self.key_path.read_bytes(),password=None)
        demand(isinstance(key,rsa.RSAPrivateKey) and key.key_size>=2048,'BOOTSTRAP_FAILED')
        now=int(time.time())
        credential=jwt.encode({'iss':str(APP_ID),'iat':now-60,'exp':now+540},key,algorithm='RS256')
        app=self.http.request('GET','/app',credential)
        demand(app.get('id')==APP_ID and app.get('name')==APP_NAME and app.get('owner',{}).get('login')=='ogdenit-nathan','BOOTSTRAP_FAILED')
        installation=self.http.request('GET',f'/app/installations/{INSTALLATION_ID}',credential)
        demand(installation.get('id')==INSTALLATION_ID and installation.get('app_id')==APP_ID and
               installation.get('account',{}).get('login')=='ogdenit-nathan' and
               'suspended_at' in installation and installation['suspended_at'] is None and
               installation.get('repository_selection')=='selected' and installation.get('permissions')==READ,'BOOTSTRAP_FAILED')
        result=self.http.request('POST',f'/app/installations/{INSTALLATION_ID}/access_tokens',credential,
            {'repository_ids':[SOURCE_ID],'permissions':FETCH_PERMISSIONS})
        demand(token_text(result.get('token')),'BOOTSTRAP_FAILED')
        self.token=result['token'] # Track before validation, so failures still revoke it.
        from datetime import datetime
        expiry=datetime.fromisoformat(result['expires_at'].replace('Z','+00:00')).timestamp()
        demand(now+120<expiry<=now+3700 and result.get('permissions')==FETCH_PERMISSIONS and
               result.get('repository_selection')=='selected','BOOTSTRAP_FAILED')
        repos=self.get('/installation/repositories?per_page=100')
        demand(repos.get('total_count')==1 and
               [(r.get('full_name'),r.get('id')) for r in repos.get('repositories',[])]==[(SOURCE,SOURCE_ID)],'BOOTSTRAP_FAILED')
        return self

    def get(self,path):
        demand(self.token is not None,'BOOTSTRAP_FAILED')
        return self.http.request('GET',path,self.token)

    def close(self):
        token,self.token=self.token,None
        if token is not None:
            self.http.request('DELETE','/installation/token',token)

    def fetch(self, destination):
        commit=self.get(f'/repos/{SOURCE}/git/commits/{SOURCE_SHA}')
        demand(commit.get('sha')==SOURCE_SHA and commit.get('tree',{}).get('sha')==SOURCE_TREE,'SOURCE_INVALID')
        tree=self.get(f'/repos/{SOURCE}/git/trees/{SOURCE_TREE}?recursive=1')
        demand(tree.get('sha')==SOURCE_TREE and tree.get('truncated') is False,'SOURCE_INVALID')
        files={}
        for item in tree.get('tree',[]):
            path=item.get('path','')
            if re.fullmatch(r'ogden_provision/[A-Za-z_][A-Za-z_0-9]*\.py',path) or path in (CONFIG,AUTH):
                demand(path not in files and item.get('type')=='blob' and item.get('mode')=='100644' and
                       re.fullmatch('[a-f0-9]{40}',item.get('sha','')),'SOURCE_INVALID')
                files[path]=item['sha']
        demand(CONFIG in files and AUTH in files and 'ogden_provision/__main__.py' in files and 5<=len(files)<=40,'SOURCE_INVALID')
        for path,sha in sorted(files.items()):
            blob=self.get(f'/repos/{SOURCE}/git/blobs/{sha}')
            demand(blob.get('sha')==sha and blob.get('encoding')=='base64','SOURCE_INVALID')
            data=base64.b64decode(blob['content'],validate=False)
            demand(len(data)<=200000 and blob.get('size')==len(data) and
                   hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==sha,'SOURCE_INVALID')
            target=destination/path
            target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with target.open('xb') as stream:stream.write(data)
        # All engine Python files are fetched verbatim: preserve the engine digest.


def child_env(key):
    env={name:os.environ[name] for name in ('PATH','HOME','LANG','LC_ALL','SSL_CERT_FILE','SSL_CERT_DIR') if name in os.environ}
    env.update(OGDEN_READER_KEY_FILE=str(key),OGDEN_CREDENTIAL_PURPOSE='provisioning')
    return env


def run_child(args,source,key):
    # stdout/stderr stay private and are never returned or printed, even on failure.
    result=subprocess.run([sys.executable,*args],cwd=source,env=child_env(key),
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=180,check=False)
    return result.returncode


GUARD = """
import json
from ogden_provision.app_auth import AppAuth
from ogden_provision.policy import Error
m=AppAuth(json.load(open('examples/auth/provisioning-reader.json')))
try:
    m.require_apply()
except Error as e:
    raise SystemExit(0 if str(e)=='AUTH_READER_CANNOT_APPLY' else 3)
raise SystemExit(3)
"""


def profile_valid(config):
    demand(config.get('profile')=='reader' and config.get('appId')==APP_ID and
           config.get('installationId')==INSTALLATION_ID and config.get('appName')==APP_NAME and
           config.get('owner')=='ogdenit-nathan' and config.get('permissions')==READ and
           len(config.get('repositories',[]))==2 and
           {r['name']:r['id'] for r in config['repositories']}==REPOS and
           config.get('keySource')=={'kind':'file','pathEnvironment':'OGDEN_READER_KEY_FILE'},'IDENTITY_INVALID')


def auth_evidence(report):
    a=report['authentication']
    demand(a.get('profile')=='reader' and a.get('appId')==APP_ID and a.get('installationId')==INSTALLATION_ID and
           a.get('appName')==APP_NAME and a.get('owner')=='ogdenit-nathan' and a.get('permissions')==READ and
           len(a.get('repositories',[]))==2 and {r['name']:r['id'] for r in a['repositories']}==REPOS and
           a.get('tokenScopeVerified') is True and report.get('target')==TARGET and report.get('complete') is True,'AUTHENTICATION_FAILED')
    expected=[f'/repos/{TARGET}'+s for s in ('/actions/permissions','/immutable-releases','/branches/main/protection')]
    checks=report['checks']
    demand(len(checks)==3 and [c.get('endpoint') for c in checks]==expected,'AUTHENTICATION_FAILED')
    result=[]
    for name,check in zip(('actions','immutableReleases','mainProtection'),checks):
        status=check.get('status');http=check.get('httpStatus')
        demand((status=='Success' and http==200) or (name=='mainProtection' and status=='Unprotected' and http==404),'AUTHENTICATION_FAILED')
        result.append({'check':name,'status':status,'httpStatus':http})
    return result


def digest(value):
    demand(isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value))
    return value


def inspect_report(report):
    demand(report.get('target')==TARGET and report.get('state',{}).get('repo_id')==TARGET_ID)


def execute(source,key,evidence,runner=run_child):
    profile_valid(json.loads((source/AUTH).read_text()))
    demand(runner(['-c',GUARD],source,key)==0,'READER_GUARD_FAILED')
    evidence['readerGuard']='passed'
    for operation in ('auth-validate','plan','verify'):
        path=source/(operation+'.json')
        code=runner(['-m','ogden_provision',operation,'--config',CONFIG,'--auth-config',AUTH,'--output',str(path)],source,key)
        if operation=='auth-validate':
            demand(code==0,'AUTHENTICATION_FAILED')
            evidence['authentication']=auth_evidence(json.loads(path.read_text()))
        else:
            demand(code in (0,2),'CLI_FAILED')
            report=json.loads(path.read_text());inspect_report(report)
            evidence[operation]={'exitCode':code,'status':'passed' if code==0 else 'rejected'}
            if operation=='plan':
                blockers=report.get('blockers');scope=report.get('scope')
                demand(isinstance(blockers,list) and isinstance(scope,list))
                demand((code==0 and not blockers) or (code==2 and bool(blockers)))
                evidence['plan'].update(planId=digest(report['planId']),configDigest=digest(report['configDigest']),
                    engineDigest=digest(report['engineDigest']),proposedOperationCount=len(scope),blockerCount=len(blockers))
            else:
                demand(type(report.get('compliant')) is bool and (code==0)==report['compliant'])
                demand(digest(report['configDigest'])==evidence['plan']['configDigest'])
    demand(evidence['plan']['exitCode']==0 and evidence['verify']['exitCode']==0,'NONCOMPLIANT')


def context():
    env=os.environ
    sha=env.get('GITHUB_SHA','')
    demand(env.get('GITHUB_REPOSITORY_ID')=='1460643831' and env.get('GITHUB_REPOSITORY')=='ogdenit-nathan/ogden-automation-control' and
           env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and env.get('GITHUB_REF')=='refs/heads/main' and
           re.fullmatch('[a-f0-9]{40}',sha) and env.get('REVIEWED_CONTROL_COMMIT')==sha and env.get('GITHUB_WORKFLOW_SHA')==sha,'CONTEXT_INVALID')
    run,attempt=env.get('GITHUB_RUN_ID',''),env.get('GITHUB_RUN_ATTEMPT','')
    demand(re.fullmatch('[1-9][0-9]*',run) and re.fullmatch('[1-9][0-9]*',attempt),'CONTEXT_INVALID')
    temp=Path(env['RUNNER_TEMP'])
    demand(temp.is_absolute() and temp.is_dir() and temp.resolve()==temp,'CONTEXT_INVALID')
    workspace=Path(env['GITHUB_WORKSPACE']).resolve()
    demand(temp!=workspace and workspace not in temp.parents,'CONTEXT_INVALID')
    for parent in (temp,*temp.parents):
        info=parent.lstat()
        demand(not stat.S_ISLNK(info.st_mode) and not (parent/'.git').exists() and
               (not info.st_mode & 0o022 or bool(info.st_mode & stat.S_ISVTX)),'CONTEXT_INVALID')
    return temp/f'ogden-reader-{run}-{attempt}',sha,run,attempt


def remove_work(root):
    if root.exists() or root.is_symlink():
        info=root.lstat()
        marker=root/'owned'
        demand(stat.S_ISDIR(info.st_mode) and not root.is_symlink() and info.st_uid==os.geteuid() and
               info.st_mode & 0o777==0o700 and not marker.is_symlink() and
               marker.read_text()=='ogden-reader-6f','CLEANUP_FAILED')
        shutil.rmtree(root)


def perform(evidence, env_key, root, bootstrap_factory=Bootstrap, executor=execute):
    # Atomic creation refuses any preexisting work directory. Nothing in checkout.
    root.mkdir(mode=0o700)
    (root/'owned').write_text('ogden-reader-6f')
    bootstrap=None
    try:
        demand(isinstance(env_key,str) and 1<=len(env_key)<=65536,'KEY_UNAVAILABLE')
        key=root/'reader.pem'
        with os.fdopen(os.open(key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as stream:stream.write(env_key)
        env_key=None
        source=root/'source';source.mkdir(mode=0o700)
        bootstrap=bootstrap_factory(key)
        bootstrap.open();bootstrap.fetch(source)
        bootstrap.close();bootstrap=None # Revoke retrieval token BEFORE private code executes.
        executor(source,key,evidence)
    finally:
        try:
            if bootstrap is not None:bootstrap.close()
        finally:
            remove_work(root)


CODES={'BOOTSTRAP_FAILED','SOURCE_INVALID','IDENTITY_INVALID','AUTHENTICATION_FAILED','READER_GUARD_FAILED',
       'CLI_FAILED','NONCOMPLIANT','REPORT_INVALID','CONTEXT_INVALID','CLEANUP_FAILED','KEY_UNAVAILABLE'}


def main(argv=None):
    pem=os.environ.pop('OGDEN_READER_PRIVATE_KEY',None)
    evidence={'schemaVersion':'1.0','acceptance':'failed','sourceCommit':SOURCE_SHA,'targetRepositoryId':TARGET_ID}
    try:
        root,sha,run,attempt=context()
        if argv==['cleanup']:
            remove_work(root)
            return 0
        demand(not argv,'CONTEXT_INVALID')
        evidence.update(controlCommit=sha,runId=run,runAttempt=attempt)
        # Remove raw secret from the parent's environment before child processes.
        from importlib.metadata import version
        demand(sys.version_info[:2]==(3,12) and all(version(n)==v for n,v in
            [('PyJWT','2.13.0'),('cryptography','50.0.0'),('cffi','2.1.1'),('pycparser','3.0')]),'CONTEXT_INVALID')
        perform(evidence,pem,root)
        pem=None
        evidence['acceptance']='passed'
        code=0
    except BaseException as error:
        code=1
        evidence['failureCode']=str(error) if type(error) is Stop and str(error) in CODES else 'LOCAL_OR_REMOTE_FAILURE'
    if argv!=['cleanup']:
        print(json.dumps(evidence,sort_keys=True)) # Reconstructed allowlist only; never raw reports.
    return code


if __name__=='__main__':
    raise SystemExit(main(sys.argv[1:]))
