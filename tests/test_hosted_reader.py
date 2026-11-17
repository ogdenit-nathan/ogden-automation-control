import base64, contextlib, copy, importlib.util, io, json, os, subprocess, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('hosted_reader',ROOT/'scripts/hosted_reader.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
SENTINEL='SYNTHETIC_PRIVATE_SENTINEL'

def profile():
 return dict(profile='reader',appId=h.APP_ID,appName=h.APP_NAME,installationId=h.INSTALLATION_ID,owner='ogdenit-nathan',permissions=dict(h.READ),repositories=[{'name':k,'id':v} for k,v in h.REPOS.items()],keySource={'kind':'file','pathEnvironment':'OGDEN_READER_KEY_FILE'})
def authentication():
 return dict(authentication=dict(profile(),tokenScopeVerified=True),target=h.TARGET,complete=True,checks=[{'endpoint':f'/repos/{h.TARGET}'+s,'status':'Success','httpStatus':200,'observation':SENTINEL} for s in ('/actions/permissions','/immutable-releases','/branches/main/protection')],raw=SENTINEL)

class Server:
 def __init__(self,key):
  self.key=key;self.calls=[];self.revoked=[];self.token='opaque.'+'t'*3000
  self.app={'id':h.APP_ID,'name':h.APP_NAME,'owner':{'login':'ogdenit-nathan'}}
  self.installation={'id':h.INSTALLATION_ID,'app_id':h.APP_ID,'account':{'login':'ogdenit-nathan'},'suspended_at':None,'repository_selection':'selected','permissions':dict(h.READ)}
  self.repos={'total_count':1,'repositories':[{'full_name':h.SOURCE,'id':h.SOURCE_ID}]}
 def request(self,method,path,bearer,body=None):
  self.calls.append((method,path,body))
  if path in ('/app',f'/app/installations/{h.INSTALLATION_ID}') or method=='POST':
   claims=jwt.decode(bearer,self.key.public_key(),algorithms=['RS256'])
   assert claims['iss']==str(h.APP_ID) and claims['exp']-claims['iat']==600
  if path=='/app':return copy.deepcopy(self.app)
  if path==f'/app/installations/{h.INSTALLATION_ID}':return copy.deepcopy(self.installation)
  if method=='POST':
   assert body=={'repository_ids':[h.SOURCE_ID],'permissions':h.FETCH_PERMISSIONS}
   return {'token':self.token,'expires_at':datetime.fromtimestamp(h.time.time()+3600,timezone.utc).isoformat().replace('+00:00','Z'),'permissions':dict(h.FETCH_PERMISSIONS),'repository_selection':'selected'}
  if path.startswith('/installation/repositories'):return copy.deepcopy(self.repos)
  if method=='DELETE':self.revoked.append(bearer);return None
  raise RuntimeError(SENTINEL)

class HostedReader(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.rsa=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir()
  (self.source/h.AUTH).parent.mkdir(parents=True);(self.source/h.AUTH).write_text(json.dumps(profile()))
  self.pem=self.rsa.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
  self.key=self.root/'synthetic.pem';self.key.write_text(self.pem);self.key.chmod(0o600)
  self.evidence={};self.codes={};self.commands=[]
  self.reports={'auth-validate':authentication(),'plan':{'target':h.TARGET,'state':{'repo_id':h.TARGET_ID,'private':SENTINEL},'planId':'c'*64,'configDigest':'a'*64,'engineDigest':'b'*64,'blockers':[],'scope':[],'private':SENTINEL},'verify':{'target':h.TARGET,'state':{'repo_id':h.TARGET_ID},'compliant':True,'configDigest':'a'*64,'private':SENTINEL}}
 def tearDown(self):self.temp.cleanup()
 def runner(self,args,source,key):
  self.commands.append(args)
  if args[0]=='-c':return self.codes.get('guard',0)
  op=args[2];Path(args[-1]).write_text(json.dumps(self.reports[op]));return self.codes.get(op,0)
 def execute(self):return h.execute(self.source,self.key,self.evidence,self.runner)
 def test_independent_commands_and_sanitized_evidence(self):
  self.execute();self.assertEqual([c[2] for c in self.commands[1:]],['auth-validate','plan','verify'])
  self.assertNotIn(SENTINEL,json.dumps(self.evidence));self.assertEqual(self.evidence['readerGuard'],'passed')
  self.assertFalse(any('apply' in c for c in self.commands))
 def test_auth_failure_stops(self):
  self.codes['auth-validate']=2
  with self.assertRaisesRegex(h.Stop,'AUTHENTICATION_FAILED'):self.execute()
  self.assertEqual(len(self.commands),2)
 def test_incomplete_report_even_zero_exit_stops(self):
  self.reports['auth-validate']['complete']=False
  with self.assertRaises(h.Stop):self.execute()
  self.assertEqual(len(self.commands),2)
 def test_wrong_identity_or_extra_scope(self):
  for field,value in [('appId',1),('installationId',2),('permissions',{}),('repositories',[])]:
   with self.subTest(field=field):
    report=authentication();report['authentication'][field]=value
    with self.assertRaises(h.Stop):h.auth_evidence(report)
 def test_guard_failure_before_auth(self):
  self.codes['guard']=3
  with self.assertRaisesRegex(h.Stop,'READER_GUARD_FAILED'):self.execute()
  self.assertEqual(len(self.commands),1)
 def test_admin_profile_stops_before_children(self):
  p=profile();p['profile']='administrator';(self.source/h.AUTH).write_text(json.dumps(p))
  with self.assertRaises(h.Stop):self.execute()
  self.assertFalse(self.commands)
 def test_blocked_plan_keeps_verify_but_fails(self):
  self.codes['plan']=2;self.reports['plan']['blockers']=[SENTINEL]
  with self.assertRaisesRegex(h.Stop,'NONCOMPLIANT'):self.execute()
  self.assertEqual(self.evidence['verify']['exitCode'],0);self.assertNotIn(SENTINEL,json.dumps(self.evidence))
 def test_verify_noncompliance_fails(self):
  self.codes['verify']=2;self.reports['verify']['compliant']=False
  with self.assertRaisesRegex(h.Stop,'NONCOMPLIANT'):self.execute()
 def test_unexpected_exit_and_wrong_target(self):
  self.codes['plan']=7
  with self.assertRaisesRegex(h.Stop,'CLI_FAILED'):self.execute()
  self.codes.clear();self.reports['plan']['state']['repo_id']=1
  with self.assertRaises(h.Stop):self.execute()
 def test_cannot_smuggle_digest_text(self):
  self.reports['plan']['planId']=SENTINEL
  with self.assertRaises(h.Stop):self.execute()
  self.assertNotIn(SENTINEL,json.dumps(self.evidence))
 def test_configuration_drift(self):
  self.reports['verify']['configDigest']='d'*64
  with self.assertRaises(h.Stop):self.execute()
 def test_child_output_and_unrelated_credentials_discarded(self):
  with patch.dict(os.environ,GH_TOKEN=SENTINEL,GITHUB_TOKEN=SENTINEL,PYTHONPATH=SENTINEL,OGDEN_READER_PRIVATE_KEY=SENTINEL),patch.object(h.subprocess,'run',return_value=type('Result',(),{'returncode':0})()) as call:
   h.run_child(['-m','ogden_provision','verify'],self.source,self.key)
  opts=call.call_args.kwargs;self.assertEqual(opts['stdout'],subprocess.DEVNULL);self.assertEqual(opts['stderr'],subprocess.DEVNULL)
  self.assertNotIn(SENTINEL,json.dumps(opts['env']))
 def test_real_jwt_and_long_source_scoped_token(self):
  server=Server(self.rsa);b=h.Bootstrap(self.key,server);b.open();self.assertGreater(len(b.token),520)
  b.close();self.assertEqual(server.revoked,[server.token])
 def test_bootstrap_wrong_identity_permissions_scope(self):
  for kind in ('app','installation','scope'):
   with self.subTest(kind=kind):
    server=Server(self.rsa)
    if kind=='app':server.app['id']=1
    elif kind=='installation':server.installation['permissions']['contents']='write'
    else:server.repos['repositories'].append({'full_name':h.TARGET,'id':h.TARGET_ID})
    b=h.Bootstrap(self.key,server)
    with self.assertRaises(h.Stop):b.open()
    b.close()
 def test_no_repository_mutation_routes(self):
  for method,path in [('PATCH',f'/repos/{h.SOURCE}'),('GET','//evil.test'),('POST','/user/repos')]:
   with self.assertRaises(h.Stop):h.HTTP().request(method,path,'opaque')
 def test_pinned_commit_and_tampered_blob(self):
  b=h.Bootstrap(self.key);b.token='synthetic'
  with patch.object(b,'get',return_value={'sha':'0'*40,'tree':{'sha':h.SOURCE_TREE}}):
   with self.assertRaises(h.Stop):b.fetch(self.source)
  paths=[h.AUTH,h.CONFIG,'ogden_provision/__main__.py','ogden_provision/a.py','ogden_provision/b.py']
  replies=[{'sha':h.SOURCE_SHA,'tree':{'sha':h.SOURCE_TREE}},{'sha':h.SOURCE_TREE,'truncated':False,'tree':[{'path':p,'sha':'a'*40,'type':'blob','mode':'100644'} for p in paths]},{'sha':'a'*40,'encoding':'base64','size':5,'content':base64.b64encode(b'wrong').decode()}]
  with patch.object(b,'get',side_effect=replies):
   with self.assertRaises(h.Stop):b.fetch(self.source)
 def test_private_material_cleaned_on_failure(self):
  outer=self
  class Fake:
   def __init__(self,key):self.key=key
   def open(self):pass
   def fetch(self,source):
    outer.assertEqual(self.key.stat().st_mode&0o777,0o600);outer.assertEqual(self.key.parent.stat().st_mode&0o777,0o700)
    (source/'private.json').write_text(SENTINEL)
   def close(self):pass
  work=self.root/'work'
  with self.assertRaises(RuntimeError):h.perform({},self.pem,work,Fake,lambda *args:(_ for _ in ()).throw(RuntimeError(SENTINEL)))
  self.assertFalse(work.exists())
 def test_revoke_failure_still_removes_key(self):
  class Fake:
   def __init__(self,key):pass
   def open(self):pass
   def fetch(self,source):pass
   def close(self):raise RuntimeError(SENTINEL)
  work=self.root/'work'
  with self.assertRaises(RuntimeError):h.perform({},self.pem,work,Fake,lambda *args:None)
  self.assertFalse(work.exists())
 def test_unowned_or_preexisting_paths_refused(self):
  work=self.root/'unowned';work.mkdir()
  with self.assertRaises(Exception):h.remove_work(work)
  self.assertTrue(work.exists())
  with self.assertRaises(FileExistsError):h.perform({},self.pem,work)
 def test_untrusted_context_fails_nonzero(self):
  stream=io.StringIO()
  with patch.dict(os.environ,{},clear=True),contextlib.redirect_stdout(stream):self.assertEqual(h.main([]),1)
  self.assertEqual(json.loads(stream.getvalue())['failureCode'],'CONTEXT_INVALID')
 def test_main_redacts_errors_and_removes_secret_env(self):
  stream=io.StringIO()
  with patch.object(h,'context',return_value=(self.root/'work','a'*40,'123','1')),patch.object(h,'perform',side_effect=RuntimeError(SENTINEL)),patch.dict(os.environ,OGDEN_READER_PRIVATE_KEY=SENTINEL),contextlib.redirect_stdout(stream):
   self.assertEqual(h.main([]),1);self.assertNotIn('OGDEN_READER_PRIVATE_KEY',os.environ)
  self.assertNotIn(SENTINEL,stream.getvalue())
 def test_fetch_validates_and_writes_only_selected_files(self):
  import hashlib
  files={h.CONFIG:b'{}',h.AUTH:b'{}','ogden_provision/__main__.py':b'# synthetic',
         'ogden_provision/a.py':b'# synthetic a','ogden_provision/b.py':b'# synthetic b'}
  blobs={hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest():data for data in files.values()}
  entries=[{'path':p,'sha':hashlib.sha1(b'blob '+str(len(d)).encode()+b'\0'+d).hexdigest(),'type':'blob','mode':'100644'} for p,d in files.items()]
  entries.append({'path':'docs/internal.md','sha':'a'*40,'type':'blob','mode':'100644'})
  def get(path):
   if '/commits/' in path:return {'sha':h.SOURCE_SHA,'tree':{'sha':h.SOURCE_TREE}}
   if '/trees/' in path:return {'sha':h.SOURCE_TREE,'truncated':False,'tree':entries}
   sha=path.rsplit('/',1)[1];data=blobs[sha]
   return {'sha':sha,'encoding':'base64','size':len(data),'content':base64.b64encode(data).decode()}
  dest=self.root/'fetched';dest.mkdir();b=h.Bootstrap(self.key)
  with patch.object(b,'get',side_effect=get):b.fetch(dest)
  self.assertEqual({str(p.relative_to(dest)) for p in dest.rglob('*') if p.is_file()},set(files))
 def test_symlink_cleanup_refused(self):
  link=self.root/'linked';link.symlink_to(self.source,target_is_directory=True)
  with self.assertRaises(h.Stop):h.remove_work(link)
  self.assertTrue(self.source.is_dir())
 def test_workflow_scopes_and_dependencies(self):
  import re
  text=(ROOT/'.github/workflows/hosted-reader-acceptance.yml').read_text()
  self.assertIn("github.ref == 'refs/heads/main'",text)
  self.assertIn('github.sha == inputs.reviewed_control_commit',text)
  self.assertIn('environment: reader-acceptance',text)
  self.assertEqual(re.findall(r'secrets\.([A-Z_]+)',text),['PROVISIONING_READER_APP_PRIVATE_KEY'])
  self.assertTrue(all(re.fullmatch('[a-f0-9]{40}',pin) for pin in re.findall(r'uses: [^@]+@([^\s]+)',text)))
  self.assertNotIn('upload-artifact',text)
  self.assertEqual([l.strip() for l in (ROOT/'requirements-reader.txt').read_text().splitlines() if l and not l.startswith('#')],['PyJWT==2.13.0','cryptography==50.0.0','cffi==2.1.1','pycparser==3.0'])
if __name__=='__main__':unittest.main()
