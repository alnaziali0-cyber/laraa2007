import io, zipfile, subprocess
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import app as mod

@pytest.fixture
def client(tmp_path,monkeypatch):
 monkeypatch.setattr(mod,'DATA',tmp_path/'data');mod.DATA.mkdir()
 monkeypatch.setattr(mod,'DB',mod.DATA/'test.sqlite3')
 monkeypatch.setattr(mod,'USERS',mod.DATA/'users');mod.USERS.mkdir()
 monkeypatch.setattr(mod,'MAX_FILE',1024*1024);monkeypatch.setattr(mod,'QUOTA',4*1024*1024)
 monkeypatch.setattr(mod,'OWNER_EMAIL','owner@example.com')
 for k,v in {'SMTP_HOST':'smtp.example.com','SMTP_USERNAME':'owner@example.com','SMTP_PASSWORD':'dummy-test-only','SMTP_FROM':'owner@example.com','APP_SECRET_KEY':'test-secret-key-with-enough-entropy-123456'}.items():monkeypatch.setenv(k,v)
 mod.init_db()
 with TestClient(mod.app) as c:yield c

def make_owner():
 import uuid
 uid=uuid.uuid4().hex
 with mod.db() as d:d.execute('INSERT INTO users VALUES(?,?,?,?,?)',(uid,mod.OWNER_EMAIL,mod.PH.hash('safe-test-password-123'),'admin',mod.utc()))
 mod.user_root(uid)
 return uid

def login(c,monkeypatch=None,owner=None):
 owner=owner or make_owner();captured={}
 mod.send_otp=lambda to,code:captured.update(to=to,code=code)
 r=c.post('/api/login',json={'email':mod.OWNER_EMAIL,'password':'safe-test-password-123'});assert r.status_code==200 and r.json()['status']=='verification_required'
 assert captured['to']==mod.OWNER_EMAIL and len(captured['code'])==6
 r=c.post('/api/verify',json={'code':captured['code']});assert r.status_code==200
 return owner,captured

def post(c,url,**kw):return c.post(url,headers={'X-CSRF-Token':c.cookies.get('hp_csrf','')},**kw)
def put(c,url,**kw):return c.put(url,headers={'X-CSRF-Token':c.cookies.get('hp_csrf','')},**kw)
def zipped(items):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w') as z:
  for n,v in items.items():z.writestr(n,v)
 return b.getvalue()

def test_owner_only_otp_argon2_and_no_registration(client,monkeypatch):
 owner,codes=login(client)
 with mod.db() as d:r=d.execute('SELECT password FROM users WHERE email=?',(mod.OWNER_EMAIL,)).fetchone()
 assert r['password'].startswith('$argon2id$')
 assert client.get('/api/me').status_code==200
 assert client.post('/api/register',json={'email':'x@example.com','password':'safe-password-123'}).status_code in (404,405)
 assert client.post('/api/verify',json={'code':codes['code']}).status_code==401

def test_wrong_email_and_password_generic_and_rate_limited(client):
 assert client.post('/api/login',json={'email':'intruder@example.com','password':'not-the-password'}).status_code==401
 for _ in range(5):client.post('/api/login',json={'email':'owner@example.com','password':'bad'})
 assert client.post('/api/login',json={'email':'owner@example.com','password':'bad'}).status_code==429

def test_missing_smtp_does_not_claim_code_sent(client,monkeypatch):
 make_owner();monkeypatch.delenv('SMTP_HOST')
 r=client.post('/api/login',json={'email':mod.OWNER_EMAIL,'password':'safe-test-password-123'})
 assert r.status_code==503 and 'لم يُرسل أي رمز' in r.json()['detail']

def test_otp_expiry_and_attempt_limit(client):
 make_owner();captured={};mod.send_otp=lambda to,code:captured.update(code=code)
 client.post('/api/login',json={'email':mod.OWNER_EMAIL,'password':'safe-test-password-123'})
 with mod.db() as d:d.execute('UPDATE otp_challenges SET expires=0')
 assert client.post('/api/verify',json={'code':captured['code']}).status_code==401

def test_file_upload_save_download_zip_slip_and_csrf(client):
 login(client)
 assert client.post('/api/upload',files=[('files',('main.py',b'print("hi")','text/x-python'))]).status_code==403
 assert post(client,'/api/upload',files=[('files',('main.py',b'print("hi")','text/x-python'))]).status_code==200
 assert client.get('/api/file?path=main.py').json()['content']=='print("hi")'
 assert put(client,'/api/file',json={'path':'main.py','content':'print("updated")'}).json()['saved']
 assert client.get('/api/download?path=main.py').content==b'print("updated")'
 good=zipped({'demo/main.py':'print(1)','demo/requirements.txt':'requests'})
 assert post(client,'/api/upload',files=[('files',('demo.zip',good,'application/zip'))]).status_code==200
 assert post(client,'/api/zip/extract',json={'path':'demo.zip','name':'project'}).status_code==200
 assert client.get('/api/file?path=project/demo/main.py').json()['content']=='print(1)'
 evil=zipped({'../../outside.txt':'bad'})
 assert post(client,'/api/upload',files=[('files',('evil.zip',evil,'application/zip'))]).status_code==400
 assert not (mod.DATA/'outside.txt').exists()
 assert client.get('/api/file?path=../../etc/passwd').status_code==400

def test_entry_discovery_explicit_files_ambiguous_and_none(tmp_path):
 root=tmp_path/'project';root.mkdir();(root/'main.py').write_text('if __name__ == "__main__": print(1)')
 (root/'bot.py').write_text('if __name__ == "__main__": print(2)')
 c=mod.discover_candidates(root)
 assert len(c)==2 and {x['path'] for x in c}=={'main.py','bot.py'} and c[0]['score']==88
 (root/'Procfile').write_text('worker: python bot.py')
 c=mod.discover_candidates(root)
 assert c[0]['path']=='bot.py' and 'Procfile' in c[0]['reasons'][0]
 blank=tmp_path/'blank';blank.mkdir();(blank/'util.py').write_text('def helper(): return 1')
 assert mod.discover_candidates(blank)==[]
 assert not list(blank.glob('*.pyc'))

def test_zip_project_entry_detection_and_pyproject(tmp_path):
 root=tmp_path/'proj';root.mkdir();(root/'start.py').write_text('def main(): pass')
 (root/'pyproject.toml').write_text('[project.scripts]\nworker = "start:main"\n')
 got=mod.discover_candidates(root)
 assert got[0]['path']=='start.py' and 'pyproject.toml' in got[0]['reasons'][0]


def test_project_create_discovery_and_missing_entry(client):
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'demo','entry':''}).json();root=mod.project_path(uid,p['id']);(root/'server.py').write_text('if __name__ == "__main__": pass')
 r=client.get(f"/api/projects/{p['id']}/discover").json();assert r['selected']=='server.py'
 q=post(client,'/api/projects',json={'name':'empty','entry':''}).json()
 r=post(client,f"/api/projects/{q['id']}/run")
 assert r.status_code==503 or r.status_code==409

def test_installation_runs_only_via_limited_docker_command(client,monkeypatch):
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'install','entry':'main.py'}).json();root=mod.project_path(uid,p['id']);(root/'requirements.txt').write_text('sample-package')
 calls=[];monkeypatch.setattr(mod,'docker_ok',lambda:True)
 monkeypatch.setattr(mod,'docker',lambda *a,**k:(calls.append(a) or subprocess.CompletedProcess(a,0,'','')))
 r=post(client,f"/api/projects/{p['id']}/install")
 assert r.status_code==200 and any('--memory' in a for a in calls) and any('"/opt/venv/env/bin/pip","install"' in str(a) and '/opt/venv' in str(a) for a in calls) and all('/var/run/docker.sock' not in str(a) for a in calls)

def test_container_start_stop_flags_and_crash_state(client,monkeypatch):
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'run','entry':'main.py'}).json();(mod.project_path(uid,p['id'])/'main.py').write_text('print(1)')
 calls=[];monkeypatch.setattr(mod,'docker_ok',lambda:True)
 def fake(*args,**kwargs):
  calls.append(args)
  if args[:1]==('info',):return subprocess.CompletedProcess(args,0,'','')
  if args[:2]==('inspect','-f') and args[-1].startswith('seahost-'):
   return subprocess.CompletedProcess(args,0,'exited' if '{{.State.Status}}' in args else '0','')
  if args[:2]==('volume','inspect'):return subprocess.CompletedProcess(args,1,'','not found')
  return subprocess.CompletedProcess(args,0,'cid','')
 monkeypatch.setattr(mod,'docker',fake)
 r=post(client,f"/api/projects/{p['id']}/run");assert r.status_code==200
 run=next(x for x in calls if x and x[0]=='run')
 assert '--network' in run and run[run.index('--network')+1]=='none'
 assert '--user' in run and run[run.index('--user')+1]=='10001:10001'
 assert '--memory' in run and '--cap-drop' in run and '--pids-limit' in run
 assert post(client,f"/api/projects/{p['id']}/stop").status_code==200
 assert any(x and x[0]=='stop' for x in calls)


def test_expired_session_and_legacy_nonowner_are_rejected(client):
 login(client)
 with mod.db() as d:d.execute('UPDATE sessions SET expires=0')
 assert client.get('/api/me').status_code==401
 import uuid
 other=uuid.uuid4().hex;token='legacy-session-token'
 with mod.db() as d:
  d.execute('INSERT INTO users VALUES(?,?,?,?,?)',(other,'old@example.com',mod.PH.hash('legacy-test-password'),'user',mod.utc()))
  d.execute('INSERT INTO sessions VALUES(?,?,?)',(mod.hash_token(token),other,int(__import__('time').time())+3600))
 client.cookies.set(mod.SESSION_COOKIE,token)
 assert client.get('/api/me').status_code==401

def test_zip_archive_static_entry_detection(tmp_path):
 root=tmp_path/'uploads';root.mkdir();archive=root/'project.zip'
 archive.write_bytes(zipped({'demo/main.py':'if __name__ == "__main__": pass','demo/Procfile':'worker: python demo/main.py'}))
 entries=mod.zip_preview(archive.read_bytes())
 with zipfile.ZipFile(archive) as z:candidates=mod.discover_candidates(root,entries,z)
 assert candidates[0]['path']=='demo/main.py' and 'Procfile' in candidates[0]['reasons'][0]
 assert not (root/'demo').exists()

def test_runner_allowlist_accepts_confined_run_rejects_privilege_and_socket(tmp_path,monkeypatch):
 import runner_worker as worker
 data=tmp_path/'persistent';uid='a'*32;pid='b'*32;root=data/'users'/uid/'projects'/pid;root.mkdir(parents=True)
 monkeypatch.setattr(worker,'DATA_ROOT',str(data))
 name='seahost-'+pid[:24]
 args=['run','-d','--name',name,'--label','seahost.owner='+'c'*20,'--network','none','--memory','256m','--memory-swap','256m','--cpus','0.50','--pids-limit','128','--ulimit','cpu=86400:86400','--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001','--env','PYTHONDONTWRITEBYTECODE=1','--env','PYTHONUNBUFFERED=1','--mount',f'type=bind,src={root},dst=/app,readonly','--workdir','/app',worker.os.getenv('RUNNER_IMAGE','python:3.12-slim'),'python','-u','main.py']
 assert worker.allowed(args)
 assert not worker.allowed(args[:1]+['--privileged']+args[1:])
 evil=args.copy();evil[evil.index('--mount')+1]='type=bind,src=/var/run/docker.sock,dst=/app'
 assert not worker.allowed(evil)


def test_pyproject_dependencies_generate_only_temporary_safe_spec(tmp_path):
 root=tmp_path/'app';root.mkdir()
 (root/'pyproject.toml').write_text('[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["requests>=2", "pydantic"]\n')
 req,generated=mod.dependency_spec(root)
 assert generated and req.name=='.seahost-requirements.pending.txt'
 assert req.read_text()=='requests>=2\npydantic\n'
 req.unlink();assert not req.exists()

def test_settings_mask_public_owner_and_do_not_expose_smtp_secret(client):
 login(client)
 public=client.get('/api/auth/config').json()
 assert 'owner@example.com' not in str(public) and public['owner_email_hint']!='owner@example.com'
 data=client.get('/api/settings').json()
 assert data['owner_email']=='owner@example.com' and data['smtp_ready'] is True
 assert 'dummy-test-only' not in str(data)

def test_install_from_pyproject_removes_temporary_file_and_logs_safe_result(client,monkeypatch):
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'pyproject','entry':'main.py'}).json();root=mod.project_path(uid,p['id'])
 (root/'main.py').write_text('print(1)');(root/'pyproject.toml').write_text('[project]\nname="demo"\nversion="0.1.0"\ndependencies=["requests>=2"]\n')
 calls=[];monkeypatch.setattr(mod,'docker_ok',lambda:True)
 monkeypatch.setattr(mod,'docker',lambda *a,**k:(calls.append(a) or subprocess.CompletedProcess(a,0,'','')))
 r=post(client,f"/api/projects/{p['id']}/install")
 assert r.status_code==200 and any('.seahost-requirements.pending.txt' in str(a) for a in calls)
 assert not (root/'.seahost-requirements.pending.txt').exists()

def test_runner_install_command_is_limited_to_project_manifest_and_dependency_volume(tmp_path,monkeypatch):
 import runner_worker as worker
 data=tmp_path/'persistent';uid='a'*32;pid='b'*32;root=data/'users'/uid/'projects'/pid;root.mkdir(parents=True)
 monkeypatch.setattr(worker,'DATA_ROOT',str(data));image=worker.os.getenv('RUNNER_IMAGE','python:3.12-slim')
 args=['run','--rm','--network','none','--memory','512m','--memory-swap','512m','--cpus','0.50','--pids-limit','96','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001','--mount',f'type=bind,src={root},dst=/app,readonly','--mount','type=volume,src=seahost-deps-'+pid[:24]+',dst=/opt/venv','--workdir','/app',image,'python','-c',worker.INSTALL_SCRIPT,'/app/requirements.txt']
 assert worker.allowed(args)
 bad=args.copy();bad[-1]=bad[-1].replace('/app/requirements.txt','/etc/passwd')
 assert not worker.allowed(bad)

def test_otp_has_five_attempt_limit_and_is_one_time(client):
 make_owner();captured={};mod.send_otp=lambda to,code:captured.update(code=code)
 client.post('/api/login',json={'email':mod.OWNER_EMAIL,'password':'safe-test-password-123'})
 for _ in range(5):assert client.post('/api/verify',json={'code':'000000'}).status_code==401
 assert client.post('/api/verify',json={'code':captured['code']}).status_code==401

def test_duplicate_start_is_blocked_by_persisted_operation_lock(client,monkeypatch):
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'locked','entry':'main.py'}).json();root=mod.project_path(uid,p['id']);(root/'main.py').write_text('print(1)')
 with mod.db() as d:d.execute("UPDATE projects SET operation='starting' WHERE id=?",(p['id'],))
 calls=[];monkeypatch.setattr(mod,'docker_ok',lambda:True);monkeypatch.setattr(mod,'docker',lambda *a,**k:(calls.append(a) or subprocess.CompletedProcess(a,0,'exited','')))
 r=post(client,f"/api/projects/{p['id']}/run")
 assert r.status_code==409 and not any(a and a[0]=='run' for a in calls)

def test_failed_install_identifies_package_without_pip_secrets(client,monkeypatch):
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'bad-dep','entry':'main.py'}).json();root=mod.project_path(uid,p['id'])
 (root/'pyproject.toml').write_text('[project]\nname="demo"\nversion="0.1.0"\ndependencies=["bad-package"]\n')
 monkeypatch.setattr(mod,'docker_ok',lambda:True)
 def fail_pip(*args,**kwargs):
  if any(isinstance(x,str) and '"/opt/venv/env/bin/pip","install"' in x for x in args):return subprocess.CompletedProcess(args,1,'','ERROR: No matching distribution found for bad-package\nhttps://token-user:secret-value@example.invalid')
  return subprocess.CompletedProcess(args,0,'','')
 monkeypatch.setattr(mod,'docker',fail_pip)
 r=post(client,f"/api/projects/{p['id']}/install")
 assert r.status_code==422 and 'bad-package' in r.json()['detail'] and 'secret-value' not in r.json()['detail']
 assert not (root/'.seahost-requirements.pending.txt').exists()

def test_crashed_container_is_reported_and_logs_persist_before_restart(client,monkeypatch):
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'crash','entry':'main.py'}).json();root=mod.project_path(uid,p['id']);(root/'main.py').write_text('raise RuntimeError()')
 with mod.db() as d:d.execute('UPDATE projects SET started_at=?,stopped_at=NULL WHERE id=?',(1000,p['id']))
 calls=[];monkeypatch.setattr(mod,'docker_ok',lambda:True)
 def fake(*args,**kwargs):
  calls.append(args)
  if args[:2]==('inspect','-f') and args[2]=='{{.State.Status}}':return subprocess.CompletedProcess(args,0,'exited','')
  if args[:2]==('inspect','-f') and args[2]=='{{.State.ExitCode}}':return subprocess.CompletedProcess(args,0,'1','')
  if args[:1]==('logs',):return subprocess.CompletedProcess(args,0,'Traceback: RuntimeError','')
  if args[:2]==('volume','inspect'):return subprocess.CompletedProcess(args,1,'','not found')
  return subprocess.CompletedProcess(args,0,'cid','')
 monkeypatch.setattr(mod,'docker',fake)
 assert client.get('/api/projects').json()[0]['status']=='Crashed'
 seen=client.get(f"/api/projects/{p['id']}/logs").json();assert 'RuntimeError' in seen['logs']
 assert post(client,f"/api/projects/{p['id']}/run").status_code==200
 with mod.db() as d:saved=d.execute('SELECT content FROM project_logs WHERE project_id=?',(p['id'],)).fetchone()
 assert saved and 'RuntimeError' in saved['content'] and any(x and x[0]=='rm' for x in calls)

def test_nested_dependency_file_supports_spaces_without_shell_injection(tmp_path,monkeypatch):
 import runner_worker as worker
 root=tmp_path/'project';nested=root/'source bundle';nested.mkdir(parents=True);req=nested/'requirements.txt';req.write_text('requests==2.32.3\n')
 selected,generated=mod.dependency_spec(root,'source bundle/main.py');assert selected==req and not generated
 rel=selected.relative_to(root).as_posix();assert rel=='source bundle/requirements.txt'
 data=tmp_path/'data';uid='a'*32;pid='b'*32;proj=data/'users'/uid/'projects'/pid;proj.mkdir(parents=True);monkeypatch.setattr(worker,'DATA_ROOT',str(data))
 args=['run','--rm','--network','none','--memory','512m','--memory-swap','512m','--cpus','0.50','--pids-limit','96','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001','--mount',f'type=bind,src={proj},dst=/app,readonly','--mount','type=volume,src=seahost-deps-'+pid[:24]+',dst=/opt/venv','--workdir','/app',worker.os.getenv('RUNNER_IMAGE','python:3.12-slim'),'python','-c',worker.INSTALL_SCRIPT,'/app/'+rel]
 assert worker.allowed(args)
 malicious=args[:-1]+['/app/source bundle/requirements.txt;id']
 assert not worker.allowed(malicious)

def test_runner_allows_only_capped_chown_initialization_container(tmp_path,monkeypatch):
 import runner_worker as worker
 vol='seahost-deps-'+'b'*24
 args=['run','--rm','--network','none','--memory','256m','--memory-swap','256m','--cpus','0.50','--pids-limit','32','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--cap-drop','ALL','--cap-add','CHOWN','--security-opt','no-new-privileges','--user','0:0','--mount',f'type=volume,src={vol},dst=/opt/venv',worker.os.getenv('RUNNER_IMAGE','python:3.12-slim'),'sh','-lc','chown -R 10001:10001 /opt/venv']
 assert worker.allowed(args)
 bad=args.copy();bad[bad.index('--cap-add')+1]='SYS_ADMIN'
 assert not worker.allowed(bad)

def test_expired_stopped_container_and_snapshot_are_pruned(client,monkeypatch):
 import datetime
 uid,_=login(client);p=post(client,'/api/projects',json={'name':'old-crash','entry':'main.py'}).json();monkeypatch.setattr(mod,'LOG_RETENTION_DAYS',1)
 old=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=2)).isoformat().replace('+00:00','Z')
 with mod.db() as d:
  d.execute('UPDATE projects SET started_at=1 WHERE id=?',(p['id'],))
  d.execute('INSERT INTO project_logs(project_id,content,updated) VALUES(?,?,?)',(p['id'],'old log',old))
 calls=[];monkeypatch.setattr(mod,'docker_ok',lambda:True)
 def fake(*args,**kwargs):
  calls.append(args)
  if args[:2]==('inspect','-f') and args[2]=='{{.State.Status}}':return subprocess.CompletedProcess(args,0,'exited','')
  if args[:2]==('inspect','-f') and args[2]=='{{.State.ExitCode}}':return subprocess.CompletedProcess(args,0,'1','')
  if args[:2]==('inspect','-f') and args[2]=='{{.State.FinishedAt}}':return subprocess.CompletedProcess(args,0,old,'')
  return subprocess.CompletedProcess(args,0,'','')
 monkeypatch.setattr(mod,'docker',fake);mod.cleanup_expired_logs_and_containers()
 assert any(args[:1]==('rm',) for args in calls)
 with mod.db() as d:assert d.execute('SELECT 1 FROM project_logs WHERE project_id=?',(p['id'],)).fetchone() is None
