import io, os, zipfile, uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
import app as mod

@pytest.fixture
def env(tmp_path,monkeypatch):
 monkeypatch.setattr(mod,'DATA',tmp_path/'data');mod.DATA.mkdir()
 monkeypatch.setattr(mod,'DB',mod.DATA/'test.sqlite3')
 monkeypatch.setattr(mod,'USERS',mod.DATA/'users');mod.USERS.mkdir()
 monkeypatch.setattr(mod,'MAX_FILE',1024*1024);monkeypatch.setattr(mod,'QUOTA',4*1024*1024)
 mod.init_db()
 with TestClient(mod.app) as client: yield client

def register(c,email):
 r=c.post('/api/register',json={'email':email,'password':'safe-password-123'});assert r.status_code==200;return r.json()
def zipped(items):
 b=io.BytesIO()
 with zipfile.ZipFile(b,'w') as z:
  for name,value in items.items():z.writestr(name,value)
 return b.getvalue()
def test_auth_and_private_file_isolation(env):
 a=env;b=TestClient(mod.app)
 ua=register(a,'one@example.com');register(b,'two@example.com')
 assert ua['role']=='admin'
 assert a.get('/api/me').status_code==200
 assert b.get('/api/download?path=secret.py').status_code==404
 assert a.get('/api/admin/users').status_code==200
 assert b.get('/api/admin/users').status_code==403

def test_upload_python_preview_save_download(env):
 c=env;register(c,'one@example.com')
 r=c.post('/api/upload',files=[('files',('main.py',b'print("hi")','text/x-python'))]);assert r.status_code==200
 assert c.get('/api/file?path=main.py').json()['content']=='print("hi")'
 assert c.put('/api/file',json={'path':'main.py','content':'print("updated")'}).json()['saved']
 assert c.get('/api/download?path=main.py').content==b'print("updated")'

def test_zip_extract_and_zip_slip(env):
 c=env;register(c,'zip@example.com')
 data=zipped({'demo/main.py':'print(1)','demo/requirements.txt':'requests'})
 assert c.post('/api/upload',files=[('files',('demo.zip',data,'application/zip'))]).status_code==200
 assert any('main.py' in x['name'] for x in c.get('/api/zip/inspect?path=demo.zip').json()['items'])
 assert c.post('/api/zip/extract',json={'path':'demo.zip','name':'project'}).status_code==200
 assert c.get('/api/file?path=project/demo/main.py').json()['content']=='print(1)'
 evil=zipped({'../../outside.txt':'bad'})
 assert c.post('/api/upload',files=[('files',('evil.zip',evil,'application/zip'))]).status_code==400
 assert not (mod.DATA/'outside.txt').exists()

def test_invalid_upload_and_missing_entry(env,monkeypatch):
 c=env;register(c,'failure@example.com')
 assert c.post('/api/upload',files=[('files',('run.exe',b'MZ','application/octet-stream'))]).status_code==400
 p=c.post('/api/projects',json={'name':'broken','entry':'missing.py','python':'3.12'}).json()
 monkeypatch.setattr(mod,'docker_ok',lambda:True)
 assert c.post(f"/api/projects/{p['id']}/run").status_code==400

def test_project_lifecycle_is_explicitly_unavailable_without_docker(env,monkeypatch):
 c=env;register(c,'runner@example.com')
 p=c.post('/api/projects',json={'name':'bot','entry':'main.py','python':'3.12'}).json()
 assert c.get('/api/projects').status_code==200
 assert c.post(f"/api/projects/{p['id']}/run").status_code==503
 assert 'لم يتم تشغيل كود المشروع' in c.post(f"/api/projects/{p['id']}/run").json()['detail']
 assert c.get(f"/api/projects/{p['id']}/logs").json()['status']=='Unavailable'

def test_path_traversal_and_empty_root_listing(env):
 c=env;register(c,'paths@example.com')
 assert c.get('/api/files').json()['items']==[]
 assert c.get('/api/file?path=../../etc/passwd').status_code==400
