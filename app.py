from __future__ import annotations
import os, re, io, json, time, uuid, shutil, zipfile, hashlib, secrets, sqlite3, subprocess
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

ROOT=Path(__file__).resolve().parent
DATA=Path(os.getenv('HOSTPANEL_DATA_DIR', ROOT/'private-data')).resolve(); DATA.mkdir(parents=True,exist_ok=True)
DB=DATA/'hostpanel.sqlite3'; USERS=DATA/'users'; USERS.mkdir(exist_ok=True)
MAX_FILE=int(os.getenv('MAX_FILE_BYTES',25*1024*1024)); QUOTA=int(os.getenv('USER_QUOTA_BYTES',512*1024*1024)); MAX_PROCS=int(os.getenv('MAX_PROJECTS',5)); DOCKER_IMAGE=os.getenv('RUNNER_IMAGE','python:3.12-slim')
SESSION_COOKIE='hp_session'; app=FastAPI(title='NawaHost API',version='1.0.0')


@contextmanager
def db():
 c=sqlite3.connect(DB,timeout=15); c.row_factory=sqlite3.Row
 try:
  yield c
  c.commit()
 except Exception:
  c.rollback(); raise
 finally:c.close()

def init_db():
 with db() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created TEXT NOT NULL); CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,entry TEXT NOT NULL DEFAULT 'main.py',python TEXT NOT NULL DEFAULT '3.12',created TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,user_id TEXT,action TEXT,detail TEXT,created TEXT);''')
init_db()

def utc(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def pwhash(p,salt=None):
 salt=salt or secrets.token_hex(16); return salt+'$'+hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(salt),310000).hex()
def verify(p,encoded):
 try: s,h=encoded.split('$'); return secrets.compare_digest(hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),310000).hex(),h)
 except ValueError:return False
def event(uid,action,detail=''):
 with db() as c:c.execute('INSERT INTO events(user_id,action,detail,created) VALUES(?,?,?,?)',(uid,action,detail[:300],utc()))
def user_root(uid):
 p=(USERS/uid).resolve()
 if p.parent!=USERS.resolve(): raise HTTPException(400,'Invalid storage path')
 p.mkdir(parents=True,exist_ok=True); return p
def used_space(uid): return sum(f.stat().st_size for f in user_root(uid).rglob('*') if f.is_file())
def safe_path(uid,rel=''):
 rel=rel or ''; p=(user_root(uid)/rel).resolve()
 if p!=user_root(uid) and user_root(uid) not in p.parents: raise HTTPException(400,'Invalid path')
 return p
def current_user(request:Request):
 tok=request.cookies.get(SESSION_COOKIE)
 if not tok: raise HTTPException(401,'يرجى تسجيل الدخول')
 with db() as c:
  row=c.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?',(tok,int(time.time()))).fetchone()
 if not row: raise HTTPException(401,'انتهت الجلسة؛ سجّل الدخول مجددًا')
 return dict(row)
def get_project(uid,pid):
 with db() as c:r=c.execute('SELECT * FROM projects WHERE id=? AND user_id=?',(pid,uid)).fetchone()
 if not r: raise HTTPException(404,'المشروع غير موجود')
 return dict(r)
def project_path(uid,pid): return safe_path(uid,'projects/'+pid)
def docker_ok():
 try:return subprocess.run(['docker','info'],capture_output=True,timeout=4).returncode==0
 except Exception:return False
class Credentials(BaseModel): email:str; password:str
class ProjectInput(BaseModel): name:str; entry:str='main.py'; python:str='3.12'
class PathInput(BaseModel): path:str; name:Optional[str]=None; destination:Optional[str]=None
class EntryInput(BaseModel): entry:str

@app.get('/api/health')
def health(): return {'status':'ok','docker_available':docker_ok(),'runner':'Docker (isolated)' if docker_ok() else 'unavailable','python_versions':['3.12']}
@app.post('/api/register')
def register(data:Credentials,response:JSONResponse):
 email=data.email.strip().lower()
 if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+',email) or len(data.password)<10: raise HTTPException(400,'أدخل بريدًا صحيحًا وكلمة مرور من 10 أحرف على الأقل')
 uid=uuid.uuid4().hex
 with db() as c:
  count=c.execute('SELECT COUNT(*) n FROM users').fetchone()['n']
  try:c.execute('INSERT INTO users VALUES(?,?,?,?,?)',(uid,email,pwhash(data.password),'admin' if count==0 else 'user',utc()))
  except sqlite3.IntegrityError: raise HTTPException(409,'هذا البريد مسجّل بالفعل')
 user_root(uid); event(uid,'register',email)
 token=secrets.token_urlsafe(32)
 with db() as c:c.execute('INSERT INTO sessions VALUES(?,?,?)',(token,uid,int(time.time())+86400*7))
 response.set_cookie(SESSION_COOKIE,token,httponly=True,samesite='lax',secure=os.getenv('COOKIE_SECURE','0')=='1',max_age=604800)
 return {'id':uid,'email':email,'role':'admin' if count==0 else 'user'}
@app.post('/api/login')
def login(data:Credentials,response:JSONResponse):
 with db() as c:r=c.execute('SELECT * FROM users WHERE email=?',(data.email.strip().lower(),)).fetchone()
 if not r or not verify(data.password,r['password']): raise HTTPException(401,'البريد أو كلمة المرور غير صحيحة')
 tok=secrets.token_urlsafe(32)
 with db() as c:c.execute('INSERT INTO sessions VALUES(?,?,?)',(tok,r['id'],int(time.time())+604800))
 response.set_cookie(SESSION_COOKIE,tok,httponly=True,samesite='lax',secure=os.getenv('COOKIE_SECURE','0')=='1',max_age=604800)
 return {'id':r['id'],'email':r['email'],'role':r['role']}
@app.post('/api/logout')
def logout(request:Request,response:JSONResponse):
 tok=request.cookies.get(SESSION_COOKIE)
 with db() as c:c.execute('DELETE FROM sessions WHERE token=?',(tok,))
 response.delete_cookie(SESSION_COOKIE); return {'ok':True}
@app.get('/api/me')
def me(u=Depends(current_user)): return {k:u[k] for k in ('id','email','role','created')}

@app.get('/api/dashboard')
def dashboard(u=Depends(current_user)):
 uid=u['id']; projects=[]
 with db() as c: rows=c.execute('SELECT * FROM projects WHERE user_id=? ORDER BY created DESC',(uid,)).fetchall()
 for r in rows:
  p=dict(r); p.update(status=proc_status(p['id']),pid=process_pid(p['id']),uptime=process_uptime(p['id'])); projects.append(p)
 return {'projects':projects,'files':file_tree(uid),'storage':{'used':used_space(uid),'quota':QUOTA},'limits':{'projects':MAX_PROCS,'max_file':MAX_FILE},'runner':docker_ok(),'python_versions':['3.12'],'user':{'email':u['email'],'role':u['role']}}

def file_tree(uid,rel=''):
 base=safe_path(uid,rel)
 if not base.exists(): return []
 out=[]
 for f in sorted(base.iterdir(),key=lambda x:(not x.is_dir(),x.name.lower())):
  st=f.stat(); out.append({'name':f.name,'path':str((Path(rel)/f.name).as_posix()).lstrip('./'),'directory':f.is_dir(),'size':st.st_size if f.is_file() else 0,'modified':datetime.fromtimestamp(st.st_mtime,timezone.utc).isoformat(),'type':f.suffix.lower() or ('folder' if f.is_dir() else 'file')})
 return out
@app.get('/api/files')
def files(path:str='',u=Depends(current_user)): return {'items':file_tree(u['id'],path),'used':used_space(u['id']),'quota':QUOTA}
@app.post('/api/upload')
async def upload(files:list[UploadFile]=File(...),path:str=Form(''),u=Depends(current_user)):
 dest=safe_path(u['id'],path)
 if not dest.is_dir(): raise HTTPException(400,'المجلد المحدد غير موجود')
 results=[]
 for f in files:
  name=Path(f.filename or '').name
  if not name or name in ('.','..') or Path(name).suffix.lower() not in ('.py','.zip','.txt','.json','.md','.toml','.yml','.yaml'): raise HTTPException(400,f'امتداد غير مسموح: {name}')
  target=dest/name
  if target.exists(): raise HTTPException(409,f'الملف موجود بالفعل: {name}')
  data=await f.read(MAX_FILE+1)
  if len(data)>MAX_FILE: raise HTTPException(413,f'تجاوز الملف حد {MAX_FILE} بايت')
  if used_space(u['id'])+len(data)>QUOTA: raise HTTPException(413,'انتهت المساحة التخزينية المتاحة')
  if target.suffix.lower()!='.zip' and b'\x00' in data[:4096]: raise HTTPException(400,'تم رفض ملف ثنائي غير مسموح')
  target.write_bytes(data)
  if target.suffix.lower()=='.zip':
   try: zip_preview(data)
   except Exception: target.unlink(missing_ok=True); raise
  results.append({'name':name,'size':len(data)})
 event(u['id'],'upload',','.join(x['name'] for x in results));return {'uploaded':results}
def zip_preview(data):
 try:z=zipfile.ZipFile(io.BytesIO(data))
 except zipfile.BadZipFile: raise HTTPException(400,'ملف ZIP تالف أو غير صالح')
 entries=z.infolist()
 if len(entries)>2000:raise HTTPException(413,'الأرشيف يتجاوز 2000 ملف')
 total=0; clean=[]
 for x in entries:
  p=PurePosixPath(x.filename)
  if p.is_absolute() or '..' in p.parts or '\\' in x.filename or (p.parts and ':' in p.parts[0]):raise HTTPException(400,'مسار غير آمن داخل ZIP')
  if x.flag_bits&1:raise HTTPException(400,'الأرشيف المشفر غير مدعوم')
  total+=x.file_size
  if x.file_size>MAX_FILE or total>MAX_FILE*20:raise HTTPException(413,'الأرشيف مفكوك الضغط أكبر من الحد الآمن')
  clean.append({'name':x.filename,'size':x.file_size,'directory':x.is_dir()})
 return clean
@app.get('/api/zip/inspect')
def inspect_zip(path:str,u=Depends(current_user)):
 p=safe_path(u['id'],path)
 if not p.is_file() or p.suffix.lower()!='.zip':raise HTTPException(400,'اختر ملف ZIP صالحًا')
 return {'items':zip_preview(p.read_bytes()),'entry_candidates':[x['name'] for x in zip_preview(p.read_bytes()) if x['name'].rsplit('/',1)[-1] in ('main.py','bot.py','app.py')]}
@app.post('/api/zip/extract')
def extract_zip(data:PathInput,u=Depends(current_user)):
 src=safe_path(u['id'],data.path)
 if not src.is_file() or src.suffix.lower()!='.zip':raise HTTPException(400,'اختر ZIP صالحًا')
 entries=zip_preview(src.read_bytes()); outname=data.name or src.stem
 expanded=sum(x['size'] for x in entries)
 if used_space(u['id'])+expanded>QUOTA:raise HTTPException(413,'المساحة المتبقية لا تكفي لفك الأرشيف')
 if not re.fullmatch(r'[\w .-]{1,80}',outname) or outname in ('.','..'):raise HTTPException(400,'اسم مجلد غير صالح')
 dest=safe_path(u['id'],outname)
 if dest.exists():raise HTTPException(409,'المجلد موجود بالفعل')
 dest.mkdir()
 try:
  with zipfile.ZipFile(src) as z:
   for info in z.infolist():
    if info.is_dir():continue
    target=(dest/info.filename).resolve()
    if dest.resolve() not in target.parents:raise HTTPException(400,'مسار استخراج غير آمن')
    target.parent.mkdir(parents=True,exist_ok=True)
    with z.open(info) as r, target.open('wb') as w:shutil.copyfileobj(r,w,length=1024*1024)
 except Exception:shutil.rmtree(dest,ignore_errors=True);raise
 event(u['id'],'extract',outname);return {'path':outname,'items':len(entries)}
@app.get('/api/file')
def read_file(path:str,u=Depends(current_user)):
 p=safe_path(u['id'],path)
 if not p.is_file():raise HTTPException(404,'الملف غير موجود')
 if p.stat().st_size>2*1024*1024:raise HTTPException(413,'المعاينة متاحة للملفات حتى 2MB')
 try:return {'content':p.read_text(encoding='utf-8')}
 except UnicodeError:raise HTTPException(415,'هذا الملف ليس نصًا قابلًا للمعاينة')
class SaveInput(BaseModel): path:str; content:str
@app.put('/api/file')
def save_file(data:SaveInput,u=Depends(current_user)):
 p=safe_path(u['id'],data.path)
 if not p.is_file() or len(data.content.encode())>MAX_FILE:raise HTTPException(400,'مسار أو حجم غير صالح')
 p.write_text(data.content,encoding='utf-8');return {'saved':True}
@app.get('/api/download')
def download(path:str,u=Depends(current_user)):
 p=safe_path(u['id'],path)
 if not p.is_file():raise HTTPException(404,'الملف غير موجود')
 return FileResponse(p,filename=p.name)
@app.post('/api/folder')
def folder(data:PathInput,u=Depends(current_user)):
 name=data.name or ''
 if not re.fullmatch(r'[\w .-]{1,80}',name) or name in ('.','..'):raise HTTPException(400,'اسم المجلد غير صالح')
 p=safe_path(u['id'],str(Path(data.path)/name));p.mkdir(parents=True,exist_ok=False);return {'created':True}
@app.post('/api/files/rename')
def rename(data:PathInput,u=Depends(current_user)):
 p=safe_path(u['id'],data.path); name=data.name or ''
 if not p.exists() or not re.fullmatch(r'[\w .-]{1,120}',name) or name in ('.','..'):raise HTTPException(400,'اسم غير صالح')
 q=safe_path(u['id'],str(p.parent.relative_to(user_root(u['id']))/name));p.rename(q);return {'renamed':True}
@app.post('/api/files/action/{operation}')
def file_operation(operation:str,data:PathInput,u=Depends(current_user)):
 if operation not in ('copy','move'):raise HTTPException(404,'عملية غير مدعومة')
 src=safe_path(u['id'],data.path); destdir=safe_path(u['id'],data.destination or '')
 if not src.exists() or not destdir.is_dir():raise HTTPException(400,'المصدر أو مجلد الوجهة غير صالح')
 if src.is_dir() and (destdir==src or src in destdir.parents):raise HTTPException(400,'لا يمكن وضع المجلد داخل نفسه')
 target=destdir/src.name
 if target.exists():raise HTTPException(409,'يوجد عنصر بالاسم نفسه في الوجهة')
 size=sum(f.stat().st_size for f in src.rglob('*') if f.is_file()) if src.is_dir() else src.stat().st_size
 if operation=='copy' and used_space(u['id'])+size>QUOTA:raise HTTPException(413,'المساحة غير كافية لنسخ العنصر')
 if operation=='move':shutil.move(str(src),str(target))
 elif src.is_dir():shutil.copytree(src,target)
 else:shutil.copy2(src,target)
 return {operation+'d':True}
@app.post('/api/files/delete')
def delete_file(data:PathInput,u=Depends(current_user)):
 p=safe_path(u['id'],data.path)
 if not p.exists():raise HTTPException(404,'غير موجود')
 shutil.rmtree(p) if p.is_dir() else p.unlink();event(u['id'],'delete',data.path);return {'deleted':True}
@app.post('/api/zip/create')
def create_zip(data:PathInput,u=Depends(current_user)):
 src=safe_path(u['id'],data.path)
 if not src.is_dir():raise HTTPException(400,'اختر مجلدًا')
 target=safe_path(u['id'],data.name or (src.name+'.zip'))
 if target.suffix.lower()!='.zip' or target.exists():raise HTTPException(400,'اسم ZIP غير صالح أو موجود')
 with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED) as z:
  for f in src.rglob('*'):
   if f.is_file():z.write(f,f.relative_to(src.parent))
 return {'path':str(target.relative_to(user_root(u['id'])))}

@app.post('/api/projects')
def create_project(data:ProjectInput,u=Depends(current_user)):
 name=data.name.strip()
 if not re.fullmatch(r'[\w .-]{1,64}',name):raise HTTPException(400,'اسم المشروع غير صالح')
 if data.python!='3.12':raise HTTPException(400,'إصدار Python المطلوب غير متاح على هذا الخادم')
 pid=uuid.uuid4().hex
 with db() as c:
  if c.execute('SELECT COUNT(*) n FROM projects WHERE user_id=?',(u['id'],)).fetchone()['n']>=MAX_PROCS:raise HTTPException(429,'بلغت الحد الأقصى لعدد المشاريع')
  c.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',(pid,u['id'],name,data.entry, data.python,utc()))
 pp=project_path(u['id'],pid); pp.mkdir(parents=True,exist_ok=True)
 event(u['id'],'project_create',name);return {'id':pid,'name':name,'entry':data.entry,'status':'Stopped'}
@app.get('/api/projects')
def projects(u=Depends(current_user)):
 with db() as c:rows=c.execute('SELECT * FROM projects WHERE user_id=?',(u['id'],)).fetchall()
 return [dict(r, status=proc_status(r['id']),pid=process_pid(r['id'])) for r in rows]
@app.post('/api/projects/{pid}/entry')
def set_entry(pid:str,data:EntryInput,u=Depends(current_user)):
 p=get_project(u['id'],pid); entry=data.entry
 if not re.fullmatch(r'[\w./-]+\.py',entry) or '..' in Path(entry).parts:raise HTTPException(400,'مسار ملف التشغيل غير صالح')
 if not (project_path(u['id'],pid)/entry).is_file():raise HTTPException(404,'ملف التشغيل غير موجود')
 with db() as c:c.execute('UPDATE projects SET entry=? WHERE id=?',(entry,pid))
 return {'entry':entry}
def container_name(pid): return 'nawahost-'+re.sub('[^a-f0-9]','',pid)[:24]
def docker(*args,timeout=15):return subprocess.run(['docker',*args],capture_output=True,text=True,timeout=timeout)
def proc_status(pid):
 if not docker_ok():return 'Unavailable'
 try:r=docker('inspect','-f','{{.State.Status}}',container_name(pid),timeout=5);return r.stdout.strip() if r.returncode==0 else 'Stopped'
 except Exception:return 'Error'
def process_pid(pid):
 if not docker_ok():return None
 try:r=docker('inspect','-f','{{.State.Pid}}',container_name(pid),timeout=5);n=int(r.stdout.strip());return n or None if r.returncode==0 else None
 except Exception:return None
def process_uptime(pid):
 if not docker_ok():return None
 try:r=docker('inspect','-f','{{.State.StartedAt}}',container_name(pid),timeout=5);return r.stdout.strip() if r.returncode==0 else None
 except Exception:return None
@app.post('/api/projects/{pid}/run')
def run_project(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid);root=project_path(u['id'],pid);entry=root/p['entry']
 if not docker_ok():raise HTTPException(503,'مشغّل Docker غير متاح على هذا الخادم. لم يتم تشغيل كود المشروع.')
 if not entry.is_file():raise HTTPException(400,'ملف التشغيل غير موجود: '+p['entry'])
 if proc_status(pid) in ('running','restarting'):raise HTTPException(409,'المشروع يعمل بالفعل')
 # Runtime container has no network, no capabilities, non-root identity, bounded CPU/RAM/PIDs and read-only source.
 try:
  docker('rm','-f',container_name(pid),timeout=8)
  r=docker('run','-d','--name',container_name(pid),'--label','nawahost.owner='+u['id'],'--network','none','--memory','256m','--memory-swap','256m','--cpus','0.50','--pids-limit','128','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001','--mount',f'type=bind,src={root.resolve()},dst=/app,readonly','--workdir','/app',DOCKER_IMAGE,'python','-u',p['entry'],timeout=20)
  if r.returncode: raise HTTPException(503,'تعذر إنشاء الحاوية: '+(r.stderr or '')[:500])
 except subprocess.TimeoutExpired:raise HTTPException(504,'انتهت مهلة تشغيل المشروع')
 event(u['id'],'project_start',p['name']);return {'status':'Running','container':container_name(pid)}
@app.post('/api/projects/{pid}/stop')
def stop_project(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid)
 if not docker_ok():raise HTTPException(503,'مشغّل Docker غير متاح')
 try:r=docker('stop','--time','4',container_name(pid),timeout=8)
 except subprocess.TimeoutExpired:raise HTTPException(504,'تعذر إيقاف المشروع ضمن المهلة')
 if r.returncode and 'No such container' not in r.stderr:raise HTTPException(500,(r.stderr or 'فشل الإيقاف')[:300])
 event(u['id'],'project_stop',p['name']);return {'status':'Stopped'}
@app.post('/api/projects/{pid}/restart')
def restart(pid:str,u=Depends(current_user)):
 try: stop_project(pid,u)
 except HTTPException as e:
  if e.status_code not in (409,):raise
 return run_project(pid,u)
@app.get('/api/projects/{pid}/logs')
def logs(pid:str,tail:int=200,u=Depends(current_user)):
 p=get_project(u['id'],pid)
 if not docker_ok():return {'logs':'','status':'Unavailable','message':'Docker غير متاح؛ لا توجد سجلات تشغيل'}
 try:r=docker('logs','--tail',str(max(1,min(tail,2000))),container_name(pid),timeout=6)
 except subprocess.TimeoutExpired:raise HTTPException(504,'انتهت مهلة جلب السجلات')
 return {'logs':(r.stdout+'\n'+r.stderr)[-200000:],'status':proc_status(pid)}
@app.delete('/api/projects/{pid}')
def delete_project(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid)
 if docker_ok():
  try:docker('rm','-f',container_name(pid),timeout=8)
  except Exception:pass
 shutil.rmtree(project_path(u['id'],pid),ignore_errors=True)
 with db() as c:c.execute('DELETE FROM projects WHERE id=? AND user_id=?',(pid,u['id']))
 event(u['id'],'project_delete',p['name']);return {'deleted':True}
@app.get('/api/admin/users')
def admin_users(u=Depends(current_user)):
 if u['role']!='admin':raise HTTPException(403,'غير مصرح')
 with db() as c: rows=c.execute('SELECT id,email,role,created FROM users ORDER BY created DESC').fetchall()
 return [{'id':r['id'],'email':r['email'],'role':r['role'],'created':r['created'],'used':used_space(r['id'])} for r in rows]
@app.get('/api/admin/events')
def admin_events(u=Depends(current_user)):
 if u['role']!='admin':raise HTTPException(403,'غير مصرح')
 with db() as c:rows=c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 200').fetchall()
 return [dict(r) for r in rows]
@app.get('/api/admin/resources')
def admin_resources(u=Depends(current_user)):
 if u['role']!='admin':raise HTTPException(403,'غير مصرح')
 actual={'docker_available':docker_ok(),'disk_bytes':shutil.disk_usage(DATA).total,'disk_free_bytes':shutil.disk_usage(DATA).free}
 if docker_ok():
  try:r=docker('stats','--no-stream','--format','{{json .}}',timeout=8);actual['docker_stats']=[json.loads(x) for x in r.stdout.splitlines() if x]
  except Exception:actual['docker_stats_error']='Could not read container stats'
 else:actual['note']='قياسات موارد الحاويات غير متاحة من Docker في هذه البيئة'
 return actual

app.mount('/',StaticFiles(directory=ROOT/'static',html=True),name='static')
