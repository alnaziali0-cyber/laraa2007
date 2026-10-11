from __future__ import annotations
import os, re, io, json, time, uuid, shutil, zipfile, hashlib, hmac, secrets, sqlite3, subprocess, smtplib, ast, tomllib, urllib.request, urllib.error, urllib.parse, threading
from contextlib import contextmanager, asynccontextmanager
from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional
from fastapi import FastAPI, Request, UploadFile, File, HTTPException, Depends, Form, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

ROOT=Path(__file__).resolve().parent
load_dotenv(ROOT/'.env')
DATA=Path(os.getenv('HOSTPANEL_DATA_DIR', ROOT/'private-data')).resolve(); DATA.mkdir(parents=True,exist_ok=True)
DB=DATA/'hostpanel.sqlite3'; USERS=DATA/'users'; USERS.mkdir(exist_ok=True)
MAX_FILE=int(os.getenv('MAX_FILE_BYTES',25*1024*1024)); QUOTA=int(os.getenv('USER_QUOTA_BYTES',512*1024*1024)); MAX_PROCS=int(os.getenv('MAX_PROJECTS',5)); MAX_RUNNING=int(os.getenv('MAX_RUNNING_PROJECTS',3)); DOCKER_IMAGE=os.getenv('RUNNER_IMAGE','python:3.12-slim')
LOG_RETENTION_DAYS=max(1,min(365,int(os.getenv('LOG_RETENTION_DAYS','7'))))
OWNER_EMAIL=os.getenv('OWNER_EMAIL','aaaq70232@gmail.com').strip().lower()
SESSION_COOKIE='hp_session'; CHALLENGE_COOKIE='hp_challenge'; CSRF_COOKIE='hp_csrf'; PH=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=2)
_log_cleanup_stop=threading.Event();_log_cleanup_thread=None
@asynccontextmanager
async def lifespan(_app):
 global _log_cleanup_thread
 if _log_cleanup_thread is None or not _log_cleanup_thread.is_alive():
  _log_cleanup_stop.clear();_log_cleanup_thread=threading.Thread(target=_log_cleanup_loop,daemon=True,name='seahost-log-retention');_log_cleanup_thread.start()
 try:yield
 finally:
  _log_cleanup_stop.set()
  if _log_cleanup_thread and _log_cleanup_thread.is_alive():_log_cleanup_thread.join(timeout=5)
app=FastAPI(title='Sea Host API',version='2.0.0',lifespan=lifespan)

@contextmanager
def db():
 c=sqlite3.connect(DB,timeout=20); c.row_factory=sqlite3.Row
 try: yield c; c.commit()
 except Exception: c.rollback(); raise
 finally: c.close()

def utc():return datetime.now(timezone.utc).isoformat(timespec='seconds')
def init_db():
 with db() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created TEXT NOT NULL); CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id TEXT NOT NULL,expires INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,name TEXT NOT NULL,entry TEXT NOT NULL DEFAULT '',python TEXT NOT NULL DEFAULT '3.12',created TEXT NOT NULL,operation TEXT NOT NULL DEFAULT '',started_at INTEGER,stopped_at INTEGER); CREATE TABLE IF NOT EXISTS project_logs(project_id TEXT PRIMARY KEY,content TEXT NOT NULL,updated TEXT NOT NULL); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,user_id TEXT,action TEXT,detail TEXT,created TEXT); CREATE TABLE IF NOT EXISTS otp_challenges(id TEXT PRIMARY KEY,email TEXT NOT NULL,code_hash TEXT NOT NULL,expires INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,used INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY,scope TEXT NOT NULL,created INTEGER NOT NULL);''')
  cols={r['name'] for r in c.execute('PRAGMA table_info(projects)')}
  if 'operation' not in cols:c.execute("ALTER TABLE projects ADD COLUMN operation TEXT NOT NULL DEFAULT ''")
  if 'started_at' not in cols:c.execute('ALTER TABLE projects ADD COLUMN started_at INTEGER')
  if 'stopped_at' not in cols:c.execute('ALTER TABLE projects ADD COLUMN stopped_at INTEGER')
  c.execute("UPDATE projects SET operation='' WHERE operation!=''")
  cutoff=(datetime.now(timezone.utc).timestamp()-LOG_RETENTION_DAYS*86400)
  c.execute('DELETE FROM project_logs WHERE updated<?',(datetime.fromtimestamp(cutoff,timezone.utc).isoformat(timespec='seconds'),))
init_db()
def event(uid,action,detail=''):
 with db() as c:c.execute('INSERT INTO events(user_id,action,detail,created) VALUES(?,?,?,?)',(uid,action,detail[:300],utc()))
def user_root(uid):
 p=(USERS/uid).resolve()
 if p.parent!=USERS.resolve():raise HTTPException(400,'مسار تخزين غير صالح')
 p.mkdir(parents=True,exist_ok=True);return p
def used_space(uid):return sum(f.stat().st_size for f in user_root(uid).rglob('*') if f.is_file())
def safe_path(uid,rel=''):
 p=(user_root(uid)/(rel or '')).resolve()
 if p!=user_root(uid) and user_root(uid) not in p.parents:raise HTTPException(400,'مسار غير مسموح')
 return p
def hash_token(x):return hashlib.sha256(x.encode()).hexdigest()
def current_user(request:Request):
 raw=request.cookies.get(SESSION_COOKIE)
 if not raw:raise HTTPException(401,'يلزم تسجيل الدخول')
 if request.method not in ('GET','HEAD','OPTIONS'):
  cookie=request.cookies.get(CSRF_COOKIE,''); header=request.headers.get('x-csrf-token','')
  if not cookie or not header or not secrets.compare_digest(cookie,header):raise HTTPException(403,'فشل التحقق من الطلب؛ حدّث الصفحة وحاول مجددًا')
 with db() as c:r=c.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>?',(hash_token(raw),int(time.time()))).fetchone()
 if not r or r['email'].lower()!=OWNER_EMAIL:raise HTTPException(401,'انتهت الجلسة؛ سجّل الدخول مجددًا')
 return dict(r)
def get_project(uid,pid):
 with db() as c:r=c.execute('SELECT * FROM projects WHERE id=? AND user_id=?',(pid,uid)).fetchone()
 if not r:raise HTTPException(404,'المشروع غير موجود')
 return dict(r)
def reserve_project_operation(uid,pid,operation):
 with db() as c:
  c.execute('BEGIN IMMEDIATE');r=c.execute('SELECT operation FROM projects WHERE id=? AND user_id=?',(pid,uid)).fetchone()
  if not r:raise HTTPException(404,'المشروع غير موجود')
  if r['operation']:raise HTTPException(409,'توجد عملية أخرى جارية للمشروع')
  c.execute('UPDATE projects SET operation=? WHERE id=? AND user_id=?',(operation,pid,uid))
def release_project_operation(uid,pid,operation):
 with db() as c:c.execute('UPDATE projects SET operation=\'\' WHERE id=? AND user_id=? AND operation=?',(pid,uid,operation))
def project_path(uid,pid):return safe_path(uid,'projects/'+pid)
def docker_ok():
 try:return docker('info',timeout=4).returncode==0
 except Exception:return False
def env_status():
 appkey=os.getenv('APP_SECRET_KEY','')
 smtp=bool(os.getenv('SMTP_HOST') and os.getenv('SMTP_USERNAME') and os.getenv('SMTP_PASSWORD') and not os.getenv('SMTP_PASSWORD','').startswith('REPLACE_') and (os.getenv('SMTP_FROM') or os.getenv('SMTP_USERNAME')) and len(appkey.encode())>=32 and not appkey.startswith('REPLACE_'))
 captcha=bool(os.getenv('TURNSTILE_SECRET_KEY') and os.getenv('TURNSTILE_SITE_KEY'))
 return {'smtp_configured':smtp,'captcha_configured':captcha,'captcha_requested':bool(os.getenv('TURNSTILE_SECRET_KEY') or os.getenv('TURNSTILE_SITE_KEY'))}
def validate_captcha(token,ip):
 cfg=env_status()
 if cfg['captcha_requested'] and not cfg['captcha_configured']:raise HTTPException(503,'تهيئة CAPTCHA غير مكتملة؛ لم يُتحقق من تسجيل الدخول.')
 if not cfg['captcha_configured']:return
 if not token:raise HTTPException(400,'أكمل اختبار التحقق البشري.')
 payload=urllib.parse.urlencode({'secret':os.environ['TURNSTILE_SECRET_KEY'],'response':token,'remoteip':ip or ''}).encode()
 req=urllib.request.Request('https://challenges.cloudflare.com/turnstile/v0/siteverify',data=payload,headers={'Content-Type':'application/x-www-form-urlencoded'},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=6) as r:valid=json.loads(r.read()).get('success') is True
 except Exception:raise HTTPException(503,'تعذر التحقق من CAPTCHA؛ حاول لاحقًا.')
 if not valid:raise HTTPException(401,'تعذر التحقق من بيانات الدخول.')
def send_otp(recipient,code):
 cfg=env_status()
 if not cfg['smtp_configured']:raise RuntimeError('تهيئة البريد غير مكتملة')
 host=os.environ['SMTP_HOST']; port=int(os.getenv('SMTP_PORT','587')); user=os.environ['SMTP_USERNAME']; password=os.environ['SMTP_PASSWORD']; sender=os.getenv('SMTP_FROM',user)
 msg=EmailMessage();msg['Subject']='رمز تسجيل الدخول إلى Sea Host';msg['From']=sender;msg['To']=recipient
 msg.set_content(f'رمز التحقق الخاص بك هو: {code}\nتنتهي صلاحيته خلال 5 دقائق. إذا لم تطلبه فتجاهل الرسالة.')
 if port==465:
  with smtplib.SMTP_SSL(host,port,timeout=12) as s:s.login(user,password);s.send_message(msg)
 else:
  with smtplib.SMTP(host,port,timeout=12) as s:s.ehlo();s.starttls();s.ehlo();s.login(user,password);s.send_message(msg)
def add_login_attempt(scope):
 with db() as c:
  now=int(time.time());c.execute('DELETE FROM login_attempts WHERE created<?',(now-900,));c.execute('INSERT INTO login_attempts(scope,created) VALUES(?,?)',(scope,now))
  return c.execute('SELECT COUNT(*) FROM login_attempts WHERE scope=? AND created>?',(scope,now-900)).fetchone()[0]
def create_session(user_id,response):
 raw=secrets.token_urlsafe(32);csrf=secrets.token_urlsafe(32);secure=os.getenv('COOKIE_SECURE','0')=='1';same='none' if secure else 'lax'
 with db() as c:
  c.execute('DELETE FROM sessions WHERE user_id=? OR expires<?',(user_id,int(time.time())))
  c.execute('INSERT INTO sessions VALUES(?,?,?)',(hash_token(raw),user_id,int(time.time())+8*3600))
 response.set_cookie(SESSION_COOKIE,raw,httponly=True,secure=secure,samesite=same,max_age=28800)
 response.set_cookie(CSRF_COOKIE,csrf,httponly=False,secure=secure,samesite=same,max_age=28800)
 response.delete_cookie(CHALLENGE_COOKIE,secure=secure,samesite=same)

class Credentials(BaseModel):email:str;password:str;captcha_token:str=''
class VerifyInput(BaseModel):code:str
class ProjectInput(BaseModel):name:str;entry:str='';python:str='3.12'
class PathInput(BaseModel):path:str;name:Optional[str]=None;destination:Optional[str]=None
class EntryInput(BaseModel):entry:str
class SaveInput(BaseModel):path:str;content:str

@app.get('/api/health')
def health():return {'status':'ok','docker_available':docker_ok(),'runner':'Docker' if docker_ok() else 'unavailable','python_versions':['3.12'],'mail_ready':env_status()['smtp_configured'],'captcha_ready':env_status()['captcha_configured']}
@app.get('/api/settings')
def settings(u=Depends(current_user)):
 with db() as c:count=c.execute('SELECT COUNT(*) FROM projects WHERE user_id=?',(u['id'],)).fetchone()[0]
 cfg=env_status()
 return {'owner_email':u['email'],'smtp_ready':cfg['smtp_configured'],'smtp_host':os.getenv('SMTP_HOST','not configured') if cfg['smtp_configured'] else None,'captcha_ready':cfg['captcha_configured'],'captcha_incomplete':cfg['captcha_requested'] and not cfg['captcha_configured'],'https_cookie':os.getenv('COOKIE_SECURE','0')=='1','runner_ready':docker_ok(),'python':'3.12','projects':count,'max_projects':MAX_PROCS,'max_running':MAX_RUNNING,'storage_quota_bytes':QUOTA,'max_upload_bytes':MAX_FILE,'build_network':os.getenv('RUNNER_BUILD_NETWORK','none'),'session_hours':8}
@app.get('/api/auth/config')
def auth_config():
 local,_,domain=OWNER_EMAIL.partition('@');hint=(local[:1]+'***@'+domain) if domain else 'مالك الحساب'
 return {'captcha_required':env_status()['captcha_configured'],'captcha_incomplete':env_status()['captcha_requested'] and not env_status()['captcha_configured'],'captcha_site_key':os.getenv('TURNSTILE_SITE_KEY','') if env_status()['captcha_configured'] else '', 'owner_email_hint':hint}
@app.post('/api/login')
def login(data:Credentials,request:Request,response:Response):
 ip=request.client.host if request.client else 'unknown';email=data.email.strip().lower();scope=hash_token(ip)
 with db() as c:
  n=c.execute('SELECT COUNT(*) FROM login_attempts WHERE scope=? AND created>?',(scope,int(time.time())-900)).fetchone()[0]
 if n>=5:raise HTTPException(429,'محاولات كثيرة. حاول بعد 15 دقيقة.')
 add_login_attempt(scope)
 validate_captcha(data.captcha_token,ip)
 if not env_status()['smtp_configured']:raise HTTPException(503,'إعداد خدمة التحقق بالبريد غير مكتمل؛ لم يُرسل أي رمز.')
 with db() as c:user=c.execute('SELECT * FROM users WHERE email=?',(OWNER_EMAIL,)).fetchone()
 valid=False
 if email==OWNER_EMAIL and user:
  stored=user['password']
  try:
   if stored.startswith('$argon2'):
    PH.verify(stored,data.password);valid=True
   elif '$' in stored:
    salt,digest=stored.split('$',1);valid=secrets.compare_digest(hashlib.pbkdf2_hmac('sha256',data.password.encode(),bytes.fromhex(salt),310000).hex(),digest)
    if valid:
     with db() as c:c.execute('UPDATE users SET password=? WHERE id=?',(PH.hash(data.password),user['id']))
  except (VerifyMismatchError,VerificationError,ValueError):valid=False
 if not valid:
  raise HTTPException(401,'تعذر تسجيل الدخول. تحقق من البيانات أو إعداد الحساب.')
 with db() as c:
  now=int(time.time());mail_scope=hash_token('otp:'+OWNER_EMAIL)
  c.execute('DELETE FROM login_attempts WHERE created<?',(now-900,))
  c.execute('DELETE FROM otp_challenges WHERE expires<? OR used=1',(now,))
  if c.execute('SELECT COUNT(*) FROM login_attempts WHERE scope=? AND created>?',(mail_scope,now-900)).fetchone()[0]>=3:raise HTTPException(429,'تم إرسال عدة رموز مؤخرًا؛ حاول بعد 15 دقيقة.')
  c.execute('INSERT INTO login_attempts(scope,created) VALUES(?,?)',(mail_scope,now))
 code=f'{secrets.randbelow(1000000):06d}';challenge=secrets.token_urlsafe(32);key=os.getenv('APP_SECRET_KEY','').encode()
 code_hash=hmac.new(key,(challenge+':'+code).encode(),hashlib.sha256).hexdigest()
 with db() as c:c.execute('INSERT INTO otp_challenges VALUES(?,?,?,?,0,0,?)',(hash_token(challenge),OWNER_EMAIL,code_hash,int(time.time())+300,int(time.time())))
 try:send_otp(OWNER_EMAIL,code)
 except Exception as e:
  with db() as c:c.execute('DELETE FROM otp_challenges WHERE id=?',(hash_token(challenge),))
  print('SMTP delivery failed:',type(e).__name__)
  raise HTTPException(401,'تعذر إتمام تسجيل الدخول. تحقق من البيانات أو من جاهزية البريد على الخادم.')
 secure=os.getenv('COOKIE_SECURE','0')=='1';response.set_cookie(CHALLENGE_COOKIE,challenge,httponly=True,secure=secure,samesite='none' if secure else 'lax',max_age=300)
 return {'status':'verification_required','message':'أُرسل رمز تحقق مؤقت إلى البريد المصرح.'}
@app.post('/api/verify')
def verify_otp(data:VerifyInput,request:Request,response:Response):
 challenge=request.cookies.get(CHALLENGE_COOKIE,'')
 if not challenge or not re.fullmatch(r'\d{6}',data.code):raise HTTPException(401,'تعذر التحقق من الرمز أو انتهت صلاحيته')
 cid=hash_token(challenge)
 with db() as c:r=c.execute('SELECT * FROM otp_challenges WHERE id=?',(cid,)).fetchone()
 if not r or r['used'] or r['expires']<int(time.time()) or r['attempts']>=5:raise HTTPException(401,'تعذر التحقق من الرمز أو انتهت صلاحيته')
 key=os.getenv('APP_SECRET_KEY','').encode();candidate=hmac.new(key,(challenge+':'+data.code).encode(),hashlib.sha256).hexdigest()
 if not secrets.compare_digest(candidate,r['code_hash']):
  with db() as c:c.execute('UPDATE otp_challenges SET attempts=attempts+1 WHERE id=?',(cid,))
  raise HTTPException(401,'تعذر التحقق من الرمز أو انتهت صلاحيته')
 with db() as c:
  c.execute('UPDATE otp_challenges SET used=1 WHERE id=?',(cid,));u=c.execute('SELECT id,email,role FROM users WHERE email=?',(OWNER_EMAIL,)).fetchone()
 if not u:raise HTTPException(401,'تعذر تسجيل الدخول')
 create_session(u['id'],response);event(u['id'],'login','OTP success');return {'id':u['id'],'email':u['email'],'role':u['role']}
@app.post('/api/logout')
def logout(request:Request,response:Response,u=Depends(current_user)):
 with db() as c:c.execute('DELETE FROM sessions WHERE token=?',(hash_token(request.cookies.get(SESSION_COOKIE,'')),))
 response.delete_cookie(SESSION_COOKIE);response.delete_cookie(CSRF_COOKIE);return {'ok':True}
@app.get('/api/me')
def me(u=Depends(current_user)):return {k:u[k] for k in ('id','email','role','created')}

@app.get('/api/dashboard')
def dashboard(u=Depends(current_user)):
 uid=u['id'];projects=[]
 with db() as c:rows=c.execute('SELECT * FROM projects WHERE user_id=? ORDER BY created DESC',(uid,)).fetchall()
 for r in rows:
  p=dict(r);p.update(status=proc_status(p['id']),pid=process_pid(p['id']),uptime=process_uptime(p['id']));projects.append(p)
 return {'projects':projects,'files':file_tree(uid),'storage':{'used':used_space(uid),'quota':QUOTA},'limits':{'projects':MAX_PROCS,'max_file':MAX_FILE},'runner':docker_ok(),'python_versions':['3.12'],'user':{'email':u['email'],'role':u['role']}}
def file_tree(uid,rel=''):
 base=safe_path(uid,rel)
 if not base.exists():return []
 out=[]
 for f in sorted(base.iterdir(),key=lambda x:(not x.is_dir(),x.name.lower())):
  st=f.stat();out.append({'name':f.name,'path':(Path(rel)/f.name).as_posix().lstrip('./'),'directory':f.is_dir(),'size':st.st_size if f.is_file() else 0,'modified':datetime.fromtimestamp(st.st_mtime,timezone.utc).isoformat(),'type':f.suffix.lower() or ('folder' if f.is_dir() else 'file')})
 return out
@app.get('/api/files')
def files(path:str='',u=Depends(current_user)):return {'items':file_tree(u['id'],path),'used':used_space(u['id']),'quota':QUOTA}
@app.post('/api/upload')
async def upload(files:list[UploadFile]=File(...),path:str=Form(''),u=Depends(current_user)):
 dest=safe_path(u['id'],path)
 if not dest.is_dir():raise HTTPException(400,'المجلد المحدد غير موجود')
 results=[]
 for f in files:
  name=Path(f.filename or '').name
  if not name or name in ('.','..') or Path(name).suffix.lower() not in ('.py','.zip','.txt','.json','.md','.toml','.yml','.yaml'):raise HTTPException(400,f'امتداد غير مسموح: {name}')
  target=dest/name
  if target.exists():raise HTTPException(409,f'الملف موجود بالفعل: {name}')
  data=await f.read(MAX_FILE+1)
  if len(data)>MAX_FILE:raise HTTPException(413,f'تجاوز الملف حد {MAX_FILE} بايت')
  if used_space(u['id'])+len(data)>QUOTA:raise HTTPException(413,'انتهت المساحة التخزينية المتاحة')
  if target.suffix.lower()!='.zip' and b'\x00' in data[:4096]:raise HTTPException(400,'تم رفض ملف ثنائي غير مسموح')
  target.write_bytes(data)
  if target.suffix.lower()=='.zip':
   try:zip_preview(data)
   except Exception:target.unlink(missing_ok=True);raise
  results.append({'name':name,'size':len(data)})
 event(u['id'],'upload',','.join(x['name'] for x in results));return {'uploaded':results}
def zip_preview(data):
 try:z=zipfile.ZipFile(io.BytesIO(data))
 except zipfile.BadZipFile:raise HTTPException(400,'ملف ZIP تالف أو غير صالح')
 entries=z.infolist()
 if len(entries)>2000:raise HTTPException(413,'الأرشيف يتجاوز 2000 ملف')
 total=0;clean=[]
 for x in entries:
  p=PurePosixPath(x.filename)
  if p.is_absolute() or '..' in p.parts or '\\' in x.filename or (p.parts and ':' in p.parts[0]):raise HTTPException(400,'مسار غير آمن داخل ZIP')
  if x.flag_bits&1:raise HTTPException(400,'الأرشيف المشفر غير مدعوم')
  total+=x.file_size
  if x.file_size>MAX_FILE or total>MAX_FILE*20:raise HTTPException(413,'الأرشيف المفكوك أكبر من الحد الآمن')
  clean.append({'name':x.filename,'size':x.file_size,'directory':x.is_dir()})
 return clean
@app.get('/api/zip/inspect')
def inspect_zip(path:str,u=Depends(current_user)):
 p=safe_path(u['id'],path)
 if not p.is_file() or p.suffix.lower()!='.zip':raise HTTPException(400,'اختر ملف ZIP صالحًا')
 items=zip_preview(p.read_bytes())
 with zipfile.ZipFile(p) as z:candidates=discover_candidates(p.parent,items,z)
 return {'items':items,'entry_candidates':candidates}
@app.post('/api/zip/extract')
def extract_zip(data:PathInput,u=Depends(current_user)):
 src=safe_path(u['id'],data.path)
 if not src.is_file() or src.suffix.lower()!='.zip':raise HTTPException(400,'اختر ZIP صالحًا')
 entries=zip_preview(src.read_bytes());expanded=sum(x['size'] for x in entries)
 if used_space(u['id'])+expanded>QUOTA:raise HTTPException(413,'المساحة المتبقية لا تكفي لفك الأرشيف')
 outname=data.name or src.stem
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
    with z.open(info) as r,target.open('wb') as w:shutil.copyfileobj(r,w,length=1024*1024)
 except Exception:shutil.rmtree(dest,ignore_errors=True);raise
 event(u['id'],'extract',outname);return {'path':outname,'items':len(entries)}
@app.get('/api/file')
def read_file(path:str,u=Depends(current_user)):
 p=safe_path(u['id'],path)
 if not p.is_file():raise HTTPException(404,'الملف غير موجود')
 if p.stat().st_size>2*1024*1024:raise HTTPException(413,'المعاينة متاحة حتى 2MB')
 try:return {'content':p.read_text(encoding='utf-8')}
 except UnicodeError:raise HTTPException(415,'الملف ليس نصًا صالحًا للمعاينة')
@app.put('/api/file')
def save_file(data:SaveInput,u=Depends(current_user)):
 p=safe_path(u['id'],data.path)
 if not p.is_file() or len(data.content.encode())>MAX_FILE:raise HTTPException(400,'المسار أو الحجم غير صالح')
 if used_space(u['id'])-p.stat().st_size+len(data.content.encode())>QUOTA:raise HTTPException(413,'تجاوز حصة التخزين')
 p.write_text(data.content,encoding='utf-8');return {'saved':True}
@app.get('/api/download')
def download(path:str,u=Depends(current_user)):
 p=safe_path(u['id'],path)
 if not p.is_file():raise HTTPException(404,'الملف غير موجود')
 return FileResponse(p,filename=p.name)
@app.post('/api/folder')
def folder(data:PathInput,u=Depends(current_user)):
 name=data.name or ''
 if not re.fullmatch(r'[\w .-]{1,80}',name) or name in ('.','..'):raise HTTPException(400,'اسم مجلد غير صالح')
 safe_path(u['id'],str(Path(data.path)/name)).mkdir(parents=True,exist_ok=False);return {'created':True}
@app.post('/api/files/rename')
def rename(data:PathInput,u=Depends(current_user)):
 p=safe_path(u['id'],data.path);name=data.name or ''
 if not p.exists() or not re.fullmatch(r'[\w .-]{1,120}',name) or name in ('.','..'):raise HTTPException(400,'اسم غير صالح')
 q=safe_path(u['id'],str(p.parent.relative_to(user_root(u['id']))/name));p.rename(q);return {'renamed':True}
@app.post('/api/files/action/{operation}')
def file_operation(operation:str,data:PathInput,u=Depends(current_user)):
 if operation not in ('copy','move'):raise HTTPException(404,'عملية غير مدعومة')
 src=safe_path(u['id'],data.path);destdir=safe_path(u['id'],data.destination or '')
 if not src.exists() or not destdir.is_dir():raise HTTPException(400,'المصدر أو مجلد الوجهة غير صالح')
 if src.is_dir() and (destdir==src or src in destdir.parents):raise HTTPException(400,'لا يمكن وضع المجلد داخل نفسه')
 target=destdir/src.name
 if target.exists():raise HTTPException(409,'يوجد عنصر بالاسم نفسه في الوجهة')
 size=sum(f.stat().st_size for f in src.rglob('*') if f.is_file()) if src.is_dir() else src.stat().st_size
 if operation=='copy' and used_space(u['id'])+size>QUOTA:raise HTTPException(413,'المساحة غير كافية للنسخ')
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

# Static, non-executing startup discovery. A selected project entry always takes precedence.
def python_candidates(base:Path,items=None,archive=None):
 paths=[]
 if items is not None: paths=[base/x['name'] for x in items if not x['directory'] and x['name'].endswith('.py')]
 else: paths=list(base.rglob('*.py'))[:500]
 out=[]
 for p in paths:
  try:
   rel=p.relative_to(base).as_posix();raw=archive.read(rel) if archive else p.read_bytes();source=raw[:512*1024].decode('utf-8');tree=ast.parse(source,filename=rel)
  except (OSError,UnicodeError,SyntaxError):continue
  score=0;reasons=[]
  if any(isinstance(n,ast.If) and isinstance(n.test,ast.Compare) and isinstance(n.test.left,ast.Name) and n.test.left.id=='__name__' and any(isinstance(c,ast.Constant) and c.value=='__main__' for c in n.test.comparators) for n in ast.walk(tree)):
   score+=80;reasons.append('يحتوي نقطة دخول __main__')
  calls={n.func.id if isinstance(n.func,ast.Name) else n.func.attr if isinstance(n.func,ast.Attribute) else '' for n in ast.walk(tree) if isinstance(n,ast.Call)}
  if calls & {'run','serve','start_polling','run_polling','polling'}:
   score+=22;reasons.append('يتضمن استدعاء تشغيل شائعًا')
  if p.name.lower() in ('main.py','bot.py','app.py'):
   score+=8;reasons.append('اسم الملف تلميح شائع وليس دليلًا')
  if score:out.append({'path':rel,'score':score,'reasons':reasons})
 return sorted(out,key=lambda x:(-x['score'],x['path']))
def discover_candidates(base:Path,items=None,archive=None):
 if items is None:items=[{'name':p.relative_to(base).as_posix(),'directory':False} for p in base.rglob('*') if p.is_file()]
 py=[x['name'] for x in items if not x.get('directory') and x['name'].endswith('.py')]
 # Explicit deployment declarations are scanned without executing project code.
 for name in ('Procfile','pyproject.toml','Dockerfile'):
  candidate=next((x for x in items if not x.get('directory') and Path(x['name']).name==name),None)
  if not candidate:continue
  try:text=(archive.read(candidate['name']).decode('utf-8') if archive else (base/candidate['name']).read_text(encoding='utf-8'))[:256*1024]
  except Exception:continue
  if name=='Procfile':
   for line in text.splitlines():
    m=re.match(r'\s*(?:web|worker|bot|release)\s*:\s*(?:python(?:3(?:\.\d+)?)?\s+)([\w./-]+\.py)\b',line)
    if m and m.group(1) in py:return [{'path':m.group(1),'score':120,'reasons':['محدد في Procfile'] }]
  elif name=='pyproject.toml':
   try:
    d=tomllib.loads(text);scripts=d.get('project',{}).get('scripts',{})
    for key,val in scripts.items():
     module=val.split(':',1)[0].replace('.','/')
     for candidate_path in (module+'.py',module+'/__main__.py'):
      if candidate_path in py:return [{'path':candidate_path,'score':115,'reasons':[f"نقطة دخول معرفّة في pyproject.toml ({key})"]}]
   except Exception:pass
  else:
   m=re.search(r'(?:CMD|ENTRYPOINT)\s+(?:\[\s*"(?:python|python3)"\s*,\s*"([\w./-]+\.py)"|(?:python|python3)\s+([\w./-]+\.py))',text,re.I)
   if m:
    path=m.group(1) or m.group(2)
    if path in py:return [{'path':path,'score':110,'reasons':['أمر تشغيل Python محدد في Dockerfile']}]
 scored=python_candidates(base,items,archive)
 return [{'path':x['path'],'score':x['score'],'reasons':x['reasons']} for x in scored]
@app.post('/api/projects')
def create_project(data:ProjectInput,u=Depends(current_user)):
 name=data.name.strip()
 if not re.fullmatch(r'[\w .-]{1,64}',name):raise HTTPException(400,'اسم المشروع غير صالح')
 if data.python!='3.12':raise HTTPException(400,'إصدار Python المطلوب غير مثبت')
 entry=data.entry.strip()
 if entry and (not re.fullmatch(r'[\w./-]+\.py',entry) or '..' in Path(entry).parts):raise HTTPException(400,'مسار التشغيل غير صالح')
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  if c.execute('SELECT COUNT(*) FROM projects WHERE user_id=?',(u['id'],)).fetchone()[0]>=MAX_PROCS:raise HTTPException(429,'بلغت الحد الأقصى للمشاريع')
  pid=uuid.uuid4().hex;c.execute('INSERT INTO projects(id,user_id,name,entry,python,created,operation) VALUES(?,?,?,?,?,?,?)',(pid,u['id'],name,entry,'3.12',utc(),''))
 project_path(u['id'],pid).mkdir(parents=True,exist_ok=True);event(u['id'],'project_create',name)
 return {'id':pid,'name':name,'entry':entry,'status':'Stopped'}
@app.get('/api/projects')
def projects(u=Depends(current_user)):
 with db() as c:rows=c.execute('SELECT * FROM projects WHERE user_id=?',(u['id'],)).fetchall()
 return [dict(r,status=proc_status(r['id']),pid=process_pid(r['id'])) for r in rows]
@app.get('/api/projects/{pid}/discover')
def discover_project(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid);root=project_path(u['id'],pid)
 if p['entry'] and (root/p['entry']).is_file():return {'selected':p['entry'],'source':'project setting','candidates':[{'path':p['entry'],'reasons':['إعداد محفوظ للمشروع']}]}
 if p['entry']:
  return {'selected':None,'candidates':[{'path':p['entry'],'reasons':['إعداد محفوظ لكن الملف غير موجود']}],'diagnostic':f"ملف التشغيل المحفوظ {p['entry']} غير موجود؛ صحّح الإعداد أو ارفع الملف."}
 candidates=discover_candidates(root)
 selected=candidates[0]['path'] if len(candidates)==1 and candidates[0]['score']>=80 else None
 if selected:
  with db() as c:c.execute('UPDATE projects SET entry=? WHERE id=?',(selected,pid))
 return {'selected':selected,'candidates':candidates,'diagnostic':'لم يُعثر على نقطة دخول مناسبة. اختر ملف Python يدويًا.' if not candidates else ('اختر ملف التشغيل؛ توجد خيارات متنافسة.' if len(candidates)>1 else None)}
@app.post('/api/projects/{pid}/entry')
def set_entry(pid:str,data:EntryInput,u=Depends(current_user)):
 p=get_project(u['id'],pid);root=project_path(u['id'],pid);entry=data.entry
 if p.get('operation') or (docker_ok() and proc_status(pid) in ('running','restarting')):raise HTTPException(409,'أوقف المشروع أو انتظر انتهاء عمليته قبل تغيير نقطة التشغيل')
 if not re.fullmatch(r'[\w./-]+\.py',entry) or '..' in Path(entry).parts:raise HTTPException(400,'مسار ملف التشغيل غير صالح')
 if not (root/entry).is_file():raise HTTPException(404,'ملف التشغيل غير موجود داخل المشروع')
 with db() as c:c.execute('UPDATE projects SET entry=? WHERE id=?',(entry,pid))
 return {'entry':entry}
def container_name(pid):return 'seahost-'+re.sub('[^a-f0-9]','',pid)[:24]
def docker(*args,timeout=20):
 base=os.getenv('RUNNER_API_URL','').rstrip('/');token=os.getenv('RUNNER_TOKEN','')
 if not base or not token or len(token.encode())<32 or token.startswith('REPLACE_'):return subprocess.CompletedProcess(args,127,'','عامل التشغيل الداخلي غير مهيأ')
 req=urllib.request.Request(base+'/v1/docker',data=json.dumps({'args':list(args)}).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+token},method='POST')
 try:
  with urllib.request.urlopen(req,timeout=timeout) as response:data=json.loads(response.read())
  return subprocess.CompletedProcess(args,data['returncode'],data.get('stdout',''),data.get('stderr',''))
 except urllib.error.HTTPError as e:
  return subprocess.CompletedProcess(args,126,'',e.read().decode(errors='replace')[:1000])
 except Exception as e:
  return subprocess.CompletedProcess(args,127,'',type(e).__name__)
def proc_status(pid):
 if not docker_ok():return 'Unavailable'
 try:
  r=docker('inspect','-f','{{.State.Status}}',container_name(pid),timeout=5)
  if r.returncode:return 'Missing'
  state=r.stdout.strip().lower()
  if state in ('running','restarting'):return 'Running'
  if state in ('exited','dead'):
   code=docker('inspect','-f','{{.State.ExitCode}}',container_name(pid),timeout=5)
   with db() as c:row=c.execute('SELECT started_at,stopped_at FROM projects WHERE id=?',(pid,)).fetchone()
   if code.returncode==0 and code.stdout.strip().isdigit() and int(code.stdout.strip())!=0 and (not row or not row['stopped_at'] or row['stopped_at']<(row['started_at'] or 0)):return 'Crashed'
   return 'Stopped'
  return 'Stopped' if state=='created' else 'Error'
 except Exception:return 'Error'
def process_pid(pid):
 if not docker_ok():return None
 try:r=docker('inspect','-f','{{.State.Pid}}',container_name(pid),timeout=5);return int(r.stdout.strip()) or None if r.returncode==0 else None
 except Exception:return None
def process_uptime(pid):
 if not docker_ok():return None
 try:r=docker('inspect','-f','{{.State.StartedAt}}',container_name(pid),timeout=5);return r.stdout.strip() if r.returncode==0 else None
 except Exception:return None
def dependency_volume_exists(name):
 r=docker('volume','inspect',name,timeout=5)
 if r.returncode==0:return True
 if 'no such volume' in r.stderr.lower() or 'not found' in r.stderr.lower():return False
 raise HTTPException(503,'تعذر التحقق من بيئة الاعتماديات عبر عامل Docker')
def backup_project_logs(pid):
 try:
  r=docker('logs','--tail','2000',container_name(pid),timeout=8)
  if r.returncode:return False
  content=(r.stdout+'\n'+r.stderr)[-200000:]
  with db() as c:c.execute('INSERT INTO project_logs(project_id,content,updated) VALUES(?,?,?) ON CONFLICT(project_id) DO UPDATE SET content=excluded.content,updated=excluded.updated',(pid,content,utc()))
  return True
 except Exception:return False
def stored_project_logs(pid):
 cutoff=datetime.fromtimestamp(time.time()-LOG_RETENTION_DAYS*86400,timezone.utc).isoformat(timespec='seconds')
 with db() as c:
  c.execute('DELETE FROM project_logs WHERE updated<?',(cutoff,))
  row=c.execute('SELECT content FROM project_logs WHERE project_id=?',(pid,)).fetchone()
 return row['content'] if row else None
def cleanup_expired_logs_and_containers():
 cutoff=time.time()-LOG_RETENTION_DAYS*86400
 with db() as c:projects=c.execute("SELECT id,user_id FROM projects WHERE operation='' ").fetchall()
 if not docker_ok():return
 for project in projects:
  pid=project['id']
  try:
   if proc_status(pid) not in ('Stopped','Crashed'):continue
   finished=docker('inspect','-f','{{.State.FinishedAt}}',container_name(pid),timeout=5)
   if finished.returncode:continue
   ended=datetime.fromisoformat(finished.stdout.strip().replace('Z','+00:00')).timestamp()
   if ended<=0 or ended>cutoff:continue
   reserve_project_operation(project['user_id'],pid,'cleanup')
   try:
    if proc_status(pid) not in ('Stopped','Crashed'):continue
    check=docker('inspect','-f','{{.State.FinishedAt}}',container_name(pid),timeout=5)
    if check.returncode or datetime.fromisoformat(check.stdout.strip().replace('Z','+00:00')).timestamp()>cutoff:continue
    removed=docker('rm','-f',container_name(pid),timeout=10)
    if removed.returncode and 'no such container' not in removed.stderr.lower():continue
    with db() as c:c.execute('DELETE FROM project_logs WHERE project_id=?',(pid,))
   finally:release_project_operation(project['user_id'],pid,'cleanup')
  except Exception:continue
def _log_cleanup_loop():
 while not _log_cleanup_stop.is_set():
  try:cleanup_expired_logs_and_containers()
  except Exception:pass
  _log_cleanup_stop.wait(3600)
def project_config(root,entry,name):
 folders=[root]
 if entry:
  parent=(root/entry).parent
  while parent!=root and root in parent.parents:
   if parent not in folders:folders.append(parent)
   parent=parent.parent
 for folder in folders:
  p=folder/name
  if p.is_file() and root.resolve() in p.resolve().parents:return p
 return None
def dependency_spec(root,entry=''):
 req=project_config(root,entry,'requirements.txt')
 if req:return req,False
 config=project_config(root,entry,'pyproject.toml')
 if config is None:return None,False
 if not config.is_file():return None,False
 if config.stat().st_size>1024*1024:raise HTTPException(413,'pyproject.toml أكبر من 1 MiB')
 try:deps=tomllib.loads(config.read_text(encoding='utf-8')).get('project',{}).get('dependencies',[])
 except Exception:raise HTTPException(400,'تعذر قراءة project.dependencies من pyproject.toml')
 if not isinstance(deps,list) or len(deps)>500 or any(not isinstance(x,str) or len(x)>500 or '\n' in x or '\r' in x for x in deps):raise HTTPException(400,'قائمة project.dependencies غير صالحة أو كبيرة')
 if not deps:return None,False
 req=root/'.seahost-requirements.pending.txt'
 req.write_text('\n'.join(deps)+'\n',encoding='utf-8')
 return req,True
def install_deps(root,pid,entry=''):
 req,generated=dependency_spec(root,entry)
 if req is None:return {'installed':False,'message':'لم يُعثر على requirements.txt أو project.dependencies؛ تخطي التثبيت.'}
 if req.stat().st_size>1024*1024:
  if generated:req.unlink(missing_ok=True)
  raise HTTPException(413,'ملف الاعتماديات أكبر من 1 MiB')
 # Installation is executed in a throwaway resource-limited container, not on the API host.
 vol='seahost-deps-'+re.sub('[^a-f0-9]','',pid)[:24]
 try:
  created=docker('volume','create',vol,timeout=10)
  if created.returncode:raise HTTPException(503,'تعذر إنشاء مساحة الاعتماديات المعزولة')
  init=docker('run','--rm','--network','none','--memory','256m','--memory-swap','256m','--cpus','0.50','--pids-limit','32','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--cap-drop','ALL','--cap-add','CHOWN','--security-opt','no-new-privileges','--user','0:0','--mount',f'type=volume,src={vol},dst=/opt/venv',DOCKER_IMAGE,'sh','-lc','chown -R 10001:10001 /opt/venv',timeout=30)
  if init.returncode:raise HTTPException(503,'تعذر تهيئة مساحة الاعتماديات المعزولة')
  build_network=os.getenv('RUNNER_BUILD_NETWORK','none')
  if build_network not in ('none','seahost-build-egress'):raise HTTPException(503,'شبكة بناء الاعتماديات غير مسموحة')
  req_rel=req.relative_to(root).as_posix()
  if not re.fullmatch(r'[\w ./-]+',req_rel) or '..' in Path(req_rel).parts:raise HTTPException(400,'مسار ملف الاعتماديات غير مدعوم')
  script='import subprocess,sys; subprocess.run([sys.executable,"-m","venv","/opt/venv/env"],check=True); subprocess.run(["/opt/venv/env/bin/pip","install","--disable-pip-version-check","--no-input","--timeout","15","--retries","1","-r",sys.argv[1]],check=True)'
  r=docker('run','--rm','--network',build_network,'--memory','512m','--memory-swap','512m','--cpus','0.50','--pids-limit','96','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=64m','--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001','--mount',f'type=bind,src={root.resolve()},dst=/app,readonly','--mount',f'type=volume,src={vol},dst=/opt/venv','--workdir','/app',DOCKER_IMAGE,'python','-c',script,'/app/'+req_rel,timeout=300)
 except subprocess.TimeoutExpired:
  if generated:req.unlink(missing_ok=True)
  raise HTTPException(504,'انتهت مهلة تثبيت الاعتماديات (5 دقائق)')
 finally:
  if generated:req.unlink(missing_ok=True)
 if r.returncode:
  try:docker('volume','rm',vol,timeout=8)
  except Exception:pass
  text=(r.stderr or '')+'\n'+(r.stdout or '')
  names=set(re.findall(r'Could not find a version that satisfies the requirement\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,100})',text,re.I))
  names.update(re.findall(r'No matching distribution found for\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,100})',text,re.I))
  detail=('تعذر تثبيت الحزمة: '+', '.join(sorted(names))) if names else 'تعذر تثبيت الاعتماديات.'
  raise HTTPException(422,detail+' لم تُعرض المخرجات الخام لحماية بيانات الاعتماد؛ تحقق من إعداد الحزمة وشبكة البناء.')
 return {'installed':True,'message':'اكتمل تثبيت المتطلبات داخل بيئة المشروع المعزولة.'}
@app.post('/api/projects/{pid}/install')
def install(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid);root=project_path(u['id'],pid)
 if not docker_ok():raise HTTPException(503,'محرك Docker غير متاح؛ لم تثبت أي حزمة')
 reserve_project_operation(u['id'],pid,'installing')
 try:
  if proc_status(pid) in ('running','restarting'):raise HTTPException(409,'أوقف المشروع قبل تحديث بيئة الاعتماديات')
  try:result=install_deps(root,pid,p.get('entry',''))
  except HTTPException as e:event(u['id'],'dependencies_install_failed',f"{p['name']}: HTTP {e.status_code}; {str(e.detail)[:180]}");raise
  event(u['id'],'dependencies_install',p['name']);return result
 finally:release_project_operation(u['id'],pid,'installing')
@app.post('/api/projects/{pid}/run')
def run_project(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid);root=project_path(u['id'],pid)
 if not docker_ok():raise HTTPException(503,'محرك Docker غير متاح على هذا الخادم. لم يتم تشغيل كود المشروع.')
 if not p['entry']:
  candidates=discover_candidates(root)
  if len(candidates)==1 and candidates[0]['score']>=80:
   with db() as c:c.execute('UPDATE projects SET entry=? WHERE id=?',(candidates[0]['path'],pid))
   p['entry']=candidates[0]['path']
  else:raise HTTPException(409,json.dumps({'message':'لم يتم تشغيل المشروع: اختر ملف بدء التشغيل أولًا.','candidates':candidates},ensure_ascii=False))
 entry=(root/p['entry']).resolve()
 if root.resolve() not in entry.parents or not entry.is_file():raise HTTPException(400,'ملف التشغيل غير موجود أو مساره غير صالح')
 with db() as c:
  c.execute('BEGIN IMMEDIATE')
  current=c.execute('SELECT operation FROM projects WHERE id=? AND user_id=?',(pid,u['id'])).fetchone()
  if not current or current['operation']:raise HTTPException(409,'توجد عملية أخرى جارية للمشروع')
  if proc_status(pid) in ('running','restarting'):raise HTTPException(409,'المشروع يعمل بالفعل')
  others=c.execute('SELECT id,operation FROM projects WHERE user_id=? AND id<>?',(u['id'],pid)).fetchall()
  if sum(bool(x['operation']) or proc_status(x['id']) in ('running','restarting') for x in others)>=MAX_RUNNING:raise HTTPException(429,'بلغت الحد الأقصى للعمليات المتزامنة')
  c.execute("UPDATE projects SET operation='starting' WHERE id=? AND user_id=?",(pid,u['id']))
 depvol='seahost-deps-'+re.sub('[^a-f0-9]','',pid)[:24]; mounts=['--mount',f'type=bind,src={root.resolve()},dst=/app,readonly']
 try:
  has_dependencies=dependency_volume_exists(depvol)
  if has_dependencies:mounts+=['--mount',f'type=volume,src={depvol},dst=/opt/venv,readonly']
  backup_project_logs(pid)
  r=docker('rm','-f',container_name(pid),timeout=10)
  if r.returncode and 'no such container' not in r.stderr.lower():raise HTTPException(503,'تعذر إزالة الحاوية القديمة بأمان')
  runargs=['run','-d','--name',container_name(pid),'--label','seahost.owner='+hashlib.sha256(u['id'].encode()).hexdigest()[:20],'--network','none','--memory','256m','--memory-swap','256m','--cpus','0.50','--pids-limit','128','--ulimit','cpu=86400:86400','--log-driver','json-file','--log-opt','max-size=10m','--log-opt','max-file=3','--read-only','--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001','--env','PYTHONDONTWRITEBYTECODE=1','--env','PYTHONUNBUFFERED=1',*mounts,'--workdir','/app']
  command=['python','-u',p['entry']]
  if has_dependencies:command=['/opt/venv/env/bin/python','-u',p['entry']]
  r=docker(*runargs,DOCKER_IMAGE,*command,timeout=25)
  if r.returncode:raise HTTPException(503,'تعذر إنشاء الحاوية: '+(r.stderr or '')[:500])
  with db() as c:c.execute('UPDATE projects SET started_at=?,stopped_at=NULL WHERE id=?',(int(time.time()*1000),pid))
  event(u['id'],'project_start',p['name']);return {'status':'Running','container':container_name(pid)}
 except subprocess.TimeoutExpired:raise HTTPException(504,'انتهت مهلة بدء المشروع')
 finally:
  with db() as c:c.execute("UPDATE projects SET operation='' WHERE id=? AND user_id=? AND operation='starting'",(pid,u['id']))
@app.post('/api/projects/{pid}/stop')
def stop_project(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid)
 if not docker_ok():raise HTTPException(503,'محرك Docker غير متاح')
 reserve_project_operation(u['id'],pid,'stopping')
 try:
  try:r=docker('stop','--time','5',container_name(pid),timeout=10)
  except subprocess.TimeoutExpired:raise HTTPException(504,'تعذر إيقاف المشروع ضمن المهلة')
  if r.returncode and 'no such container' not in r.stderr.lower():raise HTTPException(500,(r.stderr or 'فشل الإيقاف')[:300])
  with db() as c:c.execute('UPDATE projects SET stopped_at=? WHERE id=?',(int(time.time()*1000),pid))
  backup_project_logs(pid)
  event(u['id'],'project_stop',p['name']);return {'status':'Stopped'}
 finally:release_project_operation(u['id'],pid,'stopping')
@app.post('/api/projects/{pid}/restart')
def restart(pid:str,u=Depends(current_user)):
 try:stop_project(pid,u)
 except HTTPException as e:
  if e.status_code not in (409,):raise
 return run_project(pid,u)
@app.get('/api/projects/{pid}/logs')
def logs(pid:str,tail:int=200,u=Depends(current_user)):
 get_project(u['id'],pid)
 status=proc_status(pid)
 if status=='Unavailable':
  saved=stored_project_logs(pid)
  return {'logs':saved or '','status':status,'message':None if saved else 'Docker غير متاح؛ لا توجد سجلات محفوظة حديثة'}
 try:r=docker('logs','--tail',str(max(1,min(tail,2000))),container_name(pid),timeout=8)
 except subprocess.TimeoutExpired:raise HTTPException(504,'انتهت مهلة جلب السجلات')
 if r.returncode:
  saved=stored_project_logs(pid)
  return {'logs':saved or (r.stderr or '')[-200000:],'status':status}
 content=(r.stdout+'\n'+r.stderr)[-200000:]
 if status in ('Crashed','Stopped'):backup_project_logs(pid)
 return {'logs':content,'status':status}
@app.delete('/api/projects/{pid}')
def delete_project(pid:str,u=Depends(current_user)):
 p=get_project(u['id'],pid)
 reserve_project_operation(u['id'],pid,'deleting')
 try:
  if docker_ok():
   try:r=docker('rm','-f',container_name(pid),timeout=10)
   except Exception:raise HTTPException(503,'تعذر التحقق من إزالة حاوية المشروع؛ لم تُحذف ملفاته')
   if r.returncode and 'no such container' not in r.stderr.lower():raise HTTPException(503,'تعذر إزالة حاوية المشروع؛ لم تُحذف ملفاته')
   vol='seahost-deps-'+re.sub('[^a-f0-9]','',pid)[:24]
   try:r=docker('volume','rm',vol,timeout=8)
   except Exception:raise HTTPException(503,'تعذر إزالة بيئة الاعتماديات؛ لم تُحذف ملفات المشروع')
   if r.returncode and 'no such volume' not in r.stderr.lower() and 'not found' not in r.stderr.lower():raise HTTPException(503,'تعذر إزالة بيئة الاعتماديات؛ لم تُحذف ملفات المشروع')
  else:
   with db() as c:started=c.execute("SELECT 1 FROM events WHERE user_id=? AND action='project_start' AND detail=? LIMIT 1",(u['id'],p['name'])).fetchone()
   if started:raise HTTPException(503,'محرك Docker غير متاح للتحقق من تنظيف الموارد؛ لم يُحذف المشروع')
  shutil.rmtree(project_path(u['id'],pid),ignore_errors=True)
  with db() as c:c.execute('DELETE FROM project_logs WHERE project_id=?',(pid,));c.execute('DELETE FROM projects WHERE id=? AND user_id=?',(pid,u['id']))
  event(u['id'],'project_delete',p['name']);return {'deleted':True}
 finally:release_project_operation(u['id'],pid,'deleting')
@app.get('/api/admin/users')
def admin_users(u=Depends(current_user)):
 if u['role']!='admin':raise HTTPException(403,'غير مصرح')
 with db() as c:rows=c.execute('SELECT id,email,role,created FROM users WHERE id=? ORDER BY created DESC',(u['id'],)).fetchall()
 return [{'id':r['id'],'email':r['email'],'role':r['role'],'created':r['created'],'used':used_space(r['id'])} for r in rows]
@app.get('/api/admin/events')
def admin_events(u=Depends(current_user)):
 if u['role']!='admin':raise HTTPException(403,'غير مصرح')
 with db() as c:rows=c.execute('SELECT * FROM events ORDER BY id DESC LIMIT 200').fetchall()
 return [dict(r) for r in rows]
@app.get('/api/admin/resources')
def admin_resources(u=Depends(current_user)):
 if u['role']!='admin':raise HTTPException(403,'غير مصرح')
 du=shutil.disk_usage(DATA);actual={'docker_available':docker_ok(),'disk_bytes':du.total,'disk_free_bytes':du.free}
 if docker_ok():
  try:r=docker('stats','--no-stream','--format','{{json .}}',timeout=8);actual['docker_stats']=[json.loads(x) for x in r.stdout.splitlines() if x]
  except Exception:actual['docker_stats_error']='تعذر قراءة إحصاءات الحاويات'
 else:actual['note']='قياسات حاويات Docker غير متاحة في هذه البيئة'
 return actual
app.mount('/',StaticFiles(directory=ROOT/'static',html=True),name='static')
