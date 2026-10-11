"""Minimal authenticated internal runner. Exposes a strict Docker command allowlist only."""
import os,re,subprocess,hmac
from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel
app=FastAPI(title='SeaHost isolated runner')
TOKEN=os.getenv('RUNNER_TOKEN',''); DATA_ROOT=os.path.realpath(os.getenv('HOSTPANEL_DATA_DIR','/var/lib/nawahost'))
INSTALL_SCRIPT='import subprocess,sys; subprocess.run([sys.executable,"-m","venv","/opt/venv/env"],check=True); subprocess.run(["/opt/venv/env/bin/pip","install","--disable-pip-version-check","--no-input","--timeout","15","--retries","1","-r",sys.argv[1]],check=True)'
class Command(BaseModel):args:list[str]
def run(args,timeout=20):
 if len(TOKEN.encode())<32 or TOKEN.startswith('REPLACE_'):raise HTTPException(503,'Runner secret is not configured safely')
 if not args or len(args)>50 or any('\x00' in x for x in args):raise HTTPException(400,'Invalid runner request')
 return subprocess.run(['docker',*args],capture_output=True,text=True,timeout=timeout)
def valid_name(s,prefix):return bool(re.fullmatch(prefix+r'[a-f0-9]{1,32}',s))
def validate_mount(v):
 m=re.fullmatch(r'type=bind,src=([^,]+),dst=/app,readonly',v)
 if m:
  src=os.path.realpath(m.group(1));rel=os.path.relpath(src,DATA_ROOT)
  return bool(re.fullmatch(r'users/[a-f0-9]{32}/projects/[a-f0-9]{32}',rel))
 return bool(re.fullmatch(r'type=volume,src=seahost-deps-[a-f0-9]{1,24},dst=/opt/venv(?:,readonly)?',v))
def allowed(a):
 op=a[0]
 if op=='info':return len(a)==1
 if op=='volume' and len(a)==3 and a[1] in ('create','rm','inspect') and valid_name(a[2],'seahost-deps-'):return True
 if op=='inspect' and len(a)==4 and a[1]=='-f' and a[2] in ('{{.State.Status}}','{{.State.Pid}}','{{.State.StartedAt}}','{{.State.ExitCode}}','{{.State.FinishedAt}}') and valid_name(a[3],'seahost-'):return True
 if op=='stop' and len(a)==4 and a[1]=='--time' and a[2]=='5' and valid_name(a[3],'seahost-'):return True
 if op=='logs' and len(a)==4 and a[1]=='--tail' and a[2].isdigit() and 1<=int(a[2])<=2000 and valid_name(a[3],'seahost-'):return True
 if op=='rm' and a[1:2]==['-f'] and len(a)==3 and valid_name(a[2],'seahost-'):return True
 if op=='stats' and a[1:]==['--no-stream','--format','{{json .}}']:return True
 if op=='run':
  allowed_flags={'-d','--rm','--name','--label','--network','--memory','--memory-swap','--cpus','--pids-limit','--ulimit','--log-driver','--log-opt','--read-only','--tmpfs','--cap-drop','--cap-add','--security-opt','--user','--mount','--workdir','--env'}
  i=1;values={};mounts=[]
  while i<len(a) and a[i].startswith('--') or (i<len(a) and a[i] in ('-d','--rm')):
   flag=a[i];i+=1
   if flag not in allowed_flags:return False
   if flag in ('-d','--rm'):continue
   if flag=='--read-only':values[flag]=True;continue
   if i>=len(a):return False
   value=a[i];i+=1
   if flag=='--mount':
    if not validate_mount(value):return False
    mounts.append(value)
   elif flag=='--name':
    if not valid_name(value,'seahost-'):return False
   elif flag=='--label':
    if not re.fullmatch(r'seahost\.owner=[a-f0-9]{20}',value):return False
   elif flag=='--network' and value not in ('none','seahost-build-egress'):return False
   elif flag=='--memory' and value not in ('256m','512m'):return False
   elif flag=='--memory-swap' and value not in ('256m','512m'):return False
   elif flag=='--cpus' and value!='0.50':return False
   elif flag=='--pids-limit' and value not in ('32','96','128'):return False
   elif flag=='--ulimit' and value!='cpu=86400:86400':return False
   elif flag=='--log-driver' and value!='json-file':return False
   elif flag=='--log-opt' and value not in ('max-size=10m','max-file=3'):return False
   elif flag=='--env' and value not in ('PYTHONDONTWRITEBYTECODE=1','PYTHONUNBUFFERED=1'):return False
   elif flag=='--tmpfs' and value not in ('/tmp:rw,noexec,nosuid,size=32m','/tmp:rw,noexec,nosuid,size=64m'):return False
   elif flag=='--cap-drop' and value!='ALL':return False
   elif flag=='--cap-add' and value!='CHOWN':return False
   elif flag=='--security-opt' and value!='no-new-privileges':return False
   elif flag=='--user' and value not in ('10001:10001','0:0'):return False
   elif flag=='--workdir' and value!='/app':return False
   values[flag]=value
  if i>=len(a) or a[i]!=os.getenv('RUNNER_IMAGE','python:3.12-slim'):return False
  command=a[i+1:]
  if not command:return False
  if command==['sh','-lc','chown -R 10001:10001 /opt/venv']:
   return values.get('--network')=='none' and values.get('--memory')=='256m' and values.get('--memory-swap')=='256m' and values.get('--cpus')=='0.50' and values.get('--pids-limit')=='32' and '--read-only' in a and values.get('--tmpfs')=='/tmp:rw,noexec,nosuid,size=32m' and values.get('--cap-drop')=='ALL' and values.get('--cap-add')=='CHOWN' and values.get('--security-opt')=='no-new-privileges' and values.get('--user')=='0:0' and mounts==['type=volume,src='+values.get('--mount','').split('src=')[-1].split(',')[0]+',dst=/opt/venv'] and not any('dst=/app' in m for m in mounts)
  if command[0]=='python':
   if command[1:2]==['-u']:
    if len(command)!=3 or not re.fullmatch(r'[\w./-]+\.py',command[2]) or '..' in command[2].split('/'):return False
   elif command[1:2]==['-c']:
    if len(command)!=4 or command[2]!=INSTALL_SCRIPT or not re.fullmatch(r'/app/(?:[\w .-]+/)*(?:requirements\.txt|\.seahost-requirements\.pending\.txt)',command[3]) or '..' in command[3].split('/'):return False
   elif len(command)!=1:return False
  elif command[0]=='/opt/venv/env/bin/python':
   if len(command)!=3 or command[1]!='-u' or not re.fullmatch(r'[\w./-]+\.py',command[2]):return False
  else:return False
  if not any('dst=/app' in m and m.startswith('type=bind') for m in mounts):return False
  common=('--network','--memory','--cpus','--pids-limit','--read-only','--tmpfs','--cap-drop','--security-opt','--user')
  if not all(k in values for k in common):return False
  if command[0] in ('python','/opt/venv/env/bin/python') and command[1:2]!=['-c']:
   if '--cap-add' in values:return False
   if values.get('--network')!='none' or values.get('--memory')!='256m' or values.get('--memory-swap')!='256m' or values.get('--cpus')!='0.50' or values.get('--pids-limit')!='128' or values.get('--user')!='10001:10001' or values.get('--ulimit')!='cpu=86400:86400':return False
   if values.get('--tmpfs')!='/tmp:rw,noexec,nosuid,size=32m' or values.get('--cap-drop')!='ALL' or values.get('--security-opt')!='no-new-privileges':return False
   if '--read-only' not in a:return False
   if values.get('--log-driver')!='json-file' or '--log-opt' not in values or values.get('--env') not in ('PYTHONDONTWRITEBYTECODE=1','PYTHONUNBUFFERED=1'):return False
   if not all(x in a for x in ('max-size=10m','max-file=3','PYTHONDONTWRITEBYTECODE=1','PYTHONUNBUFFERED=1')):return False
   if not any(m.startswith('type=bind') and m.endswith(',readonly') and 'dst=/app' in m for m in mounts):return False
   if any(m.startswith('type=volume') and not m.endswith(',readonly') for m in mounts):return False
  elif command[0]=='python' and command[1:2]==['-c']:
   if '--cap-add' in values:return False
   if values.get('--memory')!='512m' or values.get('--pids-limit')!='96' or values.get('--user')!='10001:10001':return False
   if values.get('--memory-swap')!='512m' or values.get('--cpus')!='0.50' or values.get('--tmpfs')!='/tmp:rw,noexec,nosuid,size=64m' or values.get('--cap-drop')!='ALL' or values.get('--security-opt')!='no-new-privileges' or '--read-only' not in a:return False
   if not any(m.startswith('type=bind') and m.endswith(',readonly') and 'dst=/app' in m for m in mounts):return False
   if not any(m.startswith('type=volume') and 'dst=/opt/venv' in m and not m.endswith(',readonly') for m in mounts):return False
  return True
 return False
@app.get('/health')
def health():
 try:
  r=run(['info'],5)
  if r.returncode:raise HTTPException(503,'Docker engine unavailable')
  return {'ready':True}
 except HTTPException:raise
 except Exception:raise HTTPException(503,'Runner unavailable')
@app.post('/v1/docker')
def docker_call(req:Command,authorization:str=Header(default='')):
 if len(TOKEN.encode())<32 or TOKEN.startswith('REPLACE_') or not hmac.compare_digest(authorization.removeprefix('Bearer ').strip(),TOKEN):raise HTTPException(401,'Unauthorized')
 if not allowed(req.args):raise HTTPException(403,'Docker operation rejected by runner policy')
 try:r=run(req.args,timeout=300 if req.args[0]=='run' and INSTALL_SCRIPT in req.args else 25)
 except subprocess.TimeoutExpired:raise HTTPException(504,'Runner operation timed out')
 return {'returncode':r.returncode,'stdout':r.stdout[-200000:],'stderr':r.stderr[-200000:]}
