import getpass, os, sys, uuid
from argon2 import PasswordHasher
from app import OWNER_EMAIL, db, utc, user_root

print(f'تهيئة حساب مالك Sea Host: {OWNER_EMAIL}')
with db() as c:
    existing = c.execute('SELECT id FROM users WHERE email=?', (OWNER_EMAIL,)).fetchone()
if existing and input('يوجد حساب للمالك؛ اكتب RESET لتأكيد تغيير كلمة مروره: ').strip() != 'RESET':
    sys.exit('ألغيت إعادة تعيين حساب المالك.')
password = getpass.getpass('كلمة مرور جديدة (12 حرفًا على الأقل): ')
if len(password) < 12:
    sys.exit('كلمة المرور قصيرة؛ يلزم 12 حرفًا على الأقل.')
confirm = getpass.getpass('أعد كلمة المرور: ')
if password != confirm:
    sys.exit('كلمتا المرور غير متطابقتين.')
encoded = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2).hash(password)
if existing:
    with db() as c:
        c.execute("UPDATE users SET password=?, role='admin' WHERE id=?", (encoded, existing['id']))
    print('تم تحديث كلمة مرور حساب المالك.')
else:
    uid = uuid.uuid4().hex
    with db() as c:
        c.execute('INSERT INTO users(id,email,password,role,created) VALUES(?,?,?,?,?)', (uid, OWNER_EMAIL, encoded, 'admin', utc()))
    user_root(uid)
    print('تم إنشاء حساب المالك.')
