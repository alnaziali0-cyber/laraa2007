# نشر Sea Host على جهازك الدائم (Ubuntu 24.04)

هذا الدليل يشغّل النسخة الموجودة في مستودع `alnaziali0-cyber/laraa2007` على جهاز Linux تملكه. أفترض **Ubuntu 24.04 LTS**، نطاقًا تملكه، وإمكان الوصول إلى إعدادات الراوتر. إذا كان جهازك Windows أو macOS، لا تنفّذ أوامر `apt` هنا؛ أخبرني بنظام التشغيل لأعطيك خطوات ملائمة. تشغيل WSL2/Docker Desktop مناسب للتجربة أكثر من خادم عام دائم.

> **مهم:** استخدم جهازًا مخصصًا أو نظامًا معزولًا قدر الإمكان. خدمة `runner` وحدها تصل إلى Docker socket؛ إذا تم اختراقها فالأثر المحتمل على المضيف كبير، حتى مع قيود الأوامر والحاويات. لا تفتح حسابات عامة ولا تستضف مشاريع أشخاص غير موثوقين على جهازك الشخصي. النسخة الحالية تقيّد شبكات مشاريع المستخدمين افتراضيًا، ولا تفرض حصّة قرص حقيقية على ملفات عمليات Docker.

## 1) جهّز الجهاز والشبكة

- اترك الجهاز موصولًا بالطاقة والإنترنت طوال الوقت، وعطّل النوم/الإسبات التلقائي. إذا كان لابتوبًا، راعِ الحرارة وعمر البطارية.
- اجعل عنوان الجهاز **ثابتًا داخل الشبكة المحلية** من الراوتر (DHCP reservation).
- للوصول العام، تحتاج نطاقًا يشير سجل `A` فيه إلى عنوان الإنترنت العام للراوتر، وإعادة توجيه `80/tcp` و`443/tcp` من الراوتر إلى الجهاز. إذا كان اتصالك خلف **CGNAT** أو لا تملك عنوانًا عامًا، فلن تكفي إعادة التوجيه المعتادة؛ استخدم نفقًا مُدارًا أو خادمًا عامًا بدل كشف منافذ أخرى.
- لا توجّه المنفذين `8000` أو `8091` من الراوتر إلى الإنترنت. المنفذ 8000 مربوط على `127.0.0.1` فقط، و8091 داخلي لعامل Docker.

## 2) ثبّت Docker Engine وCompose

استخدم مستودع Docker الرسمي، وليس سكربت تثبيت عشوائيًا. إذا كان Docker مثبتًا مسبقًا، تحقّق منه بدل إزالة حزم دون مراجعة.

```bash
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker run --rm hello-world
sudo docker compose version
```

سأستخدم `sudo docker ...` أدناه، بدل إضافة الحساب إلى مجموعة `docker`؛ عضوية تلك المجموعة تعادل عمليًا صلاحية عالية على المضيف.

## 3) نزّل المشروع وأنشئ الإعدادات

ثبّت GitHub CLI وسجّل الدخول إذا كان المستودع خاصًا، ثم:

```bash
sudo apt install -y git gh
# عند الحاجة لمستودع خاص:
gh auth login
gh repo clone alnaziali0-cyber/laraa2007
cd laraa2007
cp .env.example .env
```

أنشئ سرّي التطبيق تلقائيًا داخل ملف `.env` دون طباعتهما على الشاشة أو كتابتهما في سجل الأوامر:

```bash
python3 - <<'PY'
from pathlib import Path
import secrets
p = Path('.env')
s = p.read_text()
s = s.replace('RUNNER_TOKEN=REPLACE_WITH_A_RANDOM_SECRET_AT_LEAST_32_BYTES', 'RUNNER_TOKEN=' + secrets.token_hex(32))
s = s.replace('APP_SECRET_KEY=REPLACE_WITH_A_SEPARATE_RANDOM_SECRET_AT_LEAST_32_BYTES', 'APP_SECRET_KEY=' + secrets.token_hex(32))
p.write_text(s)
p.chmod(0o600)
PY
```

افتح `.env` بمحرر محلي، وتحقق من الإعدادات التالية. الملف خاص بهذا الجهاز ويجب ألا يُرفع إلى Git:

```bash
nano .env
```

- `HOSTPANEL_DATA_DIR=/srv/seahost-data`
- `OWNER_EMAIL=aaaq70232@gmail.com`
- `SMTP_HOST=smtp.gmail.com`
- `SMTP_PORT=587`
- `SMTP_USERNAME=aaaq70232@gmail.com`
- `SMTP_FROM=aaaq70232@gmail.com`
- `SMTP_PASSWORD=` ضع هنا **Gmail App Password** فقط، بلا مسافات
- `COOKIE_SECURE=1`
- اترك `RUNNER_BUILD_NETWORK=none` و`RUNNER_API_URL=http://runner:8091` كما هما في البداية.

لحساب Gmail، فعّل التحقق بخطوتين أولًا، ثم أنشئ App Password مخصصًا من [إعدادات App Passwords لدى Google](https://myaccount.google.com/apppasswords). لا تستخدم كلمة مرور حساب Google العادية، ولا ترسل App Password في المحادثة. قد لا يظهر الخيار لبعض حسابات المؤسسات أو الحسابات التي عليها Advanced Protection.

حضّر مساحة البيانات الدائمة بالمالك الذي تستخدمه الحاوية (UID 10001):

```bash
sudo install -d -o 10001 -g 10001 -m 0750 /srv/seahost-data
chmod 600 .env
```

لا ترفع `.env` أو النسخ الاحتياطية التي تحتويه إلى المستودع. احفظ نسخة احتياطية مشفّرة للأسرار في مكان آمن خارج الجهاز.

## 4) ابنِ الخدمات وأنشئ حساب المالك

من مجلد المستودع نفسه:

```bash
sudo docker compose config --quiet
sudo docker compose build
sudo docker compose run --rm --no-deps panel python create_owner.py
sudo docker compose up -d
sudo docker compose ps
```

سيطلب `create_owner.py` كلمة مرور المالك مرتين تفاعليًا؛ أدخلها في الطرفية فقط. لا يوجد تسجيل عام ولا كلمة مرور افتراضية. بعد نجاح تهيئة SMTP، يسجّل الدخول بكلمة المرور ثم رمز OTP المرسل إلى البريد.

افحص مؤشرات الجاهزية وسجلات الخدمات:

```bash
curl -fsS http://127.0.0.1:8000/api/health
sudo docker compose logs --tail=80 panel runner
```

قبل ضبط البريد، يتوقع أن تكون `mail_ready` غير جاهزة؛ وبعد إعداد SMTP الصحيح ينبغي أن تصبح `true`. يجب ألا ترى منفذ العامل `8091` منشورًا، ولا ينبغي أن تضع أسرار SMTP أو App Password في HTML أو JavaScript.

## 5) أضف نطاقًا وHTTPS عبر Caddy

ثبّت Caddy من مستودعه الرسمي على Ubuntu:

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
```

أنشئ سجل `A` لنطاقك يوجّه إلى عنوان الإنترنت العام، ثم أعد توجيه المنافذ 80 و443 على الراوتر إلى عنوان الجهاز المحلي. بعد ذلك حرّر إعداد Caddy:

```bash
sudo nano /etc/caddy/Caddyfile
```

ضع نطاقك الحقيقي بدل `sea.example.com`:

```caddyfile
sea.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

افتح الجدار الناري على الجهاز (أضف قاعدة SSH أولًا إذا كنت متصلًا به عن بُعد)، ثم تحقّق وأعد تحميل Caddy:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status
sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

عندما يكون سجل DNS صحيحًا والمنفذان 80 و443 قابلين للوصول من الإنترنت، يتولى Caddy إصدار شهادة HTTPS وتجديدها تلقائيًا. افتح `https://sea.example.com` واختبر:

```bash
curl -fsS https://sea.example.com/api/health
```

لا تغيّر ربط Compose إلى `0.0.0.0:8000`، ولا تنشر `8091`، ولا تفتح منفذ Docker daemon للإنترنت.

## 6) فحوص الاستمرار والنسخ الاحتياطي

- خدمات Compose مضبوطة على `restart: unless-stopped`؛ مع تفعيل خدمة Docker ستعود بعد إعادة تشغيل الجهاز. تحقّق بعد أول إعادة تشغيل مخطط لها.
- لا تجعل الجهاز يدخل في Sleep/Suspend؛ هذا يوقف الموقع حتى لو كانت إعدادات Docker صحيحة.
- بيانات لوحة التحكم والملفات في `/srv/seahost-data`. احتفظ بنسخة احتياطية دورية خارج الجهاز، واختبر الاستعادة. لتجنب نسخ SQLite أثناء كتابة نشطة، أوقف الخدمتين أثناء النسخ:

```bash
sudo docker compose stop panel runner
sudo tar -czf "$HOME/seahost-data-backup-$(date +%F).tar.gz" /srv/seahost-data
sudo docker compose start runner panel
```

احتفظ بملف `.env` منفصلًا ومشفّرًا؛ لا يحتوي مجلد البيانات على جميع أسرار التشغيل.

## قيود شبكة المشاريع

الأمان الافتراضي يمنع حاويات مشاريع Python من الوصول إلى الإنترنت (`network none`). لذلك قد لا يعمل `pip install` لتنزيل اعتمادية من PyPI، وقد لا تتمكن البوتات من الاتصال بـ APIs خارجية. **لا تغيّر الإعداد إلى شبكة Docker عامة مباشرة.** السماح بالخروج يحتاج شبكة egress وجدارًا ناريًا يمنع الشبكات الخاصة وعناوين metadata وخدمات الإدارة؛ راجع قسم «شبكة تثبيت الحزم الاختيارية» في [README](README.md) قبل أي تغيير. كما أن حصة الملفات في التطبيق ليست بديلًا عن حصص قرص Linux الفعلية.

## حدود هذا المسار

هذا الدليل موجّه إلى Ubuntu 24.04. إعداد Windows/WSL2 أو macOS يختلف في بدء الخدمات والشبكات وتوجيه منافذ الراوتر. كما أن تشغيله من منزل يعتمد على الكهرباء والإنترنت وDNS/CGNAT، وليس له ضمان إتاحة من مزود خوادم. استخدم خادمًا منفصلًا أو استضافة مناسبة إذا احتجت وقت تشغيل أعلى أو إذا لم يكن الراوتر يتيح منافذ عامة.

## مصادر رسمية

- [تثبيت Docker Engine على Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Google: تسجيل الدخول باستخدام App Passwords](https://support.google.com/mail/answer/185833?hl=ar)
- [تثبيت Caddy](https://caddyserver.com/docs/install)
- [HTTPS التلقائي من Caddy ومتطلباته](https://caddyserver.com/docs/automatic-https)
- [توجيه Reverse Proxy في Caddy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)
