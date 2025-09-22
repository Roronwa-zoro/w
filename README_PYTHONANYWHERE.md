# رفع التطبيق على PythonAnywhere

## الملفات المطلوبة:
- `app.py` - التطبيق الرئيسي
- `config.py` - إعدادات التطبيق
- `wsgi.py` - ملف WSGI للخادم
- `requirements.txt` - المكتبات المطلوبة
- `templates/` - مجلد القوالب
- `static/` - مجلد الملفات الثابتة

## خطوات الرفع:

### 1. إنشاء حساب على PythonAnywhere
- اذهب إلى: https://www.pythonanywhere.com
- سجل حساب جديد (مجاني)

### 2. رفع الملفات
- استخدم Files tab لرفع جميع الملفات
- أو استخدم Git لاستنساخ المشروع

### 3. تثبيت المكتبات
```bash
pip3.10 install --user -r requirements.txt
```

### 4. إنشاء مجلد uploads
```bash
mkdir -p static/uploads
```

### 5. إعداد Web App
- اذهب إلى Web tab
- اضغط "Add a new web app"
- اختر "Manual configuration"
- اختر Python 3.10
- في Source code: ضع مسار المشروع
- في WSGI configuration file: ضع مسار wsgi.py

### 6. تعديل wsgi.py
- غيّر `yourusername` إلى اسم المستخدم الخاص بك
- غيّر `mysite` إلى اسم مجلد المشروع

### 7. إعادة تشغيل التطبيق
- اضغط "Reload" في Web tab

## معلومات الدخول:
- Username: mounir
- Password: 3mmk

## الميزات:
- إدارة المرضى
- رفع صور جداول المناوبات والعمليات
- نظام تسجيل الدخول
- سجل التعديلات
