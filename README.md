# توصيلة – النسخة الكاملة

سيرفر Node.js + قاعدة بيانات SQLite + خريطة جوجل (Routes API). عميل وسائق بحسابات حقيقية، والطلبات بتتنقل بينهم عن طريق السيرفر.

## تشغيل على جهازك
1. نزّل Node.js 18 أو أحدث.
2. جوه الفولدر: `npm install`
3. انسخ `.env.example` لـ `.env` وعدّل القيم (JWT_SECRET لازم نص عشوائي طويل).
4. `npm start` وافتح http://localhost:3000

## مفتاح جوجل
في Google Cloud: فعّل **Maps JavaScript API** و **Routes API**، واعمل API key وقيّده بدومين موقعك. اعمل Map ID من Map Management وحطه في `MAP_ID`.

## الرفع على الإنترنت
ارفعه على Render أو Railway أو VPS (محتاج HTTPS). قاعدة SQLite لازم تتخزن على disk دائم، حدد مكانه بـ `DB_FILE=/data/data.db`.

## اللي لسه ناقص قبل الإطلاق الفعلي
- الدفع (Fawry / Paymob).
- تأكيد رقم الموبايل برسالة SMS.
- تتبع موقع السائق لحظيًا (WebSocket).
- لوحة إدارة، وتقييم الرحلات، وسياسة خصوصية وشروط استخدام.
