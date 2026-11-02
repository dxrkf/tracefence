# Arabic

بنيت TraceFence للإجابة عن سؤال محدد: هل قيمة حساسة دخلت إلى وكيل ذكاء اصطناعي ظهرت لاحقًا في طلب أداة إرسال، حتى بعد تغيير ترميزها؟

يربط المصدر بطلب الإرسال والموضع الذي ظهرت فيه القيمة، ويدعم plaintext وURL encoding وBase64 وhex. التقرير يخفي القيم المسجّلة، والأداة تعمل محليًا دون مكتبات خارجية.

أرفقت تجربة تسرب اصطناعية، وحالة سليمة، ومثال فحص قبل التنفيذ، و14 اختبارًا. الأداة تثبت تطابق بيانات يستحق المراجعة؛ لا تحكم على النية ولا تدّعي كشف كل التسربات.

https://github.com/dxrkf/tracefence

#AISecurity #AgentSecurity #Python #CyberSecurity

# English

Introducing TraceFence: an offline Python prototype for reviewing known sensitive-data flows across explicitly instrumented AI agent tool boundaries.

Link registered source values to later outbound payloads and destinations—even in supported URL, Base64 or hex representations. Get source-to-sink evidence with known values redacted from the report.

Includes a synthetic leak, a clean trace, a pre-execution integration demo and 14 tests. Matches require authorization review; no claim of universal leak or prompt-injection detection.

https://github.com/dxrkf/tracefence

Attach assets/cover.png and assets/demo-output.png.
