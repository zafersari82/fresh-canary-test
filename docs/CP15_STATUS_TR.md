# CP15 — canlı doğrulama henüz tamamlanmadı

22 Eylül 2026 itibarıyla durum: `INCOMPLETE_RUNTIME_FAILURE`.

Girdi CP14 SHA-256: `d7853514f5158085064a615525a4c2c2fe3a909d418069d0306b48b93e83e7f6`.

OpenShell kaynak pini: `484f0768fc6a0d93e0a2be295c1679aed24e18a9`.

CI dalı: `cp15-durable-lifecycle`; çalıştırılmış commit: `86d3107c2e10c2d37575fe6bb901f5f563b01f04`.

[CI çalışması 35653624859](https://github.com/zafersari82/fresh-canary-test/actions/runs/35653624859).

## Doğrulanmış sonuçlar

GitHub'ın açık job API yanıtında aşağıdaki adımlar başarılıdır:

- Bağımsız Python parser kontrolleri ve sabit kaynağa entegrasyon.
- Eski writer'ın daha önce yazdığı permit ile dispatch yapabilmesini gösteren negatif kontrol; workflow yalnız beklenen `CP15_STALE_DISPATCH` hatasını kabul eder.
- Dispatch admission'ı kalıcı writer kilidiyle birleştiren düzeltmeden sonraki Rust regresyonları.
- Gerçek supervisor ve statik sandbox ikililerinin derlenmesi.

`Full gateway supervisor sandbox lifecycle` adımı başarısızdır. 22 Eylül'de yeniden erişilebilen ham log, supervisor'ın `libgcc_s.so.1` eksikliği yüzünden başlangıçta durduğunu doğruladı. Hiçbir receiver aşamasına ulaşılamadı. Aynı logda 30 Rust regresyonu geçti.

## Bu devam adımında bulunan ve düzeltilen hata

Test, gateway'i öldürüp yeniden başlatarak aynı supervisor'ın yeniden bağlanmasını bekliyordu. Pinned Docker driver gateway startup sırasında supervisor'ı yeniden oluşturur. Bu nedenle senaryo aynı-supervisor şartını karşılayamaz.

Düzeltilmiş test, wrapper'ın sahibi olduğu gateway PID'sine SIGSTOP gönderir. Aynı supervisor'ın logunda başlangıca göre yeni bir `supervisor session failed, reconnecting` olayı gözlenmeden ilerlemez; 90 saniyelik deadline aşılırsa başarısız olur. Ardından SIGCONT gönderir. Panic/unwind sırasında da duraklatma koruması SIGCONT gönderir.

Devam sonrasında yeni kabul edilmiş session, aynı supervisor container kimliği, aynı writer token, aynı kalıcı volume ve değişmemiş journal prefix şarttır. Üç ağ yolu tekrar gerçek sandbox üzerinden receiver'a gitmelidir. Forced stop/start aşamasına da açık supervisor değişimi ve volume korunması kontrolleri eklendi.

Bu reconnect kaynak hatası bağımsız incelemede doğrulandı; düzeltme tekrar incelendi ve yeni somut bulgu çıkmadı. İlk CI başarısızlığının nedeni ayrıca eksik GNU unwind kütüphanesidir. CP15'in native GNU CI derlemesinin gerektirdiği `libgcc_s.so.1` artık build hostundan image'a taşınıyor; dosyanın SHA-256 değeri ve ikilinin shared-library listesi kaydediliyor. Supervisor image'ının aynı kısıtlı kullanıcıyla `--help` başlangıcı yaşam döngüsünden önce zorunlu kontrol oldu. Bu CI derlemesi upstream'in release/glibc 2.28 dağıtım sözleşmesini kanıtlamaz.

Düzeltmelerin canlı doğrulaması bekliyor. Yerelde 13 Python kontrolü, temiz kaynak pinine uygulama ve `git diff --check` başarılıdır.

## Engellenen iş ve devam noktası

Önceki GitHub bağlantı hatası bu devam adımında kalktı ve ham job logu alındı. Tam Docker yaşam döngüsü CI'da tekrar çalıştırılacak; yerel ortamda Docker daemon/socket, Rust toolchain ve etkin Linux yetenekleri bulunmuyor.

Erişim sağlandığında:

1. İlk başarısız çalışmanın job logunu koru: `106511732590`; artifact `10662814658`, adı `cp15-lifecycle-35653624859-1`, API digest'i `sha256:9fe8eeb258ef9ce40c64a1622aa1d9a33de5f86a01f58004a0740813341ac7ce`. Artifact ZIP baytlarının indirilmesi henüz doğrulanmadı.
2. Logla doğrulanan başlangıç hatasını (`libgcc_s.so.1`) reconnect senaryosu hatasından ayrı tut.
3. Reconnect ve GNU runtime düzeltmelerini aynı dala gönder; exact commit üzerinde workflow'u tekrar çalıştır.
4. Başarılı görünen çalışma için de ham journal, witness, receiver kayıtları, session/writer/container/volume kimlikleri ve dört aşamanın prefix ilişkisini artifact'tan bağımsız doğrula.

## İddia sınırı

Yeşil bir yaşam döngüsü testi bile üretim sertifikası değildir. Source SEAL, receiver'da wire-level operation ID, fsync ile receiver gözlemi arasında nedensel bariyer, authenticated remote witness, birlikte journal/witness rollback tespiti ve fiziksel güç kaybı testi bu aşamada kurulmadı. Sonuçlar `coverage=NOT_ESTABLISHED`, `outcome=OUTCOME_UNKNOWN` sınırında kalır; imza veya hash kontrolü bunları yükseltmez.
