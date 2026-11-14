# Toolgate

Agent'ların tek bildiği yerel bir MCP ucu (`http://localhost:7777/mcp`). Arkasında N tane MCP sunucusu, veritabanı ve API durur. Şifreler gateway'in kasasında tutulur. Agent'lar şifreleri hiçbir zaman görmez.

```
Claude Code / Codex / Gemini CLI / kendi agent'ın
              │  Authorization: Bearer agw_…  (agent başına token)
              ▼
     Toolgate  ──  kasa (AES-256-GCM, ana anahtar Keychain'de)
     5 meta-tool        policy (sunucu + agent bazlı glob)
                        audit (SQLite)
              │
     ┌────────┼──────────┬───────────────┐
  stdio MCP  http MCP   http MCP+OAuth   …
  (postgres, (github,   (cloudflare,
   sqlite…)   docs…)     notion…)
```

## Agent'ın gördükleri

Varsayılan (lazy) modda agent'a sadece 5 tool açılır. Gerçek tool'lar aramayla keşfedilir, böylece context dolmaz:

| Tool | İşlevi |
|---|---|
| `overview` | Bütün sunucular, durumları, tool sayıları ve örnek tool'lar. Açıklamasında güncel özet de var. Aynı özet MCP `instructions` olarak da gönderilir. |
| `search_tools` | Bütün upstream tool'larında anahtar kelime araması (iki geçişli, aşağıda). Policy'nin gizlediği, onay bekleyen ve kapalı bağlantılardaki tool'lar hiç görünmez. |
| `describe_tools` | Seçilen tool'ların input şeması ve annotation'ları. |
| `call_tool` | `server.tool` + argümanlar. Policy kontrolü yapılır, audit'e yazılır, isteği ilgili sunucuya yönlendirir. |
| `manage` | Yalnızca `can_manage` agent'larda var: sunucu ekleme/düzenleme, katalog arama/kurma, OAuth başlatma, şifre isteme, tool kısıtlama, audit okuma. |

**"Bana sadece login'i bırak" akışı:** Agent `manage catalog_install` ile bir sunucu kurar. Sunucu OAuth istiyorsa gateway bir login linki döndürür; agent bu linki kullanıcıya verir. Kullanıcı tarayıcıda onayladığında callback `localhost:7777/oauth/callback` adresine gelir, gateway token'ı alıp kasaya yazar, bağlantıyı tamamlar ve token süresi dolunca kendisi yeniler. Dynamic Client Registration desteklenir; önceden kayıtlı bir OAuth uygulaması varsa `oauth_client_id` + `oauth_client_secret_ref` ile de kullanılabilir.

**Tool sunumu (lazy / direct / otomatik):** Her agent için seçilir (Agent'lar > agent > Tool sunumu); seçilmezse panelin varsayılanı kullanılır (kurulumda `lazy`).

- `lazy`: yukarıdaki 5 meta tool. Bağlam küçük kalır, çok sayıda tool varsa en iyisi.
- `direct`: agent'ın kullanabileceği her tool, gerçek şemasıyla doğrudan listelenir. Adı `<sunucu>__<tool>` olur (MCP istemcilerinin kabul ettiği `[A-Za-z0-9_-]{1,64}`; uzun adlar özetle kısaltılır). Yanında `overview` ve (yetkisi varsa) `manage` kalır. En fazla 128 tool listelenir; fazlası varsa `search_tools`/`describe_tools`/`call_tool` da eklenir ve instructions bunu söyler.
- `auto`: agent'ın gördüğü tool sayısı 40 ya da daha azsa `direct`, fazlaysa `lazy`.
- Tek bir istemci için bağlantı adresine `?tools=lazy|direct|auto` eklenebilir; bu, agent ayarından önce gelir.
- Direct tool'lar `call_tool` ile aynı yoldan geçer: policy, onay bekleyen tool'ların gizlenmesi, sunucu onayı ve audit aynıdır. Kapalı, onaylanmamış, yasaklı ya da onay bekleyen tool'lar listelenmez.
- Agent formunda her modun bu agent için kaç tool ve yaklaşık kaç KB tuttuğu (gerçek `tools/list` + instructions ölçülerek) gösterilir. İstemciler listeyi genelde bağlanırken bir kez aldığı için mod değişikliği yeniden bağlanınca geçerli olur.

**Arama iki geçişlidir:** Önce *sıkı* geçiş çalışır: sorgudaki her anlamlı kelime (`the`, `to` gibi dolgu kelimeleri hariç) tool adında, açıklamasında ya da bağlantının id/ad/açıklama/amaç metninde birebir, kök olarak (`issues` ≈ `issue`) ya da önek olarak geçmelidir; `snake_case` ve `camelCase` adlar kelimelere ayrılır. Sıkı geçiş bir şey bulamazsa *gevşek* geçiş devreye girer: kelimelerden biri yeterlidir, küçük bir eş anlamlılar tablosu (`add` ≈ `create`, `ticket` ≈ `issue`, `mail` ≈ `email` …) ve bir harf hatası (uzun kelimelerde iki) kabul edilir. Sonuçta `match` alanı `strict`, `loose` ya da `none` olur; `loose` ve `none` için agent'a ne yapacağını söyleyen bir `note` eklenir. Boş sorgu her şeyi listeler.

**Bulunamayan aramalar:** Her `search_tools` çağrısı günlük olarak sayılır (tam eşleşme, gevşek eşleşme, bulunamadı). Hiçbir şey bulamayan sorgular normalize edilip (küçük harf, noktalama yok) toplanır: kaç kez arandığı, son hangi agent'ın aradığı ve ne zaman. Etkinlik sayfasının üstündeki "Tool aramaları" kutusu bunları gösterir; sık tekrarlanan bir arama genelde eksik bir bağlantıdır, "Katalogda ara" ile doğrudan katalogda aranabilir. Kayıtlar audit saklama süresine uyar. Audit argüman modu `none` ise sorgu metni saklanmaz, yalnızca sayılır; `none`'a geçerken "eski kayıtları temizle" seçilirse saklanmış sorgular da silinir.

**Bağlantı amacı:** Panelde her bağlantıya kısa bir "Amaç" yazılabilir (ör. "Şirket hesabı, prod ortamı"). Amaç, `search_tools` ve `describe_tools` çıktısında her tool açıklamasının başına `[amaç]` olarak eklenir; `overview` ve `instructions` içinde de görünür, ayrıca aramada eşleşir. Böylece aynı türden iki bağlantı olduğunda agent doğrusunu seçebilir. Amaç bütün agent'ların okuduğu metne girdiği için yalnızca kullanıcı yazabilir: agent'ın `upsert_server` ile gönderdiği değer yok sayılır, katalogdan yeniden kurmak da kullanıcının yazdığını korur. En fazla 160 karakterdir, satır sonları tek boşluğa indirilir.

**Şifre gerektiğinde:** Agent `manage request_secret` ile arayüzde ilgili kaydın açık olduğu bir link üretir. Kullanıcı değeri arayüzde girer, değer sohbete hiç düşmez.

## Kurulum

> Asıl belge İngilizce [README.md](README.md); bu çeviri geride kalabilir.

```bash
./scripts/install.sh            # derler, sonra: sudo bin/toolgate install
```

`toolgate install` her şeyi kendisi kurar ve her adımı çalıştırmadan önce yazar (`--dry-run` yalnızca planı gösterir). Yükseltmek için yeniden çalıştırılır; veriler korunur.

### Önerilen: ayrı kullanıcıyla (yalıtılmış, yönetici hesabı gerekir)

`sudo toolgate install`

- **macOS:** gizli `_toolgate` kullanıcısı (kabuksuz, parolasız), LaunchDaemon `io.github.nekinci.toolgate`, veri `/Library/Application Support/Toolgate` (700), çıktılar `/Users/Shared/Toolgate/outputs`.
- **Linux:** `toolgate` sistem kullanıcısı, kısıtlı (sandbox'lı) systemd birimi `toolgate.service` (`ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges`…), veri `/var/lib/toolgate` (700), çıktılar `/var/lib/toolgate-outputs`, log `journalctl -u toolgate`.
- İkili `/usr/local/libexec/toolgate/toolgate`, `/usr/local/bin`'den bağlanır. Kurulum panel parolasını sorar (`--password-stdin` ile de verilebilir).

Senin kullanıcınla çalışan agent'lar (shell erişimi olanlar dahil) kasayı okuyamaz, gateway process'lerinin ortam değişkenlerini göremez. stdio MCP sunucuları da servis kullanıcısıyla çalıştığı için senin dosyalarına dokunamaz; bir klasöre erişmesi gerekiyorsa o kullanıcıya okuma izni ver.

Mevcut bir kurulumdan taşımak için: `toolgate migrate-export -out ~/agw-export`, sonra `sudo toolgate install --from ~/agw-export`. Dışa aktarım kopyalandıktan sonra silinir; eski `~/.toolgate` yalnızca `--remove-old-data` verilirse silinir.

Kaldırmak için: `sudo toolgate uninstall` (`--purge` ile veriler ve servis kullanıcısı da silinir). Durum: `toolgate status`.

### Hızlı: kendi kullanıcınla

`toolgate install --user` (sudo gerekmez; macOS'ta ana anahtar Anahtar Zinciri'nde). Panel linki: `toolgate admin-url`. Bu modda kasa, senin kullanıcınla çalışan ve shell erişimi olan agent'lara karşı korunmaz.

### Agent'ları bağlamak

Panelde **Agent'lar → Agent ekle** varsayılan olarak bir **eşleştirme kodu** verir (ör. `VCGM-FRW8`): tek kullanımlık, 10 dakika geçerli. Panel her istemci için kodu içeren hazır bir komut gösterir; komut kodu `POST /pair` ile anahtara çevirip doğrudan istemcinin ayarına yazar, anahtar ekranda ya da sohbette hiç görünmez:

```bash
T=$(curl -fsS http://localhost:7777/pair -d code=VCGM-FRW8 -d format=token) && \
  claude mcp add --scope user --transport http gateway http://localhost:7777/mcp --header "Authorization: Bearer $T"
```

- Claude Code, Codex (`codex mcp add … --bearer-token-env-var`), Gemini CLI için komutlar; "Agent'a ver" sekmesi başka bir agent'ın sohbetine yapıştırılacak hazır bir metin verir (agent komutu kendisi çalıştırır). "Diğer" sekmesi JSON döndüren `curl` komutunu verir.
- Kod geçersizse ya da süresi dolduysa `curl -f` başarısız olur ve komutun geri kalanı çalışmaz, yani bozuk bir ayar yazılmaz.
- Kod kullanıldığında o agent için yeni bir anahtar üretilir; varsa eski anahtar geçersiz olur. Aynı agent için yeni kod istemek eskisini iptal eder. Kodlar yalnızca bellekte (hash'li) tutulur; art arda 20 yanlış denemede `/pair` 10 dakika kilitlenir.
- Anahtarı doğrudan görmek istersen "Eşleştirme kodu yerine anahtarı göster" seçilebilir ya da mevcut agent'ta "Yeni anahtarı göster" kullanılabilir.
- Aynı akış Uygulamalar (API proxy) için de vardır: kod `export TOOLGATE_APP_TOKEN=…` komutuna gömülür.

**Anahtar süresi:** Her agent ve uygulama için süresiz, 30/90/180 gün ya da 1 yıl seçilebilir. Süre anahtar üretildiğinde (oluşturma, yenileme, eşleştirme) ve süre ayarı değiştirildiğinde o andan başlar. Süresi dolan anahtar reddedilir; hata mesajı yeni kodun panelden alınacağını söyler. Son 7 günde agent'ın instructions'ına bir uyarı eklenir ki agent kullanıcıya söyleyebilsin; panel listesi 14 gün kala uyarır.

## Admin arayüzü (`/ui`)

- **Sunucular:** durum, bağlan/kes, OAuth girişi, tool listesi. İşaretlenmeyen tool'lar bütün agent'lardan gizlenir. "Sadece salt-okur" kısayolu var. JSON ile düzenleme ve stderr logları da burada.
- **Katalog:**
  - **Önerilen:** gateway şablonları ve popüler Claude connector'leri.
  - **Claude dizini:** ~320 connector, yerelde önbelleklenir ve 12 saatte bir yenilenir.
  - **Benim:** kendi eklediğiniz şablonlar.
  - **Topluluk:** resmi MCP Registry, sadece aramayla.
  - Kartlarda ikon, auth türü ve "kurulu" işareti görünür. Karta tıklayınca kurulum penceresi açılır: auth seçimi, gerekli adımlar, bölge veya adres gibi alanlar. Giriş gerekiyorsa login sekmesi açılır ve pencere bağlantı tamamlanana kadar bekler.
  - Aynı connector farklı id ile birden çok kez kurulabilir (`pg-prod`, `pg-staging`, …).
  - **GitHub:** GitHub OAuth otomatik istemci kaydını (DCR) desteklemez. "GitHub ile giriş" seçeneği bir kerelik OAuth App oluşturma adımlarını gösterir (callback: `http://localhost:7777/oauth/callback`). Alternatif olarak izinleri önceden seçilmiş bir PAT kullanılabilir.
  - **Cloudflare:** gateway şablonu `mcp.cloudflare.com` adresidir (izin seçme ekranı olan tüm API). Claude dizinindeki "Cloudflare Developer Platform" ise `bindings` sunucusudur.
- **Kasa:** şifreler sadece yazılabilir. Hangi sunucunun hangi şifreyi kullandığı ve eksik şifreler listelenir.
- **Agent'lar:** token oluşturma/yenileme, allow/deny kalıpları, yönetim yetkisi, "ne görüyor?" önizlemesi.
- **Tool deneme (playground):** bağlantının Tool'lar sekmesinde her tool'un "Dene" düğmesi, girdi şemasından üretilen bir form açar: enum'lar seçim kutusu, sayılar sayı alanı, düz diziler satır satır metin, iç içe nesneler JSON alanı olur; zorunlu alanlar başta ve işaretlidir. Form ile ham JSON arasında geçiş yapılabilir. Çağrı gerçektir: yönetici olarak ya da seçilen bir agent'ın kısıtlamalarıyla çalışır, sadece izin kontrolü (dry-run) de yapılabilir. `destructiveHint` taşıyan tool'lar için ayrıca onay kutusu istenir; onay bekleyen (yeni ya da değişmiş) tool'lar denenemez. Görsel ve ses çıktıları sayfada gösterilir. Bu çağrılar Etkinlik'te agent kullanımına karışmaz: actor `ui:test` (agent adına çalıştırılırsa `ui:test:<agent>`) olur ve "panel denemeleri" filtresiyle listelenir. Doğrudan link: `#c/<id>?tab=tools&try=<tool>`.
- **Etkinlik (audit):** her çağrı, aksiyon, bağlantı ve OAuth olayı. "Kayıt ayarları"ndan:
  - **Saklama süresi:** varsayılan 90 gün; daha eski kayıtlar saatte bir silinir. `-audit-retention-days N` bayrağı panel ayarını geçersiz kılar.
  - **Tool argümanları:** `full` (değerleriyle; hassas görünen anahtarlar maskelenir, başarılı sonucun kısa alıntısı da saklanır), `keys` (yalnızca argüman adları; varsayılan) ya da `none`. Yönetim işlemleri (`manage.*`, panel) güvenlik kaydı olduğu için her modda maskelenerek saklanır. İstenirse eski kayıtlar da seçilen moda göre temizlenir.

## Gemini (dahili sunucu)

Gateway'in içinde `gemini` adlı dahili bir sunucu vardır (`transport: builtin`). Ayrı bir süreç ya da adres kullanmaz.

- **Anahtar havuzu:** Kasa'da adı `GEMINI_API_KEY` ya da `GEMINI_API_KEY_*` olan her şifre Gemini havuzuna girer (Kasa > Anahtar havuzları). Her çağrıda en az meşgul ve en uzun süredir kullanılmayan anahtar seçilir.
- **Rotasyon:** 429 gelirse anahtar o model için Google'ın verdiği `retryDelay` kadar dinlendirilir. Günlük kota dolduysa Pasifik saatiyle gece yarısına kadar dinlendirilir. Geçersiz ya da yetkisiz anahtar (400 `API_KEY_INVALID`, 401, 403) değiştirilene kadar kullanılmaz. 5xx gelirse 10 saniye beklenip sıradaki anahtar denenir. Anahtar URL'ye değil `x-goog-api-key` başlığına konur.
- **Tool'lar:**
  - `gemini.tts`: tek ses için `text`, `voice`, `style`; diyalog için `turns` ve `speakers` alır. Uzun metin parçalanıp anahtarlara paralel dağıtılır, sonuç tek bir WAV dosyasında birleşir. Üçten fazla konuşmacı varsa her repliği ayrı ayrı seslendirir.
  - `gemini.voices`, `gemini.models` (anahtarların erişebildiği TTS modelleri ve varsayılan), `gemini.pool_status`.
- **API:** önce Interactions API (`/v1beta/interactions`) denenir. 404 alınırsa ya da model eskiyse (`gemini-2.*`, `gemini-3.1-*`) `generateContent` kullanılır.
- **Çıktılar:** `-output-dir` ile ayarlanır (varsayılan `<data>/outputs`). İzole kurulumda `/Users/Shared/Toolgate/outputs` kullanılır: yalnızca servis yazabilir, herkes okuyabilir. Agent dosyayı oradan projeye kopyalar.
- **Kısıtlar:** agent'lar dahili sunucuyu değiştiremez ya da silemez, sadece kapatabilir. Kullanıcı silerse yeniden başlatmada geri gelmez.

## Anahtar havuzları

Aynı servisin birden fazla API anahtarı bir havuzda toplanır (Kasa > Anahtar havuzları > Havuz ekle). Her havuzun bir id'si, adı, sağlayıcısı ve secret ad öneki vardır: öneki `OPENAI_API_KEY` olan havuza `OPENAI_API_KEY` ve `OPENAI_API_KEY_*` adlı şifreler girer. Gateway çağrıları anahtarlar arasında dağıtır, hız sınırına takılanı dinlendirir, geçersiz olanı değiştirilene kadar devre dışı bırakır. Havuzu kaldırmak anahtarları silmez.

| Sağlayıcı | Anahtarın gittiği başlık | Bekleme süresi |
|---|---|---|
| Gemini | `x-goog-api-key` | `RetryInfo.retryDelay`; günlük kota (`QuotaFailure` …PerDay…) Pasifik gece yarısına kadar. Hata bazen dizi içinde gelir. |
| OpenAI | `Authorization: Bearer …` | `Retry-After`, yoksa `x-ratelimit-reset-requests/-tokens`. `insufficient_quota` anahtarı devre dışı bırakır. |
| Anthropic | `x-api-key` (+ `anthropic-version`) | `retry-after`, yoksa `anthropic-ratelimit-*-reset`. 529 geçici sayılır. |
| ElevenLabs | `xi-api-key` | `Retry-After`; `quota_exceeded` 24 saat. |
| Özel | kullanıcının verdiği başlık ve önek | 429'da `Retry-After` (yoksa 60 sn). |

Ortak kurallar: 401/403 geçersiz, 5xx/408 geçici (10 sn sonra başka anahtar). Gemini havuzu (`gemini`) dahili sunucu tarafından kullanıldığı için silinemez; öneki sabittir.

## API proxy (kendi programların için)

Agent'lar dışında kendi yazdığın programlar da havuzdaki anahtarları kullanabilir; gerçek anahtarı hiç görmeden. Agent'lar sayfasındaki **Uygulamalar** bölümünden bir uygulama eklersin, hangi havuzları kullanabileceğini seçersin ve bir kez gösterilen bir uygulama anahtarı (`agp_…`) alırsın. Program, sağlayıcının kendi SDK'sını kullanmaya devam eder; yalnızca iki şey değişir:

| Sağlayıcı | API adresi | API anahtarı |
|---|---|---|
| OpenAI | `http://localhost:7777/proxy/<havuz>/v1` (`OPENAI_BASE_URL`) | uygulama anahtarı (`OPENAI_API_KEY`) |
| Anthropic | `http://localhost:7777/proxy/<havuz>` (`ANTHROPIC_BASE_URL`) | uygulama anahtarı |
| Gemini (google-genai) | `http_options={"base_url": "http://localhost:7777/proxy/gemini"}` | uygulama anahtarı |
| ElevenLabs | `base_url="http://localhost:7777/proxy/<havuz>"` | uygulama anahtarı |
| Özel | `http://localhost:7777/proxy/<havuz>/<yol>` | `Authorization: Bearer agp_…` |

Nasıl çalışır:

- Gateway uygulama anahtarını SDK'nın koyduğu her yerde arar: `Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, `xi-api-key` ya da `?key=`. Anahtar geçersizse ya da uygulama o havuzu kullanamıyorsa istek sağlayıcıya hiç gitmez (401/403).
- İstemcinin gönderdiği bütün kimlik bilgisi başlıkları, `?key=`, çerezler ve `X-Forwarded-*` başlıkları silinir; havuzdan seçilen anahtar sağlayıcının beklediği başlığa konur. Yanıttaki `Set-Cookie` iletilmez.
- Rotasyon gateway'in kendi tool'larıyla aynıdır: 429/kota, geçersiz anahtar ya da sunucu hatası gelirse uygulamaya henüz bir şey gönderilmediyse istek sıradaki anahtarla tekrarlanır. Bekleme süresi modele göre tutulur (Gemini'de yoldaki model, diğerlerinde gövdedeki `model`). Bütün anahtarlar dinleniyorsa gateway `429` ve `Retry-After` ile cevap verir. İstekten kaynaklanan hatalar (400 gibi) tekrarlanmaz, olduğu gibi iletilir.
- Başarılı yanıtlar, SSE akışları dahil, tamponlanmadan aktarılır. İstek gövdesi tekrar denenebilsin diye bellekte tutulur (en fazla 32 MB).
- Yol `..` ya da `.` parçası içeremez; hedef her zaman havuzun API adresidir. Havuz adresi yalnızca `https` ya da bu makinedeki `http://localhost`/`127.0.0.1` olabilir ve yalnızca panelden değiştirilir.
- Uygulama anahtarı MCP'ye ya da panele erişim vermez; agent anahtarları da proxy'de çalışmaz. Uygulama eklemek, anahtar yenilemek ve silmek yalnızca panelden yapılır.
- Etkinlik'te her istek `app:<id>` olarak görünür: havuz, metot, yol, HTTP durumu, kullanılan anahtarın **adı** ve deneme sayısı. İstek ve yanıt içerikleri, token'lar ve anahtar değerleri kaydedilmez.

## Güvenlik

- **Ağ:** Sadece `127.0.0.1` dinlenir. `Host` başlığı localhost değilse istek reddedilir (DNS rebinding koruması), `/api` için `Origin` de kontrol edilir.
- **Panel girişi:** Parolayla yapılır (PBKDF2-SHA256, 600k tur).
  - Oturum `HttpOnly`, `SameSite=Strict` bir çerezdir; 30 dakika işlem yapılmazsa ya da 12 saat dolunca biter.
  - Durum değiştiren istekler ayrıca `X-AGW` başlığı ister (CSRF koruması).
  - Hatalı denemeler sınırlanır.
  - Betikler için `X-Admin-Token` da kabul edilir; token veri klasöründedir.
- **Agent token'ları:** SHA-256 hash olarak saklanır.
- **Kasa:** Şifreler AES-256-GCM ile şifrelenir (AAD = şifrenin adı). Ana anahtar yalıtılmış kurulumda servis kullanıcısının klasöründe, hızlı kurulumda macOS Anahtar Zinciri'ndedir. OAuth token'ları da kasada `oauth:<sunucu>` adıyla durur.
- **Onay akışı:** Bir agent'ın `manage` ile yaptığı, bir sunucunun **ne çalıştırdığını ya da bilgileri nereye gönderdiğini** değiştiren her değişiklik (komut, argümanlar, ortam değişkenleri, adres, header'lar, OAuth istemcisi) panelden onaylanana kadar çalışmaz.
  - Panel, önce/sonra farkını ve hangi şifrenin hangi alan adına gideceğini gösterir.
  - Reddetmek, son onaylı ayarlara döndürür; hiç onaylanmamış bir sunucuyu siler.
  - Adres değişikliği onaylanırsa kayıtlı OAuth oturumu silinir.
  - Gateway şablonlarından ya da Claude dizininden, adresi sabit (ya da bölge seçenekli) uzak sunucu kurulumları otomatik onaylanır.
- **Tool sabitleme:** Her upstream tool'un adı, açıklaması ve girdi şeması hash'lenip onaylı sürüm olarak saklanır (`tool_pins`). Bağlı bir sunucu sonradan bir tool'un açıklamasını ya da şemasını değiştirirse (ör. açıklamaya agent'a talimat sokarsa) ya da yeni bir tool eklerse, o tool panelden onaylanana kadar `search_tools`, `describe_tools`, `overview` ve `call_tool`'da görünmez; agent'a onay linki döner. Onay ekranı açıklama ve şema farkını gösterir. Reddetmek tool'u `deny_tools`'a ekler.
  - Otomatik sabitlenenler: bir sunucunun ilk indekslemesindeki tool'lar, dahili sunucular (`gemini`) ve özelliğin geldiği andaki mevcut tool'lar (tek seferlik migration).
  - İndekste olmayan bir tool çağrılırsa gateway önce yeniden indeksler; bilinmeyen tool'lar upstream'e körlemesine iletilmez.
- **Agent sınırları:**
  - Yeni şifre oluşturabilir ama var olanın üzerine yazamaz.
  - Parametrelerde `${secret:…}` kullanamaz.
  - Tool gizleyebilir ama gizlenmiş bir tool'u açamaz.
  - Sunucu kapatabilir ama açamaz.
  - Eklediği şablonlar panelde uyarıyla işaretlenir.

## Yapılandırma referansı

```jsonc
{
  "id": "pg-prod", "name": "Prod DB", "description": "agent bunu görür",
  "purpose": "Şirket prod veritabanı (salt okunur)",   // yalnızca panelden; agent'tan gelen değer yok sayılır
  "transport": "stdio",                // ya da "http"
  "command": "uvx", "args": ["postgres-mcp", "--access-mode=restricted"],
  "env": { "DATABASE_URI": "${secret:PG_PROD_DATABASE_URI}" },
  // http: "url", "headers": {"Authorization": "Bearer ${secret:X}"}, "auth": "auto|oauth|none"
  "allow_tools": [], "deny_tools": ["execute_*"],
  "enabled": true
}
```

## Geliştirme

```bash
go test ./...
go run ./testdata/mockoauth          # OAuth akışını tarayıcısız test etmek için sahte AS + MCP
go run . serve -data /tmp/agw -addr 127.0.0.1:7790 -key-store file
```

Bağımlılıklar: resmi `modelcontextprotocol/go-sdk` (MCP istemci/sunucu + OAuth istemcisi) ve `modernc.org/sqlite` (cgo'suz).
