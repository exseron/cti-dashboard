# CTI Dashboard

Python (FastAPI) ile yazılmış, 3 panelli tehdit istihbaratı paneli:

1. **CTI Haberleri**: 16 RSS kaynağından haberler. Her habere bir özet ve etiket eklenir: tehdit türü, aktör/malware, ülke, üretici, sektör, CVE ve ATT&CK ID'leri. `ANTHROPIC_API_KEY` verilirse özetler Claude ile Türkçe yazılır.
2. **CVE'ler**: NVD'den son N günün CVE'leri, CISA KEV, FIRST EPSS ve PoC/exploit kaynakları ile zenginleştirilir. PoC kaynakları: nomi-sec/PoC-in-GitHub, Exploit-DB, NVD "Exploit" referansları. İsteğe bağlı olarak tek bir CVE için GitHub araması da yapılabilir.
3. **ATT&CK Navigator**: Enterprise, Mobile ve ICS matrisleri. Teknik seçme, renk/skor/yorum ekleme, grup/yazılım/kampanya tekniklerini tek tıkla seçme, lejant ve **PNG dışa aktarma** desteklenir. Resmi Navigator ile uyumlu layer JSON içe/dışa aktarılabilir.

## Hızlı başlangıç (yerel)

```bash
python -m venv .venv
.venv\Scripts\activate            # Linux: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env            # Linux: cp .env.example .env  -> APP_USERNAME / APP_PASSWORD'ü düzenleyin
python run.py                     # http://localhost:8000
```

İlk açılışta veri arka planda çekilir: haberler yaklaşık 30 saniyede, CVE'ler 1-3 dakikada gelir. ATT&CK verisi ilk açılışta yaklaşık 1 dakikada indirilir ve `data/` altında önbelleğe alınır.

## İnternete açma (önerilen: Docker + Caddy, otomatik HTTPS)

1. Alan adınızın DNS A kaydını sunucuya yönlendirin. 80 ve 443 portlarını açın.
2. `.env` dosyasında `DOMAIN`, `APP_USERNAME` ve `APP_PASSWORD` değerlerini (uzun, rastgele) ayarlayın.
3. Çalıştırın:
   ```bash
   docker compose up -d --build
   ```
   Caddy, Let's Encrypt sertifikasını kendisi alır. Uygulama portu (8000) dışarı açılmaz.

Docker kullanmadan yayınlarsanız uygulamayı mutlaka nginx veya Caddy gibi bir TLS reverse proxy arkasına koyun. Basic Auth şifreleri HTTPS olmadan düz metin gider. Bu durumda `FORWARDED_ALLOW_IPS` değerine proxy'nin IP'sini yazın.

## Güvenlik önlemleri

- **Opsiyonel HTTP Basic Auth.** Varsayılan olarak kapalıdır (`ALLOW_NO_AUTH=1`). Açmak için `.env` dosyasında `ALLOW_NO_AUTH=0` yapın ve `APP_USERNAME` / `APP_PASSWORD` değerlerini doldurun.
- **Kaba kuvvet koruması.** Aynı IP 15 dakika içinde 10 hatalı giriş yaparsa 429 alır.
- **Sıkı güvenlik başlıkları.** CSP (`script-src 'self'`; html2canvas yerel olarak sunulur), X-Frame-Options DENY, nosniff, no-referrer.
- **XSS koruması.** Dış kaynaklardan gelen içerik hiçbir zaman `innerHTML` ile basılmaz. Linkler yalnızca http/https şemasıyla açılır.
- **CSRF koruması.** Manuel yenileme endpoint'i özel bir header ister ve 2 dakikalık bekleme süresi vardır.
- **Kullanıcı girdisiyle dış istek yok (SSRF yok).** Sunucu yalnızca sabit kaynaklara istek atar. GitHub aramasındaki CVE ID'si regex ile doğrulanır.
- **Root olmayan kullanıcı.** Container root olmayan bir kullanıcıyla çalışır. `/docs` ve `/openapi.json` kapalıdır.

## Yapılandırma

Tüm ayarlar ve açıklamaları `.env.example` dosyasında. Ücretsiz iki anahtar önerilir:

- `NVD_API_KEY`: NVD rate limit'ini 5'ten 50 istek/30 sn'ye çıkarır.
- `GITHUB_TOKEN`: PoC aramaları için GitHub limitlerini yükseltir.

Haber kaynaklarını değiştirmek için proje köküne `feeds.json` koyun:
`[["Kaynak adı", "https://.../feed"], ...]`

## Claude ile özetler (opsiyonel)

`ANTHROPIC_API_KEY` ayarlanınca her yeni haber Claude ile özetlenir ve etiketlenir. Varsayılan model `claude-opus-5-5`, effort `low`. Maliyet kontrolü için:

- `LLM_MAX_PER_CYCLE`: her döngüde özetlenecek en fazla haber sayısı.
- `CLAUDE_MODEL`: daha ucuz bir model, örneğin `claude-haiku-5-5`.

Her haber yalnızca bir kez özetlenir; sonuçlar SQLite'ta tutulur. Claude'a erişilemezse kural tabanlı özet ve etiketler kullanılır.

## Mimari notu

Arka plan yenileme görevleri ve önbellek süreç içinde tutulur. Bu yüzden `run.py` tek uvicorn worker ile çalışır. Veri `data/` (Docker'da `/data` volume) altında saklanır: `news.db`, `cves.json`, `attack-*.json`.
