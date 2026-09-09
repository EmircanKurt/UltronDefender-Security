# ULTRON DEFENDER — UI/UX ve Politika Oturumu için Gemini Promptu

> Kullanım: AegisPC.sln projesinde yeni Gemini oturumu aç, bu dosyanın tamamını yapıştır.
> Son durum: 537/537 test geçiyor, profil sistemi AdaptiveScanResourceManager ile koordinatöre bağlı, tam tarama C:\Windows tam kapsamlı hale getirildi.

---

# ROL ve BAĞLAM
"Ultron Defender / AegisPC" (C# .NET 8 WPF, AegisPC.sln) projesinin kıdemli UI mühendisisin. Bu oturum YALNIZCA aşağıdaki görevlerle ilgilidir; imza/IOC verisi üretmek, tarama motoru mantığını değiştirmek yasak. Her görevden sonra `dotnet test tests\AegisPC.Tests\AegisPC.Tests.csproj -c Debug --filter "Category!=LiveSample"` PASS çıktısını göstermeden görev bitti deme. Sessiz catch yasak (Serilog). Türkçe yorum, mevcut kod stili. Değişiklik sonrası CHANGELOG.md güncelle.

# GÖREV 1 — Sayfa geçiş animasyonları (öncelik 1, "her şey animasyonlu ve hızlı hissettirsin")
1. MainWindow'da NavigationView içerik geçişini yakala (Frame.Navigated olayı): gelen sayfaya 180 ms'lik opaklık 0→1 + 12 px yukarı kayma animasyonu uygula (EasingFunction: CubicEase EasingMode=EaseOut). Çıkış animasyonu YOK — hızlı his için yalnızca giriş animasyonu.
2. Animasyonu her View'e tek tek eklemek yerine tek noktadan yap: MainWindow.xaml.cs'te Navigate fonksiyonunu sarmala veya NavigationView.Navigating/Navigated'e bağlan.
3. ReduceMotion: Windows "Animasyonları kapat" ayarı açıksa (SystemParameters.ClientAreaAnimation == false) animasyonları atla.
4. Kabul kriteri: sayfa geçişinde titreme/donma yok; XamlStaticResourceIntegrityTests hâlâ geçiyor.

# GÖREV 2 — Açılış animasyonu (splash)
1. Program.Main'de (App.xaml.cs'ten önce) 1.5-2 saniyelik splash penceresi göster: koyu arka plan (#0D0D0D), ortada bulut logosu (ImageCloudLogoBase/ImageCloudCursorLine kaynaklarını yeniden kullan) + yanıp sönen imleç çizgisi storyboard'u, altında ince bir yüklenme çizgisi (belirsiz ilerleme, 1.2 sn döngü).
2. DI konteyneri hazırlanınca splash 250 ms fade-out ile kapansın; toplam açılış hissi 2 sn'yi geçmesin.
3. Splash tek seferlik; --minimized açılışta da gösterilebilir ama tray'e geçişte kapatılmalı.

# GÖREV 3 — Süreç Yöneticisi güncellemesi
1. ProcessListView'de varsayılan sıralama RAM'e göre azalan; üstte üç hızlı filtre çipi: "En Çok RAM", "En Çok CPU", "GPU".
2. RAM/CPU: mevcut Performance modülü sayaçlarını kullan (Process WORKING SET + Processor Time). 2 saniyelik hareketli ortalama ile güncelle; her satır için tek tek sayaç AÇMA (PerformanceCounter oluşturmak pahalı — toplu System.Diagnostics.Process sorgusu kullan).
3. GPU kullanımı: "GPU Engine" kategorisindeki PerformanceCounter'ları (enginetype=3D vb.) süreç PID'ine göre topla. Kategori yoksa (eski sürücü/VM) GPU çipini gizle, hata atma.
4. Kabul kriteri: 300+ süreçte liste 500 ms içinde açılıyor; sıralama değişimi anlık.

# GÖREV 4 — Tarayıcı Güvenliği dark mode bug'ı
1. Tarayıcı Güvenliği sayfasındaki seçili satır ve sağdaki inceleme panelinde beyaz kalabilen kontroller var (DataGrid seçim fırçası ve açıklama TextBox'ı). Tüm hardcoded Brush'ları DynamicResource theme brush'larına bağla: seçim satırı arka planı #262626, seçili satır metni BrushTextPrimary, açıklama alanı BrushCardBg + BrushCardBorder.
2. Özellikle: DataGrid RowStyle/CellStyle Selected durumları ve "Açıklama / İstenen İzinler" bölümündeki TextBlock'lar. "___MSG_description___" gibi ham yer tutucu metinler boşsa alanı gizle ("Açıklama yok" yazma).
3. Kabul kriteri: koyu temada beyaz kutu/şerit kalmıyor; açık temada da kontrast korunuyor.

# GÖREV 5 — Tarama penceresi renk dili (yeşil tarama, kırmızı tehdit)
1. ActiveScanWindow: tarama sürerken TÜM ilerleme göstergeleri yeşil olsun (progress bar, "Dosya sistemini tara" aşama noktası, tick'ler) — BrushStatusSafe kullan.
2. Tespit sayısı > 0 olduğunda yalnızca "Tespitler" sayısı ve ilgili satır kırmızıya dönsün (BrushStatusDanger); tarama barı yeşil kalmaya devam etsin.
3. Tarama bittiğinde: 0 tespit → yeşil "Sisteminiz temiz" özeti; tespit var → kırmızı özet + "Karantinaya Al" birincil butonu.
4. "Kaynak Kotası" metni artık ScanQueueCoordinator.ActiveResourceSummary'dan okunmalı — ekranda gösterilen kota ile gerçek uygulanan kota AYNI olacak. Farklı formatlı eski kota metinlerini (ScanHardwareProfile.SummaryText vb.) bu tek kaynağa bağla, çift kaynak bırakma.

# GÖREV 6 — Tarama başlangıcında kaynak profili sorusu + RAM ayarı
1. "Hızlı Tarama / Tam Tarama" başlatınca bir kez soran küçük dialog: "Tarama kaynak kullanımı" — üç seçenek: 🌱 Sakin (~1 GB RAM, düşük CPU) / ⚖️ Dengeli (RAM'in yarısı) / 🚀 Tam Güç (tüm çekirdekler). "Bir daha sorma" checkbox'ı (AppSettings'e yaz: ScanResourceMode).
2. Seçim ScanResourceProfile.Create(mode:...) ile AdaptiveScanResourceManager'a verilmeli — mevcut Auto akışını seçilen modla değiştir (Auto yerine kullanıcı seçimi).
3. RAM değeri ekranda MB yerine anlaşılır gösterilsin: "16 GB RAM'in ~8 GB'ı kullanılabilir".
4. Kabul kriteri: Sakin seçilince tarama sırasında uygulamanın working set 1 GB'ı aşmıyor (test: bellek ölçümü runner'ı); Tam Güç'te CPU tüm çekirdekleri kullanıyor.

# GÖREV 7 — "Uyarıldı" bulguları ile karantina tutarsızlığı
1. Sorun: canlı akışta "Uyarıldı" görünen bulgular karantina listesinde yok (doğru — yalnızca uyarıldılar) ama bildirime tıklayınca kullanıcı karantinaya düşüyor, dosyayı bulamıyor.
2. Çözüm: RiskScore >= 85 bulgular PolicyEngine ile OTOMATİK karantinaya alınmalı (müdahele sütunu "Karantinaya alındı" olacak). 60-84 arası "Uyarıldı" kalsın ama bildirim tıklaması Olay Merkezi'ne gitsin (karantinaya değil).
3. PolicyEngine'i ScanCoordinatorService'in tamamlama akışına bağla; her otomatik karantina için AuditLog kaydı.
4. Kabul kriteri: EICAR düşürülünce bulgu "Karantinaya alındı" etiketiyle listelenir ve gerçekten kasada görünür (uçtan uca test yaz).

# BİTİŞ KONTROL LİSTESİ
- dotnet test toplam/pass/fail (537+ bekleniyor)
- Sayfa geçiş ve splash animasyonlarının kısa ekran açıklaması
- Süreç yöneticisi sıralama ekran akışı
- Tarayıcı sayfası dark mode ekran açıklaması
- Tarama penceresi yeşil/kırmızı durum açıklaması
- Kaynak profili dialogu ve tekilleştirilmiş kota metni kanıtı
- Değişen dosya listesi + FEATURE_STATUS güncellemesi
