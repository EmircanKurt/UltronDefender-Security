# AI Self-Audit & Verification Protocol (Yapay Zeka Öz-Denetim Protokolü)

> [!IMPORTANT]
> Bu protokol, Ultron Defender projesinde çalışan her yapay zekanın (AI) her görev başında, kod düzenleme esnasında ve özellikle **"tamamlandı / çalışıyor / düzeltildi / başarılı"** raporu vermeden hemen ÖNCE kendi kendine harfiyen uygulamak zorunda olduğu katı bir denetim sürecidir.

---

## 1. İlke 1: İDDİA ≠ KANIT (Hipotezi Kanıt Sayma Yasağı)

* **1.1**: Kod yazıp mantıken doğru görünmesi, onun çalıştığının **kanıtı değildir**. Asla "düzelttim", "çalışıyor", "başarılı" deme; gerçekten test edilip edilmediğini kesin olarak belirt.
* **1.2**: Durumu her zaman dürüstçe iki kategoriden birine koy:
  - `[TEST EDİLDİ & DOĞRULANDI]`: Komut (örn. `dotnet test`, `dotnet build`) çalıştırıldı, çıktısı okundu, beklenen sonuç gözlemlendi.
  - `[KODLANDI / HİPOTEZ - HENÜZ TEST EDİLMEDİ]`: Kod düzenlendi veya eklendi fakat çalışma zamanı testi ya da uçtan uca doğrulaması henüz yapılmadı.
* **1.3**: Asla bir varsayımı veya temenniyi kesin bir gerçekmiş gibi kullanıcıya sunma.

---

## 2. İlke 2: Her Kod Değişikliği Sonrası 4 Kritik Soru

Bir dosyayı değiştirdiğinde veya yeni bir modül eklediğinde derhal şu 4 soruyu yanıtla:

1. **Yan Etki Analizi:** Bu değişiklik başka hangi modülü, servisi veya projeyi dolaylı yoldan kırabilir/etkileyebilir? (Dependency & Interface kontrolü).
2. **Golden Test Suite Kontrolü:** `GoldenTestSuite` (regresyon test seti) gerçekten çalıştırıldı mı ve 5 temel kural (EICAR tespiti, self-detection olmaması, false positive olmaması, karantina bütünlüğü, risk skor eşikleri) korundu mu?
3. **Regresyon Risk Kontrolü:** Bu değişiklik daha önce `knowledge/history/bug_fixes.md` dosyasında çözüldüğü kaydedilmiş bir hatayı (örn. bellek sızıntısı, race condition, ACL zaafiyeti) yeniden açabilir mi?
4. **Muafiyet / Güvenlik İstismarı Riski:** Eğer koda bir muafiyet, whitelist, bypass veya kural gevşetmesi ekleniyorsa, **bu bir saldırgan tarafından istismar edilebilir mi?** (Örn: bir zararlının process adını, klasörünü veya dosya uzantısını bu muafiyete uydurarak antivirüsten gizlenmesi).

---

## 3. İlke 3: Rapor Dürüstlüğü ve Yalın Dil

* **3.1**: Sadece bizzat komut satırından çalıştırıp çıktısını doğruladığın işlevlere "başarılı" yaz.
* **3.2**: Test edilmemiş veya sadece derleme seviyesinde kalan kod için: `"Dosya/kod eklendi, derlendi, ancak çalışma zamanı senaryosu henüz test edilmedi"` ayrımını açıkça yaz.
* **3.3**: Sayısal iddialarda bulunurken (örn. "244 test geçti") rakamların arkasını doldur: Kaç tanesi gerçek güvenlik/AV senaryosu, kaç tanesi basit birim/smoke testi olduğunu özetle.
* **3.4**: Yasaklı Abartı Sözcükleri: `"Kusursuz"`, `"tam başarılı"`, `"üretime hazır"`, `"%100 güvenli"`, `"mükemmel"`, `"kesinlikle çalışıyor"` gibi kanıtlanamaz, pazarlama kokan mutlak ifadeleri KULLANMAK YASAKTIR.

---

## 4. İlke 4: Zorunlu Şüphecilik Kotası

* **4.1**: Her görev ve sonuç raporunun sonuna mutlaka bir **"Şüphecilik ve Doğrulama Notu"** bölümü ekle.
* **4.2**: Bu bölümde en az bir `"Şu an emin olmadığım / tam doğrulayamadığım nokta şudur: [...]"` maddesi yer almalıdır.
* **4.3**: Eğer hiçbir teknik şüphen kalmadığını iddia ediyorsan, bunu **hangi somut testleri ve sınır durumlarını (edge-cases) bizzat çalıştırıp doğruladığını** kanıtlayarak gerekçelendir.

---

## 5. İlke 5: Rapor ve İddia Denetim Kuralı

* **5.1**: Kullanıcı sana bir rapor, özet, durum tespiti veya başka bir yapay zekanın (ya da kendinin eski bir oturumunun) çıktısını sunduğunda, **onu ASLA otomatik olarak doğru kabul etme**.
* **5.2**: Rapordaki her iddiayı kod tabanında satır satır ara.
* **5.3**: Rapor çıktını kesin olarak şu iki formatla ayrıştır:
  - `DOĞRULANDI [Dosya:Satır]`: Kod tabanında fiziken var olan, mantığı iddiayı karşılayan durumlar.
  - `İDDİA EDİLDİ AMA KOD TABANINDA KARŞILIĞI YOK [Eksik/Uyuşmayan Kısım]`: Kodda olmayan, sadece adı geçen veya yarım bırakılmış durumlar.

---

## 6. İlke 6: Yaşayan Protokol Uygulaması

* **6.1**: Bu dosya, HER görev başlangıcında ve her "tamamlandı" raporu öncesinde okunur ve harfiyen uygulanır.
* **6.2**: Bu kural `AI_GUIDELINES.md` kural 14 ile zorunlu kılınmıştır.

---

## 7. İlke 7: Test Sayısı Şişirme Yasağı

Bir testin "güvenlik senaryosu" sayılabilmesi için **ŞU ÜÇ KOŞULUN TAMAMI** gerekir:

1. **Gerçek Disk I/O veya Gerçek OS Kaynağı:** Mock veya sentetik byte array değil; dosya sisteminde gerçek dosya I/O veya OS süreç kaynağı kullanılmalı.
2. **Gerçek Motor Sınıfı:** Test edilen motor ve koruma sınıfı gerçek (mock/stub değil) olmalı.
3. **Somut Güvenlik Kararı Doğrulaması:** `Assert` ifadesi somut bir güvenlik kararını (risk skoru, karantina eylemi, blok kararı, NT status, süreç sonlandırma) doğrulamalı — sadece "null değil" veya "hata fırlatmadı / çökmedi" kontrolü **YETERSİZDİR**.

Bu üç koşulu sağlamayan testler **"altyapı/duman testi"** veya **"güvenlik birim testi"** olarak sınıflandırılır; asla **"güvenlik entegrasyon senaryosu"** sayılarına **DAHİL EDİLMEZ**.

Bundan sonra hiçbir raporda toplam test sayısı toptan "güvenlik testi" olarak sunulmayacak — **SADECE** bu 3 koşulu sağlayan alt küme "güvenlik entegrasyon testi" olarak anılacak, geri kalanı ayrı kategorilerde (güvenlik birim testi, altyapı/duman testi) raporlanacaktır.
