import os
import re

def create_pdf(output_path):
    pages = []
    current_page_ops = []
    
    # Page setup (A4: 595.28 x 841.89)
    width = 595
    height = 842
    margin_left = 50
    margin_right = 545
    content_width = margin_right - margin_left
    margin_bottom = 60
    
    y = 780
    
    def start_page():
        nonlocal y, current_page_ops
        current_page_ops = []
        pages.append(current_page_ops)
        y = 780
        # Draw header rule and logo text
        current_page_ops.append("0.1 0.3 0.6 rg") # Dark blue
        current_page_ops.append("0.1 0.3 0.6 RG")
        current_page_ops.append(f"50 805 {content_width} 1 re f")
        current_page_ops.append("BT /F2 8 Tf 50 812 Td (ULTRON DEFENDER TOTAL SECURITY | KURULUM VE KULLANICI KILAVUZU v3.5.0) Tj ET")
        # Reset color
        current_page_ops.append("0 0 0 rg")
        current_page_ops.append("0 0 0 RG")
        
    def check_space(needed):
        nonlocal y
        if y - needed < margin_bottom:
            start_page()

    def escape_pdf(text):
        # Clean ASCII/Latin-1 mapping for Turkish characters in standard Type1 Helvetica
        tr_map = {
            'ç': 'c', 'Ç': 'C',
            'ğ': 'g', 'Ğ': 'G',
            'ı': 'i', 'I': 'I', 'İ': 'I',
            'ö': 'o', 'Ö': 'O',
            'ş': 's', 'Ş': 'S',
            'ü': 'u', 'Ü': 'U',
            '’': "'", '“': '"', '”': '"', '–': '-', '—': '-'
        }
        for k, v in tr_map.items():
            text = text.replace(k, v)
        return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    def add_title(text):
        nonlocal y
        check_space(50)
        safe = escape_pdf(text)
        current_page_ops.append("0.05 0.25 0.55 rg")
        current_page_ops.append(f"BT /F2 18 Tf {margin_left} {y} Td ({safe}) Tj ET")
        current_page_ops.append("0 0 0 rg")
        y -= 26

    def add_heading1(text):
        nonlocal y
        check_space(40)
        safe = escape_pdf(text)
        current_page_ops.append("0.12 0.35 0.65 rg")
        current_page_ops.append(f"BT /F2 13 Tf {margin_left} {y} Td ({safe}) Tj ET")
        current_page_ops.append("0.7 0.7 0.7 RG")
        current_page_ops.append(f"{margin_left} {y-4} {content_width} 0.5 re f")
        current_page_ops.append("0 0 0 rg")
        current_page_ops.append("0 0 0 RG")
        y -= 22

    def add_heading2(text):
        nonlocal y
        check_space(30)
        safe = escape_pdf(text)
        current_page_ops.append("0.15 0.2 0.3 rg")
        current_page_ops.append(f"BT /F2 10.5 Tf {margin_left} {y} Td ({safe}) Tj ET")
        current_page_ops.append("0 0 0 rg")
        y -= 16

    def wrap_text(text, max_chars):
        words = text.split(' ')
        lines = []
        cur = []
        cur_len = 0
        for w in words:
            if cur_len + len(w) + 1 <= max_chars:
                cur.append(w)
                cur_len += len(w) + 1
            else:
                if cur:
                    lines.append(' '.join(cur))
                cur = [w]
                cur_len = len(w)
        if cur:
            lines.append(' '.join(cur))
        return lines

    def add_paragraph(text, indent=0):
        nonlocal y
        lines = wrap_text(text, 92 - int(indent / 6))
        for line in lines:
            check_space(14)
            safe = escape_pdf(line)
            current_page_ops.append(f"BT /F1 9.5 Tf {margin_left + indent} {y} Td ({safe}) Tj ET")
            y -= 13
        y -= 4

    def add_bullet(text):
        nonlocal y
        lines = wrap_text(text, 88)
        first = True
        for line in lines:
            check_space(14)
            safe = escape_pdf(line)
            if first:
                current_page_ops.append("0.2 0.4 0.7 rg")
                current_page_ops.append(f"BT /F2 9.5 Tf {margin_left + 8} {y} Td (*) Tj ET")
                current_page_ops.append("0 0 0 rg")
                current_page_ops.append(f"BT /F1 9.5 Tf {margin_left + 20} {y} Td ({safe}) Tj ET")
                first = False
            else:
                current_page_ops.append(f"BT /F1 9.5 Tf {margin_left + 20} {y} Td ({safe}) Tj ET")
            y -= 13
        y -= 2

    def add_code_block(code_lines):
        nonlocal y
        box_height = len(code_lines) * 12 + 10
        check_space(box_height + 10)
        
        # Background box
        current_page_ops.append("0.95 0.96 0.98 rg")
        current_page_ops.append("0.8 0.82 0.85 RG")
        current_page_ops.append(f"{margin_left} {y - box_height + 4} {content_width} {box_height} re B")
        current_page_ops.append("0 0 0 rg")
        current_page_ops.append("0 0 0 RG")
        
        box_y = y - 10
        for line in code_lines:
            safe = escape_pdf(line)
            current_page_ops.append(f"BT /F3 8.5 Tf {margin_left + 12} {box_y} Td ({safe}) Tj ET")
            box_y -= 12
        y -= (box_height + 8)

    # Start first page
    start_page()

    # Manual content construction
    add_title("Ultron Defender Total Security (AegisPC)")
    add_paragraph("Uretim Surumu (Production-Ready) Kurulum, Yonetim ve Calistirma Kilavuzu - v3.5.0")
    
    add_heading1("1. Genel Bakis ve 4 Katmanli Guvenlik Mimarisi")
    add_paragraph("Ultron Defender Total Security, Windows uzerinde yuksek basarimli, cevik ve yerel cevrimdisi (air-gapped) calisabilen yeni nesil bir ucbirim koruma ve EDR mimarisidir.")
    add_bullet("Katman 1 - Kernel Minifilter Driver (AegisFilter): Dosya I/O olaylarini cekirdek seviyesinde yakalar. Zararli dosyalarin olusumunu PreCreate asamasinda STATUS_ACCESS_DENIED (0xC0000022) kodu ile bloke eder. Altitude: 320500.")
    add_bullet("Katman 2 - Windows Core Protection Service (AegisPCProtectionService): start= auto modunda LocalSystem olarak arka planda calisir. Hizmet gocmelerine karsi otomatik kendini onarma (failure recovery actions= restart) politikasina sahiptir.")
    add_bullet("Katman 3 - ETW ve Anti-Tamper Motoru: 256 MB dongusel tampon bellek ile ProcessStart, ProcessExit ve ImageLoad telemetrisini analiz eder. LOLBAS, DLL injection, BYOVD rootkit ve sc config/reg add tamper saldirilarini engeller.")
    add_bullet("Katman 4 - Modern WPF Kullanici Paneli (UltronDefender.exe): Hızlı, Tam ve Ozel tarama, Karantina Kasasi, DNS Kalkanı ve performans optimizasyon arayuzunu sunar.")

    add_heading1("2. Sistem Gereksinimleri")
    add_bullet("Isletim Sistemi: Windows 10 (1903+) / Windows 11 / Windows Server 2016/2019/2022 (x64 uyumlu)")
    add_bullet("Donanim: Asgari 2 Core CPU, 4 GB RAM (Onerilen: 8 GB+ RAM, NVMe SSD)")
    add_bullet("Disk Alani: Kurulum ve loglar icin en az 500 MB bos depolama alani")
    add_bullet("Yetki Duzeyi: Administrator (Yerel Yonetici Haklari)")

    add_heading1("3. Hizli ve Otomatik Kurulum (install.ps1)")
    add_paragraph("Sistemde 'install.ps1' calistirildiginda dosya dizinleri, erisim izinleri, surucu kaydi, Windows servisi ve baslangic entegrasyonu 1 dakikadan kisa surede tamamlanir.")
    add_code_block([
        "# Administrator olarak acilmis PowerShell penceresinde:",
        "cd 'C:\\Path\\To\\UltronDefender'",
        "powershell.exe -ExecutionPolicy Bypass -File .\\install.ps1",
        "",
        "# Parametreli Sessiz / Ozel Kurulum Secenekleri:",
        ".\\install.ps1 -Force -NoDesktopShortcut   # Sessiz kurulum ve masaustu ikonu olmadan",
        ".\\install.ps1 -SkipDriver               # Sadece servis ve UI kurulumu (surucusuz)"
    ])

    add_heading1("4. Cevrimdisi USB Imza Guncelleme (Auto-Update Engine)")
    add_paragraph("Internet baglantisi olmayan kapali aglarda veya sahada imza guncellemesi USB uzerinden tam otomatik gerceklesir:")
    add_bullet("Guncel imza paketi (signatures_packed.bin) bir USB bellege kopyalanir (Orn: E:\\UltronUpdate\\signatures_packed.bin).")
    add_bullet("USB bellek cihaza takildiginda, arka plandaki 'UltronDefender_UsbUpdateWatcher' gorevi veya 'Sync-UsbSignatures.ps1' betigi guncellemeyi otomatik olarak tespit eder.")
    add_bullet("Paketin SHA-256 ozeti ve boyutu denetlenir, C:\\ProgramData\\UltronDefender\\signatures\\ altina atomik olarak aktarilir ve calisan servise aninda bildirilir.")

    add_heading1("5. Kurulum ve Saglik Dogrulamasi (verify_install.ps1)")
    add_paragraph("Kurulumun eksiksiz tamamlandigini teyit etmek icin 'verify_install.ps1' komutu calistirilir. 6 temel guvenlik vektoru denetlenir:")
    add_code_block([
        "powershell.exe -ExecutionPolicy Bypass -File .\\verify_install.ps1",
        "",
        "# Cikti Ozeti:",
        "[PASS] AegisPCProtectionService : Servis calisiyor (Status: Running)",
        "[PASS] Kernel Minifilter Driver  : AegisFilter aktif (Altitude 320500)",
        "[PASS] Dosya Butunlugu          : UltronDefender.exe ve AegisPC.Service.exe dogrulandi",
        "[PASS] Imza Veritabani          : 500+ Tehdit imzasi bellek ve diskte hazir",
        "[PASS] Guvenli IPC Kanali       : \\\\.\\pipe\\AegisPC_ServicePipe baglantisi aktif",
        "[PASS] Explorer Entegrasyonu    : 'Ultron Defender ile Tara' sag-tik aktif"
    ])

    add_heading1("6. Kusursuz ve Kalintisiz Kaldirma (uninstall.ps1)")
    add_paragraph("Ultron Defender guvenlik yazilimini ve tum izlerini sistemden 100% temizlemek icin:")
    add_code_block([
        "# Tam kaldirma ve tum dosya/registry kayitlarini temizleme:",
        "powershell.exe -ExecutionPolicy Bypass -File .\\uninstall.ps1 -Force",
        "",
        "# Temizlenen Bilesenler:",
        "1. Calisan surecler sonlandirilir.",
        "2. Minifilter surucu bosaltilir (fltmc unload) ve PnP deposundan silinir.",
        "3. AegisPCProtectionService servisi ve Registry kayitlari temizlenir.",
        "4. Hosts dosyasindaki DNS sinkhole girdileri geri alinir (rollback).",
        "5. Program Files ve ProgramData dizinleri tamamen silinir."
    ])

    # Footer on all pages
    total_pages = len(pages)
    for idx, page_ops in enumerate(pages):
        page_num = idx + 1
        page_ops.append("0.4 0.4 0.4 rg")
        page_ops.append("0.8 0.8 0.8 RG")
        page_ops.append(f"50 45 {content_width} 0.5 re f")
        page_ops.append(f"BT /F1 8 Tf 50 32 Td (Ultron Security Technologies (c) 2026 | Guvenli Windows EDR Mimarisi) Tj ET")
        page_ops.append(f"BT /F1 8 Tf 500 32 Td (Sayfa {page_num} / {total_pages}) Tj ET")

    # Serialize PDF 1.4 objects
    objects = []
    
    def add_obj(content):
        objects.append(content)
        return len(objects)

    # Object 1: Catalog
    # Object 2: Pages
    # Object 3: Font Helvetica
    # Object 4: Font Helvetica-Bold
    # Object 5: Font Courier
    # Object 6..: Page objects & contents

    obj_catalog = 1
    obj_pages = 2
    obj_f1 = 3
    obj_f2 = 4
    obj_f3 = 5
    
    page_obj_ids = []
    content_obj_ids = []
    
    curr_id = 6
    for _ in pages:
        page_obj_ids.append(curr_id)
        content_obj_ids.append(curr_id + 1)
        curr_id += 2

    body_chunks = []
    
    # Header
    body_chunks.append("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    
    # 1: Catalog
    body_chunks.append(f"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    
    # 2: Pages
    kids_str = " ".join([f"{pid} 0 R" for pid in page_obj_ids])
    body_chunks.append(f"2 0 obj\n<< /Type /Pages /Kids [{kids_str}] /Count {len(pages)} >>\nendobj\n")
    
    # Fonts
    body_chunks.append("3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    body_chunks.append("4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")
    body_chunks.append("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")
    
    for idx in range(len(pages)):
        p_id = page_obj_ids[idx]
        c_id = content_obj_ids[idx]
        
        # Page obj
        p_str = (
            f"{p_id} 0 obj\n"
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] "
            f"/Contents {c_id} 0 R "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>\nendobj\n"
        )
        body_chunks.append(p_str)
        
        # Content stream
        stream_data = "\n".join(pages[idx])
        c_str = (
            f"{c_id} 0 obj\n"
            f"<< /Length {len(stream_data.encode('latin1'))} >>\n"
            f"stream\n{stream_data}\nendstream\nendobj\n"
        )
        body_chunks.append(c_str)

    # Calculate xref
    xref_offsets = [0]
    byte_count = len(body_chunks[0].encode('latin1'))
    
    for chunk in body_chunks[1:]:
        xref_offsets.append(byte_count)
        byte_count += len(chunk.encode('latin1'))
        
    xref_start = byte_count
    total_objects = 5 + len(pages) * 2
    
    xref_str = f"xref\n0 {total_objects + 1}\n0000000000 65535 f \n"
    for offset in xref_offsets:
        xref_str += f"{offset:010d} 00000 n \n"
        
    trailer_str = (
        f"trailer\n<< /Size {total_objects + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_start}\n%%EOF\n"
    )
    
    with open(output_path, "wb") as f:
        for chunk in body_chunks:
            f.write(chunk.encode('latin1'))
        f.write(xref_str.encode('latin1'))
        f.write(trailer_str.encode('latin1'))

    print(f"PDF generated successfully: {output_path} ({os.path.getsize(output_path)} bytes)")

if __name__ == "__main__":
    out_pdf = r"c:\Users\PC\Documents\gemini virüs program\user_manual.pdf"
    create_pdf(out_pdf)
