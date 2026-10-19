Adli Bilişim Delil Bütünlüğü ve Hash Doğrulama Aracı

Adli bilişim incelemelerinde toplanan dijital delillerin değiştirilmediğini (delil zincirinin korunduğunu) kanıtlamak ve dosya üzerindeki olası müdahaleleri tespit etmek için geliştirdiğim Python tabanlı komut satırı aracı.

Ne İşe Yarar?
Hash Hesaplama: Seçilen bir dosyanın MD5, SHA-1 ve SHA-256 özet değerlerini aynı anda çıkarır.

Zaman Bilgisi ve Metadata: Dosyanın boyutunu, oluşturulma, değiştirilme ve erişim zamanlarını tespit eder.

Bütünlük Kontrolü (Tamper Detection): Daha önce çıkarılmış bir JSON raporu ile mevcut dosyayı karşılaştırarak dosyada tek bir karakter bile değiştiyse bunu tespit eder ve uyarı verir.

Performans: Büyük boyutlu adli imaj veya log dosyalarında bilgisayarı kasmaması için dosyaları 64 KB'lık parçalar halinde okur.

Nasıl Kullanılır?
Dosyayı İnceleme ve Rapor Oluşturma:
python forensic_validator.py -f sample_evidence.txt -u "Zilan Karakoç"

Delil Bütünlüğünü Doğrulama:
python forensic_validator.py -f sample_evidence.txt -v evidence_sample_evidence.txt_report.json

Parametreler
-f : İncelemek istediğin dosyanın yolu

-u : İncelemeyi yapan kişinin adı / unvanı

-v : Karşılaştırma yapacağın JSON raporu