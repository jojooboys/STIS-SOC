# Panduan 05: Uji fungsional pada target nyata dan demo web1

**Hasil yang ingin dicapai:** membuktikan secara terpisah bahwa pola serangan dikenali, alert sampai ke SOC, dan pemblokiran benar-benar menghentikan koneksi baru. Status HTTP saja tidak menyatakan berhasil/gagalnya sistem. Pada server nyata, pengujian harus disesuaikan dengan aplikasi dan dilakukan dalam izin yang disepakati; pada demo, helper membuat kejadian sintetis.

Dokumentasi rule dan alur sistem ada di [STIS_SOC.md](../STIS_SOC.md). Perintah di panduan ini adalah prosedur untuk operator; hasil belum boleh dianggap lulus sebelum bukti dari VM disimpan.


Panduan ini memiliki dua jalur: **Bagian I** untuk server target nyata yang menjalankan aplikasi sendiri, dan **Bagian II** untuk demo `web1.stis.local` yang sudah dibuat di lab. Keduanya memakai Wazuh Manager, SOC, dan pfSense yang sama, tetapi bukti login/SQLi berbeda. Jalankan satu skenario per siklus; setelah IP uji berstatus diblokir, buktikan dengan koneksi baru bahwa request tidak lagi mencapai Apache. Jika masih mencapai target, periksa rule, alias, state, dan rute pfSense sebelum menyimpulkan perlindungan berhasil. Simpan hasil nyata, termasuk kegagalan, untuk skripsi.

Instalasi sistem: [Panduan Instalasi](PANDUAN_01_INSTALASI_PFSENSE_WAZUH_DAN_STIS_SOC.md). Penambahan Agent/situs: [Panduan Agent](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md). Rujukan resmi: [Wazuh logtest](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html), [koleksi log](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/index.html), [FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html), dan [pfSense States](https://docs.netgate.com/pfsense/en/latest/monitoring/status/firewall-states-gui.html).

## Bagian I — pengujian pada server target nyata

### 1. Prasyarat yang harus dipenuhi

Pada target baru, pasang satu Wazuh Agent dan pola log/FIM global dari [Panduan Agent](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md). Jalur HTTP eksternal harus benar-benar melalui WAN pfSense → HAProxy → VirtualHost target; `X-Forwarded-For` hanya dipercaya dari IP HAProxy, sehingga access log memuat IP klien sesungguhnya. DNS/Host, sertifikat, route HAProxy dan rule WAN Block `SOC_Blocklist` harus menunjuk target yang benar. Nama domain saja di SOC tidak membuat route atau Agent baru.

Untuk setiap website, `CustomLog /var/log/stis-soc/apache/<slug>.access.log stis_soc_combined` berada di VirtualHost yang aktif. Agent mengoleksi wildcard access log, JSONL aplikasi, dan FIM `/var/www`. Pastikan aplikasi **sendiri** menulis kegagalan login dan percobaan SQLi yang ditolak dengan `srcip` yang sudah diverifikasi; helper `lab_probe.php` pada Bagian II hanya untuk demo dan tidak membuktikan aplikasi nyata. Jika aplikasi tidak menulis event tersebut, catat kategori login/SQLi sebagai **belum memenuhi syarat**, walaupun rule sintetis Manager lulus.

Contoh kontrak satu baris per event di `/var/log/stis-soc/apps/<slug>.jsonl`:

```json
{"timestamp":"2026-10-03T10:00:00Z","event_type":"stis_auth_failed","srcip":"192.0.2.20","dstuser":"akun-uji","url":"/login","domain":"situs.example","asset_name":"nama-situs"}
{"timestamp":"2026-10-03T10:00:01Z","event_type":"stis_sqli_attempt","srcip":"192.0.2.20","dstuser":"akun-uji","url":"/login","domain":"situs.example","asset_name":"nama-situs"}
```

Pemicu kedua berasal dari validasi/WAF aplikasi yang **sudah menolak** input berbahaya; jangan membuat website sengaja rentan demi demo. Jangan menulis password, cookie, token atau isi formulir sensitif ke JSONL. Pada Apache yang memakai `mod_remoteip`, aplikasi PHP dapat memakai `$_SERVER['REMOTE_ADDR']` setelah proxy tepercaya dikonfigurasi; jangan langsung mempercayai header `X-Forwarded-For` dari internet. Untuk aplikasi non-PHP, terapkan prinsip yang sama pada framework-nya.

Di **Manager**, verifikasi Agent berstatus `Active`, lalu cek koneksi SOC dan pfSense:

```bash
sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/wazuh-analysisd -t
cd /root/backend
venv/bin/python check_wazuh.py
venv/bin/python check_pfsense.py
venv/bin/python check_auto_response.py
```

Di **target**, periksa path log yang benar dan proses Agent:

```bash
sudo /var/ossec/bin/wazuh-agentd -t
sudo /var/ossec/bin/wazuh-logcollector -t
sudo apache2ctl configtest
sudo systemctl is-active wazuh-agent apache2
sudo tail -n 3 /var/log/stis-soc/apache/NAMA_SLUG.access.log
sudo tail -n 3 /var/log/stis-soc/apps/NAMA_SLUG.jsonl
```

Ganti `NAMA_SLUG` dengan slug nyata. Jika service tidak memakai Apache, abaikan perintah Apache dan buktikan log service yang sesuai. Di pfSense, periksa posisi WAN Block di atas Pass HAProxy serta hak tulis alias. Pada hasil lab 3 Oktober 2026, uji tulis alias berhasil tetapi pembersihan state otomatis memberi HTTP 400; karena itu penegakan koneksi baru tetap harus diuji dan state IP spesifik dibersihkan melalui **Diagnostics → States** bila perlu.

### 2. Jalankan kasus dari komputer uji

Gunakan akun, domain, path dan IP **khusus pengujian** yang benar-benar diarahkan ke server target. Contoh berikut perlu diisi sesuai aplikasi; jangan menempelkannya tanpa mengganti nilai `GANTI_*`. Jalankan dari Kali/klien luar melalui WAN pfSense.

```bash
TARGET_WAN='GANTI_IP_WAN_PFSENSE'
TARGET_HOST='GANTI_DOMAIN_TARGET'
LOGIN_PATH='/GANTI_PATH_LOGIN'
USER_FIELD='GANTI_NAMA_FIELD_USER'
PASS_FIELD='GANTI_NAMA_FIELD_PASSWORD'
TEST_USER='GANTI_AKUN_UJI'

# Satu request kontrol: harus terlihat di access log dengan IP Kali sebenarnya.
curl -i --connect-timeout 3 --max-time 8 \
  -H "Host: $TARGET_HOST" "http://$TARGET_WAN/"

# Lima password salah untuk akun uji; harapkan rule 100501 bila aplikasi
# menulis stis_auth_failed, atau 100102 bila format legacy yang dipakai.
for n in 1 2 3 4 5; do
  curl -sS --connect-timeout 3 --max-time 8 -o /dev/null -w 'HTTP %{http_code}\n' \
    -H "Host: $TARGET_HOST" \
    --data-urlencode "${USER_FIELD}=${TEST_USER}" \
    --data-urlencode "${PASS_FIELD}=wrong-test-${n}" \
    "http://${TARGET_WAN}${LOGIN_PATH}"
done
```

Setelah alert level 10, IP dapat terblokir. Simpan bukti, **Unblock** dari SOC dan hapus state IP uji yang masih aktif di pfSense sebelum uji berikutnya. Untuk SQLi, gunakan hanya akun/form uji setelah aplikasi dipastikan menolak input; satu event `stis_sqli_attempt` harus muncul dari aplikasi itu sendiri dan rule `100510` level 12 harus muncul. Jika aplikasi menggunakan rule legacy `SQLI ATTEMPT`, ID yang diharapkan adalah `100200`. Respons `403` dari aplikasi menunjukkan penolakan input, bukan bukti WAN firewall memblokirnya.

```bash
# Hanya pada target uji yang Anda kelola dan endpoint yang telah divalidasi
curl -i --connect-timeout 3 --max-time 8 \
  -H "Host: $TARGET_HOST" \
  --data-urlencode "${USER_FIELD}=test' OR '1'='1' -- " \
  --data-urlencode "${PASS_FIELD}=wrong-test" \
  "http://${TARGET_WAN}${LOGIN_PATH}"
```

Untuk kategori berbasis access log, [skrip probe](../scripts/testing/run_web_attack_tests.sh) dapat dipakai dengan `LAB_WAN="$TARGET_WAN" LAB_HOST="$TARGET_HOST"` untuk **hanya** kasus `webshell`, `wordpress`, `scanner`, `sensitive-file`, `rce`, `recon`, `traversal`, `xss`, `shellshock`, `ssrf-once`, `ssrf`. Skrip `auth-bruteforce`, `sqli`, dan `http400` **khusus demo** karena memanggil `/lab_probe.php`; jangan gunakan untuk mengklaim pengujian login/SQLi aplikasi nyata. URL probe 404 tetap dapat membuktikan deteksi percobaan, bukan keberhasilan eksploitasi atau keberadaan file. Catat kategori yang tidak relevan sebagai *tidak berlaku*.

FIM/perubahan file dapat diuji pada root terisolasi di bawah `/var/www` dengan `run_file_integrity_tests.sh` **pada target** jika Website Guard sudah terpasang. Pastikan direktori uji tidak disajikan VirtualHost. Alert perubahan file harus menampilkan path dan saran investigasi; jangan auto-block IP tebakan dari event tanpa `srcip` yang tepercaya.

### 3. Bukti yang membuat klaim sah

Untuk setiap kasus simpan: request/waktu/IP uji, baris log target, alert nyata di `alerts.json` Manager atau Indexer, detail dan Audit SOC, isi alias/rule pfSense, serta hasil **koneksi baru** setelah block. Bila koneksi baru masih menghasilkan HTTP dari Apache dan access log bertambah, firewall belum menghentikan jalur itu meskipun SOC menampilkan `BLOCKED`. Cek jalur HTTPS/TLS passthrough, akses LAN, IPv6 dan proxy lain secara terpisah. Setelah demo, pertahankan konfigurasi monitoring target; hapus hanya file uji terisolasi. [Tabel evaluasi](#8-format-tabel-hasil-untuk-skripsievaluasi) di Bagian II dapat digunakan juga untuk target nyata.

## Bagian II — pengujian pada server demo `web1`

### Sinkronisasi setelah perubahan kode (jalankan berurutan)

Ini adalah jalur pembaruan untuk lab yang **sudah terpasang**, bukan instalasi ulang. Dari Windows, pastikan versi file terbaru benar-benar berada pada folder yang dipasang di UbuntuServer sebagai `/media/sf_VM-Share`. VM lab tidak dapat diperbarui hanya dengan menyimpan file di editor Windows. Jalankan perintah berikut di **UbuntuServer**, bukan di STIS:

```bash
test -f '/media/sf_VM-Share/config/wazuh/rules/local_rules.xml'
test -f '/media/sf_VM-Share/config/wazuh/decoders/local_decoder.xml'
test -f '/media/sf_VM-Share/scripts/testing/prepare_manager.sh'
test -x /root/backend/venv/bin/python
sudo bash /media/sf_VM-Share/scripts/testing/prepare_manager.sh --no-tests
```

Skrip itu menyalin kode terbaru ke `/root`, memasang paket Python hanya bila `requirements.txt` berubah, menjalankan `npm ci` bila dependensi frontend berubah/rusak, membangun frontend, me-restart SOC, lalu memasang **kedua** file rule/decoder Manager dengan backup dan validasi. Opsi `--no-tests` melewati diagnosis koneksi dan matriks rule sintetis; keduanya dijalankan kemudian pada sesi pengujian. Jangan menjalankan `setup_ubuntu.sh` atau `update_from_vm_share.sh` lagi untuk pembaruan yang sama. Sebelum menjalankannya, periksa apakah `local_rules.xml`/`local_decoder.xml` Manager berisi aturan pribadi di luar proyek: skrip mengganti isi kedua file secara penuh. File `.env`, database, dan `venv` dipertahankan; `node_modules` dibangun ulang hanya bila dependensi frontend berubah atau tidak lengkap. Hentikan di sini jika output tidak berakhir dengan `[SELESAI]` atau ada layanan yang tidak `active`.

Setelah Manager siap, **di UbuntuServer** kirim salinan skrip terbaru ke STIS (gunakan akun SSH yang memang berhasil login; contoh `vboxuser`):

```bash
scp /root/examples/lab_probe.php \
  /root/scripts/testing/setup_target_lab.sh \
  /root/scripts/testing/check_target_readiness.sh \
  /root/scripts/testing/run_file_integrity_tests.sh \
  /root/scripts/testing/cleanup_target_lab.sh \
  vboxuser@10.10.10.30:/tmp/
```

Di **STIS**, jalankan `sudo bash /tmp/setup_target_lab.sh 10.10.10.1 /var/www/web1 web1.stis.local`. IP Kali tidak menjadi argumen lagi: helper memakai token privat dan Wazuh membaca IP sumber aktual dari log. Skrip terbaru juga menonaktifkan serta menghapus pembatas `Require ip` yang dibuat versi lama. Bila masih berhenti dengan `[BELUM SELESAI]`, selesaikan tepat tiga konfigurasi Agent/VirtualHost di [langkah 0.3](#03-server-stis-pasang-helper-lab-dan-periksa-persyaratan-target), lalu jalankan ulang skrip dan `sudo LAB_HAPROXY_IP=10.10.10.1 bash /tmp/check_target_readiness.sh lab`. Jangan salin `ossec.conf` atau `web1.conf` dari Manager ke STIS: keduanya adalah konfigurasi lokal server target yang perlu diedit dengan backup. Target siap untuk uji jaringan hanya jika hasil checker `Perlu perbaikan: 0`, Agent STIS berstatus `Active` pada `sudo /var/ossec/bin/agent_control -l` di UbuntuServer, dan tes satu request di [langkah 0.6](#06-jalankan-satu-serangan-per-siklus) menghasilkan **baris baru** di kedua log target serta alert nyata di Manager/SOC.

Website Guard yang sudah terpasang di STIS perlu disalin ulang dari `/root/website_guard/` dan timer di-restart **hanya bila file sumbernya berubah**; [langkah 0.3](#03-server-stis-pasang-helper-lab-dan-periksa-persyaratan-target) memuat perintah dan aturan baseline-nya. pfSense tidak menerima konfigurasi dari `prepare_manager.sh`: periksa alias `SOC_Blocklist`, urutan rule WAN Block terhadap Pass HAProxy, IP asli `X-Forwarded-For`, dan hak tulis API di [langkah 0.4](#04-pfsense-setting-yang-wajib-sebelum-simulasi). Jangan memulai seluruh simulasi Kali sebelum empat bukti ini terkumpul.

**Jangan jalankan `cleanup_target_lab.sh` selama demo dan penulisan skripsi masih membutuhkan `lab_probe.php`.** Skrip itu menghapus helper, token, dan sisa konfigurasi Apache helper versi lama bila ada. `web1.conf`, isi website, `CustomLog`, `RemoteIP`, Wazuh Agent/rule, Website Guard, dan log bukti tetap ada, tetapi uji brute force/SQLi berbasis helper berhenti sampai `setup_target_lab.sh` dijalankan lagi. `run_file_integrity_tests.sh cleanup` hanya membersihkan file uji FIM terisolasi dan aman dijalankan di antara sesi demo.

| Perintah di STIS | Yang berubah | Dampak untuk demo berikutnya |
| --- | --- | --- |
| `sudo bash /tmp/run_file_integrity_tests.sh cleanup` | Menghapus direktori/state **uji FIM terisolasi** dan mengaktifkan lagi timer Guard jika sebelumnya aktif | `web1` dan helper tetap siap |
| `sudo bash /tmp/cleanup_target_lab.sh` | Menghapus `lab_probe.php`, token, dan sisa konfigurasi pembatas IP dari versi lama bila ada | Website dan `web1.conf` tetap ada, tetapi uji login/SQLi **berbasis helper berhenti** |
| `sudo LAB_HAPROXY_IP=10.10.10.1 bash /tmp/check_target_readiness.sh production` | Tidak mengubah apa pun; hanya memeriksa layanan dan konfigurasi | Dalam mode `production`, helper yang masih terpasang justru dilaporkan sebagai temuan |

Jalankan setiap perintah pada baris sendiri **tanpa `\` di akhir baris**. Tanda itu menyambung baris berikutnya sebagai bagian perintah yang sama. Selama demonstrasi skripsi masih akan diulang, cukup jalankan baris pertama, lalu gunakan `check_target_readiness.sh lab` untuk verifikasi.

Matriks rule Manager kini memuat 21 skenario sintetis dasar (22 bila daftar reputasi contoh aktif), tetapi hasil itu tidak membuktikan target STIS siap untuk demo. Agent harus mengoleksi `*.access.log` dan `*.jsonl`, VirtualHost harus menulis `CustomLog` STIS SOC, dan checker harus menghasilkan `Perlu perbaikan: 0`. Setelah itu buktikan satu request Kali menghasilkan log serta alert nyata. Posisi rule pfSense dan state cleanup juga harus diverifikasi. Hasil lama tidak dapat dipakai untuk menyatakan konfigurasi VM **saat ini** sudah siap.

Setelah source di Windows berubah, sinkronkan **sekali** di UbuntuServer sebelum menyalin skrip ke STIS/Kali. Pilih sesuai perubahan: `prepare_manager.sh` sudah memanggil `update_from_vm_share.sh`, jadi jangan menjalankan keduanya berurutan tanpa alasan.

```bash
# Pilihan A: hanya kode aplikasi/panduan/skrip uji berubah
bash /media/sf_VM-Share/update_from_vm_share.sh /root
```

### 0. Jalur cepat: perintah yang langsung dijalankan

Bagian ini menggunakan topologi lab yang sudah dipakai sebelumnya:

| Komponen | Alamat/nilai |
| --- | --- |
| UbuntuServer, Wazuh Manager, STIS SOC | `10.10.10.20` |
| Dashboard SOC dari Windows (host-only UbuntuServer) | `http://192.168.1.10:5173/` |
| Server target STIS | `10.10.10.30` |
| pfSense/HAProxy LAN | `10.10.10.1` |
| pfSense WAN | `192.168.18.99` |
| Kali | `192.168.18.103` |
| Domain uji | `web1.stis.local` |
| Web root | `/var/www/web1` |

Alamat `192.168.18.99` adalah contoh WAN pfSense pada sesi sebelumnya. Setelah mengganti Wi-Fi atau adapter bridged, lihat IP WAN terkini pada pfSense dan isi `LAB_WAN` secara eksplisit; skrip Kali tidak memakai alamat WAN lama secara otomatis.

Asal file yang dipakai langkah berikut:

| Path | Asal dan kapan tersedia |
| --- | --- |
| `/media/sf_VM-Share/scripts/testing/*.sh`, `/media/sf_VM-Share/examples/lab_probe.php` | Source repositori pada VM-Share; periksa mount sebelum memulai |
| `/root/scripts/testing/*.sh`, `/root/backend/venv/bin/python` | Dibuat di UbuntuServer setelah sinkronisasi source dan `setup_ubuntu.sh` |
| `/tmp/setup_target_lab.sh`, `/tmp/check_target_readiness.sh`, `/tmp/lab_probe.php` | Salinan dari UbuntuServer ke STIS pada langkah 0.2; **tidak ada otomatis** |
| `/var/www/web1`, `/etc/apache2/sites-available/web1.conf` | Website/VirtualHost yang sudah dipasang terpisah di STIS; **tidak ada dalam source SOC** |
| `/var/log/stis-soc/apps/web1.jsonl`, `/var/log/stis-soc/apache/web1.access.log` | Dibuat oleh `setup_target_lab.sh`; baru berisi bukti setelah request/event |

Jika salah satu IP berubah, ganti pada perintah **sebelum** dijalankan. Jika web root atau VirtualHost belum ada di STIS, selesaikan [Panduan 02](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md) dahulu; jangan menjalankan skrip dengan path yang belum ada. Urutan siap pakainya adalah sebagai berikut.

#### 0.1 UbuntuServer: sinkronkan kode, pasang rule, dan uji Manager

Jalankan di `root@UbuntuServer`. Skrip membuat backup rule, memulihkannya bila validasi gagal, me-restart Manager hanya setelah rule valid, lalu menjalankan pemeriksaan Wazuh, pfSense, auto-response, dan matriks `wazuh-logtest`:

Jika decoder/rule Manager belum pernah dipasang atau berubah, jalankan **Pilihan B** berikut sebagai pengganti sinkronisasi biasa. Skrip menyalin **`config/wazuh/decoders/local_decoder.xml` dan `config/wazuh/rules/local_rules.xml`**, membuat backup jika file tujuan sudah ada, serta memulihkannya bila validasi gagal. Matriks source terbaru memuat **21 kasus dasar**, termasuk XSS dan SSRF berulang; hasil pengujian lama 19/19 berasal dari versi sebelum pembaruan ini dan tidak menjamin keadaan VM sekarang. Kekurangan Agent/Apache STIS harus diperbaiki pada target, bukan dengan mengulang pemasangan Manager:

Skrip mengganti **isi penuh** `local_decoder.xml` dan `local_rules.xml`. Jika kedua file di Manager sudah memuat aturan lain di luar proyek ini, gabungkan dulu aturan tersebut ke source proyek dan validasi; backup otomatis bukan penggabungan.

```bash
sudo bash /media/sf_VM-Share/scripts/testing/prepare_manager.sh
```

Hasil akhirnya harus menampilkan `[SELESAI] Manager siap untuk uji end-to-end` dan matriks `passed` sama dengan `total`. Skrip tetap membandingkan file sumber dengan file yang disinkronkan dan rule yang dipasang, tanpa mencetak checksum debugging. Jika shared folder tidak berada di `/media/sf_VM-Share`, jalankan dengan lokasi sebenarnya:

```bash
sudo SOC_SOURCE='/lokasi/shared-folder' SOC_TARGET='/root' \
  bash '/lokasi/shared-folder/scripts/testing/prepare_manager.sh'
```

Jika matriks gagal lagi, gunakan laporan `/tmp/stis-soc-rule-matrix.json` dan log Manager untuk menentukan rule yang gagal sebelum mengubah target.

#### 0.2 UbuntuServer: kirim helper dan skrip pengujian ke server STIS

Gunakan akun server STIS yang sebelumnya sudah terbukti dapat login melalui SSH:

```bash
scp /root/examples/lab_probe.php \
  /root/scripts/testing/setup_target_lab.sh \
  /root/scripts/testing/check_target_readiness.sh \
  /root/scripts/testing/run_file_integrity_tests.sh \
  /root/scripts/testing/cleanup_target_lab.sh \
  vboxuser@10.10.10.30:/tmp/
```

Jika source belum ada di `/root`, berarti sinkronisasi langkah 0.1 belum selesai. Jangan menjalankan perintah `scp` dari server STIS; file sumber berada di UbuntuServer.

#### 0.3 Server STIS: pasang helper lab dan periksa persyaratan target

**Catatan hasil lama:** laporan Manager 19/19 berasal dari versi sebelum rule reputasi IP ditambahkan. Pada saat itu STIS masih kekurangan dua `<localfile>` Agent (`*.access.log` dan `*.jsonl`) serta `CustomLog` VirtualHost web1. Periksa ulang hasil `check_target_readiness.sh` terbaru pada STIS; jangan memakai laporan lama untuk menyatakan keadaan VM sekarang sudah siap.

Jalankan pada `root@STIS` atau gunakan `sudo` dari akun `vboxuser`:

```bash
sudo bash /tmp/setup_target_lab.sh \
  10.10.10.1 \
  /var/www/web1 \
  web1.stis.local
```

Skrip memasang helper, token, log JSONL, format log Apache, dan `mod_remoteip`. Helper menerima IP penguji yang berubah-ubah karena otorisasi dilakukan dengan token privat; request tanpa token yang benar mendapat `404` dan tidak membuat event. Skrip juga menghapus pembatas IP helper dari versi lama. Skrip sengaja berhenti dengan `[BELUM SELESAI]` jika `ossec.conf` atau `CustomLog` belum memenuhi syarat. Jika itu terjadi, buka konfigurasi Agent:

Jika skrip berhenti lebih awal karena `php` belum ada, periksa PHP pada target. Untuk lab Ubuntu dengan Apache dan tanpa handler PHP, jalankan:

```bash
php -v || true
sudo apache2ctl -M | grep -E 'php|proxy_fcgi' || true
sudo apt update
sudo apt install -y php libapache2-mod-php
sudo systemctl restart apache2
```

Jika website memakai PHP-FPM yang sudah ada, pertahankan handler itu dan cukup pasang paket `php-cli` untuk pemeriksaan sintaks. Jangan memasang dua handler PHP pada VirtualHost yang sama. Ulangi skrip setup setelah PHP siap.

```bash
sudo cp -a /var/ossec/etc/ossec.conf \
  "/var/ossec/etc/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
sudo nano /var/ossec/etc/ossec.conf
```

Di dalam blok `<ossec_config>`, tambahkan setiap blok berikut **satu kali**:

Pada STIS yang sekarang, blok Website Guard sudah ada, jadi **cukup tambahkan dua blok pertama** di bawah dan jangan menduplikasi blok ketiga. Pastikan semuanya berada di dalam `<ossec_config>`, bukan di dalam `<syscheck>` atau `<localfile>` lain.

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/stis-soc/apache/*.access.log</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/var/log/stis-soc/apps/*.jsonl</location>
</localfile>
<localfile>
  <log_format>json</log_format>
  <location>/var/log/mini-soc/website_guard.log</location>
</localfile>
```

Di dalam blok `<syscheck>` yang sudah ada, tambahkan satu baris berikut:

```xml
<directories check_all="yes" realtime="yes">/var/www</directories>
```

Kemudian buka VirtualHost `web1`:

```bash
sudo nano /etc/apache2/sites-available/web1.conf
```

Pastikan blok `<VirtualHost *:80>` yang aktif memiliki baris berikut. Jangan membuat VirtualHost kedua:

Biarkan `CustomLog` lama bila masih digunakan untuk kebutuhan lain; baris STIS SOC dapat ditambahkan sebagai `CustomLog` kedua. `setup_target_lab.sh` memastikan format `stis_soc_combined` aktif: ia memakai directive yang sudah ada atau membuat `stis-soc-logging.conf` bila belum ada.

```apache
ServerName web1.stis.local
DocumentRoot /var/www/web1
CustomLog /var/log/stis-soc/apache/web1.access.log stis_soc_combined
```

Validasi semuanya, lalu jalankan ulang skrip persiapan:

```bash
sudo /var/ossec/bin/wazuh-agentd -t
sudo /var/ossec/bin/wazuh-logcollector -t
sudo /var/ossec/bin/wazuh-syscheckd -t
sudo apache2ctl configtest
sudo systemctl restart wazuh-agent
sudo systemctl reload apache2
sudo bash /tmp/setup_target_lab.sh \
  10.10.10.1 /var/www/web1 web1.stis.local
sudo systemctl is-active apache2 wazuh-agent
sudo LAB_HAPROXY_IP=10.10.10.1 bash /tmp/check_target_readiness.sh
```

Tampilkan token satu kali dan salin nilainya untuk dimasukkan pada Kali ketika diminta:

```bash
sudo cat /etc/stis-soc-lab/probe-token
```

`check_target_readiness.sh` memeriksa file, layanan, VirtualHost, handler PHP Apache, izin log, dan konfigurasi Agent tanpa mengubahnya. Hasil `Perlu perbaikan: 0` berarti pemeriksaan **lokal web1** selesai, belum membuktikan jalur HAProxy atau Manager. Mode `production` pada skrip ini berarti **web1 setelah helper lab dilepas**, bukan audit kesiapan produksi untuk semua website. Bila handler PHP belum aktif, tentukan apakah situs memakai `mod_php` atau PHP-FPM, aktifkan handler yang sesuai, lalu ulangi pemeriksaan. Tes HTTP dari Kali pada langkah 0.6 tetap diperlukan untuk membuktikan PHP benar-benar dieksekusi, HAProxy meneruskan IP asli, dan JSONL terisi. Skrip setup hanya mendukung lab `web1.stis.local` di `/var/www/web1`; gunakan [panduan Agent](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md) untuk situs lain.

Di **UbuntuServer**, pastikan Agent target benar-benar terhubung (layanan `wazuh-agent` yang `active` di STIS saja belum cukup):

```bash
sudo /var/ossec/bin/agent_control -l
```

Cari baris Agent STIS (contoh ID `001`) dengan status `Active`. Jika tidak aktif, periksa `sudo tail -n 50 /var/ossec/logs/ossec.log` di STIS, alamat Manager pada `ossec.conf`, dan koneksi STIS ke Manager di port Agent yang dipakai lab. Jangan mulai uji alur nyata sampai Agent terhubung.

Source website STIS yang berjalan pada VM **tidak ada di repositori SOC**, jadi pemeriksaan source `process_login.php`, query database, dan handler login asli harus dilakukan di server STIS sendiri. Untuk uji integrasi SOC, helper `lab_probe.php` cukup dan tidak memerlukan website rentan. Untuk mengklaim perlindungan **aplikasi asli**, pastikan aplikasi asli menolak input berbahaya, mencatat `srcip` hasil `mod_remoteip` dan jenis kejadian ke log yang dikoleksi Agent, lalu tunjukkan alert nyata di Manager serta penegakan blokir pfSense. Uji helper saja tidak membuktikan bahwa query login asli sudah aman.

Untuk uji judol/pinjol dan pola file webshell, Website Guard harus terpasang di STIS. Periksa dulu:

```bash
test -x /usr/local/sbin/website_guard.py && echo 'Website Guard siap'
systemctl is-active website-guard.timer || true
```

Jika programnya belum ada, kirim file dari UbuntuServer dan pasang di STIS:

```bash
# UbuntuServer
scp /media/sf_VM-Share/website_guard/website_guard.py \
  /media/sf_VM-Share/website_guard/website-guard.service \
  /media/sf_VM-Share/website_guard/website-guard.timer \
  vboxuser@10.10.10.30:/tmp/
```

```bash
# Server STIS
sudo install -m 0750 /tmp/website_guard.py /usr/local/sbin/website_guard.py
sudo install -m 0644 /tmp/website-guard.service /etc/systemd/system/website-guard.service
sudo install -m 0644 /tmp/website-guard.timer /etc/systemd/system/website-guard.timer
sudo install -d -m 0700 /var/lib/mini-soc-website-guard
sudo install -d -m 0750 /var/log/mini-soc
sudo touch /var/log/mini-soc/website_guard.log
sudo chmod 0640 /var/log/mini-soc/website_guard.log
sudo systemctl daemon-reload
```

Sebelum mengaktifkan timer, periksa konten **seluruh `/var/www`**. Periksa pula `root` di baseline yang sudah ada; instalasi lama bisa masih menunjuk `/var/www/web1`:

```bash
sudo python3 -c 'import json; print(json.load(open("/var/lib/mini-soc-website-guard/baseline.json"))["root"])' \
  2>/dev/null || echo 'Belum ada baseline'
```

Bila hasilnya `/var/www/web1`, migrasikan state sesuai [Panduan 02](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md#7-website-guard-fim-dan-keterbatasan-perlindungan-file) **sebelum** mengaktifkan timer. Bila belum ada baseline, buat setelah situs yang ada dinyatakan bersih:

```bash
if [ ! -f /var/lib/mini-soc-website-guard/baseline.json ]; then
  sudo /usr/local/sbin/website_guard.py init --root /var/www
fi
sudo systemctl enable --now website-guard.timer
sudo systemctl start website-guard.service
sudo systemctl status website-guard.timer --no-pager
```

Jika `init` menolak konten mencurigakan, investigasi file yang disebutkan; jangan memakai `--force`. Jika baseline lama berakar di path lain, ikuti [panduan perubahan root Website Guard](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md#7-website-guard-fim-dan-keterbatasan-perlindungan-file) sebelum mengaktifkan timer. Jalankan lagi `sudo bash /tmp/check_target_readiness.sh` setelah semua persyaratan dipenuhi.

#### 0.4 pfSense: setting yang wajib sebelum simulasi

Di **Services → HAProxy → Frontend**, gunakan mode HTTP/SSL offloading dan masukkan pada **Advanced pass thru**:

```text
http-request set-header X-Forwarded-For %[src]
```

Save dan Apply. Jangan mengaktifkan `forwardfor` bersamaan dengan baris tersebut. Pada **Firewall → Aliases**, pastikan ada alias host bernama `SOC_Blocklist`. Pada **Firewall → Rules → WAN**, buat atau periksa rule berikut dan letakkan di atas rule pass menuju HAProxy:

```text
Action      : Block
Interface   : WAN
Address     : IPv4
Protocol    : Any
Source      : SOC_Blocklist
Destination : Any
Description : STIS SOC auto block
```

Save dan Apply. Di dashboard STIS SOC bagian **Settings**, pastikan koneksi Wazuh dan pfSense sukses, `Auto-Response` aktif, threshold `10`, interval polling `30`, maksimum umur alert `900`, dan **IP Kali saat pengujian** tidak berada di whitelist. IP tersebut boleh berubah; rule Wazuh dan pfSense tidak perlu diedit karena `srcip` aktual diproses secara dinamis.

Output `check_pfsense.py` yang menunjukkan `alias_readable: true` hanya membuktikan akses baca. Jalankan sekali di UbuntuServer untuk membuktikan hak ubah alias (skrip menambah lalu menghapus IP dokumentasi):

```bash
cd /root/backend
venv/bin/python check_pfsense.py --write-test
```

Harapkan `write_test.status: success`, lalu pastikan IP uji `198.51.100.254` sudah hilang dari `SOC_Blocklist`. Pada hasil lab 3 Oktober, penambahan, apply, dan penghapusan IP ini **berhasil**, tetapi `state_cleanup.status: error` (HTTP 400) menunjukkan pembersihan koneksi aktif otomatis **belum terbukti**. Jangan menyamakan `write_test.status: success` dengan keberhasilan pembersihan state. Bila ada state dari IP yang diblokir, periksa dan hapus hanya state IP tersebut melalui **Diagnostics → States** pada pfSense; jangan gunakan reset seluruh state table. Periksa pula posisi rule WAN Block: `position: 5` pada output hanya menunjukkan lokasinya, belum membuktikan ia berada di atas rule pass HAProxy.

#### 0.5 Salin skrip simulasi ke Kali

Pilihan termudah adalah shared folder VirtualBox. Pada Kali:

```bash
sudo install -m 0750 \
  /media/sf_VM-Share/scripts/testing/run_web_attack_tests.sh \
  /root/run_web_attack_tests.sh
```

Jika shared folder tidak dipasang pada Kali, aktifkan SSH Kali lalu kirim dari UbuntuServer:

```bash
# Kali
sudo systemctl enable --now ssh

# UbuntuServer; ganti "kali" bila akun SSH Anda berbeda
scp /root/scripts/testing/run_web_attack_tests.sh \
  kali@192.168.18.103:/tmp/run_web_attack_tests.sh

# Kali
sudo install -m 0750 /tmp/run_web_attack_tests.sh /root/run_web_attack_tests.sh
```

Lihat daftar kasus:

```bash
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' \
  bash /root/run_web_attack_tests.sh list
```

#### 0.6 Jalankan satu serangan per siklus

Pertama, pastikan **satu request** helper benar-benar mencapai target. Pada terminal Kali:

```bash
read -rsp 'Token lab_probe.php: ' LAB_TOKEN; echo
curl -i --connect-timeout 3 --max-time 8 \
  -H 'Host: web1.stis.local' \
  -H "X-STIS-SOC-Lab-Token: $LAB_TOKEN" \
  --data-urlencode 'mode=auth-failed' \
  --data-urlencode 'username=lab-admin' \
  http://192.168.18.99/lab_probe.php
unset LAB_TOKEN
```

Respons harus `401` dan body `Lab login denied`. Pada terminal STIS, periksa dua baris terakhir:

```bash
sudo tail -n 2 /var/log/stis-soc/apache/web1.access.log
sudo tail -n 2 /var/log/stis-soc/apps/web1.jsonl
```

Keduanya harus menunjukkan IP Kali yang sebenarnya, misalnya `192.168.18.103`, dan JSONL harus memiliki `event_type=stis_auth_failed` serta `timestamp`. Jika log Apache masih menunjukkan `10.10.10.1`, periksa set-header X-Forwarded-For pada HAProxy dan `RemoteIPInternalProxy` pada Apache. `404` berarti path/VirtualHost atau token salah; `503` berarti PHP tidak dapat menulis JSONL. Respons `403` dengan `Lab SQLi input rejected` adalah hasil normal untuk kasus SQLi. Setelah tes tunggal ini, reset IP di pfSense/SOC bila rule lain sempat memblokirnya, kemudian jalankan kasus brute force lengkap.

Bila respons menampilkan kode PHP mentah atau mengunduh file `.php`, **hentikan uji**: Apache belum mengeksekusi PHP. Periksa handler di `apache2ctl -M`, konfigurasi PHP-FPM bila dipakai, dan ulangi `sudo bash /tmp/check_target_readiness.sh` sampai siap. Respons `401` dengan body `Lab login denied` serta satu baris JSONL baru adalah bukti bahwa helper dijalankan, bukan sekadar tersedia di disk.

Pada Manager, periksa alert nyata baru setelah request, terpisah dari `wazuh-logtest`:

```bash
sudo tail -n 200 /var/ossec/logs/alerts/alerts.json | \
  grep -E '"id":"(100500|100501|100510|100300|100305)"' | tail -n 10
```

Jika JSONL sudah bertambah namun tidak muncul rule `100500`, periksa sumber `*.jsonl` di `ossec.conf`, status Agent, dan rule Manager yang terpasang. Satu kegagalan login hanya menghasilkan `100500` level 5; lima kegagalan dari IP yang sama dalam 60 detik diperlukan untuk `100501` level 10.

Selanjutnya jalankan kasus brute force aplikasi dari Kali:

```bash
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' \
  bash /root/run_web_attack_tests.sh auth-bruteforce
```

Masukkan token langkah 0.3 ketika diminta. Tunggu maksimal satu interval polling, klik **Fetch New Alerts**, lalu periksa rule `100501`, Blocked IPs, Audit Log, dan alias pfSense. Setelah IP Kali berstatus `BLOCKED`, buktikan penegakan dengan koneksi baru:

```bash
curl -i --connect-timeout 3 --max-time 8 \
  -H 'Host: web1.stis.local' \
  http://192.168.18.99/
```

Koneksi semestinya timeout/ditolak dan access log target tidak bertambah. Setelah bukti disimpan, lakukan **Unblock** untuk IP Kali yang tampil pada dashboard STIS SOC. Backend versi terbaru membaca kembali alias dan baru melaporkan sukses bila IP benar-benar sudah hilang dari `SOC_Blocklist`; periksa Audit Log bila tombol menampilkan kegagalan. Biasanya siklus berikutnya dapat langsung dimulai. Bila koneksi masih terpengaruh state lama, hapus hanya state IP tersebut melalui **Diagnostics → States** di pfSense. Baru kemudian jalankan kasus berikut, misalnya:

```bash
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh sqli
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh webshell
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh wordpress
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh scanner
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh sensitive-file
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh rce
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh recon
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh traversal
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh xss
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh shellshock
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh ssrf
LAB_WAN='192.168.18.99' LAB_HOST='web1.stis.local' bash /root/run_web_attack_tests.sh http400
```

Jangan menempelkan seluruh baris di atas sekaligus. Setiap kasus level tinggi dapat memblokir Kali. Kasus `ssrf` kini mengirim lima probe dan dapat menghasilkan `100481` level 10 serta auto-block; gunakan `ssrf-once` pada sesi terpisah untuk membuktikan bahwa satu alert `100480` level 8 tidak memblokir.

#### 0.7 Uji FIM, judol/pinjol, dan pola webshell file

Pada server STIS, jalankan tiga fase secara terpisah:

```bash
sudo bash /tmp/run_file_integrity_tests.sh prepare
sudo bash /tmp/run_file_integrity_tests.sh events
```

Tunggu event sampai Manager/SOC, tekan **Fetch New Alerts**, lalu simpan bukti rule `100300`, `100301`, `100302`, `100304`, dan `100305` yang benar-benar muncul. Setelah bukti selesai:

```bash
sudo bash /tmp/run_file_integrity_tests.sh cleanup
```

Uji file tidak mempunyai IP sumber yang dapat dipercaya, sehingga hasil yang benar adalah `integrity_alert` dan petunjuk mitigasi, bukan auto-block IP.

### 1. Definisi hasil uji untuk laporan

Gunakan tingkat bukti berikut, agar klaim dalam laporan sesuai dengan hasil yang benar-benar terlihat:

| Tingkat | Bukti yang harus ada | Klaim yang sah |
| --- | --- | --- |
| A — rule | `check_attack_matrix.py` menunjukkan `passed`, rule ID cocok | Pola log sintetis dikenali oleh ruleset Wazuh yang terpasang |
| B — alur nyata | Event baru terlihat di log target, `alerts.json` Manager, Indexer/SOC | Target → Agent → Manager → Indexer → SOC berfungsi |
| C — respons | SOC `action_taken=blocked`, IP ada di alias `SOC_Blocklist`, audit sukses | SOC meminta dan memverifikasi blokir pada pfSense |
| D — penegakan | Koneksi **baru** dari IP uji gagal sebelum Apache; access log tidak bertambah | Firewall menghentikan trafik pada jalur yang diuji |

Respons `403` dari **PHP/Apache** berarti request mencapai target; itu dapat membuktikan penolakan aplikasi, **bukan** bukti pemblokiran di WAN. `404` pada probe file yang tidak ada tetap dapat membuktikan deteksi **percobaan**, tetapi tidak membuktikan kerentanan atau keberhasilan eksploitasi. Alert FIM tanpa IP membuktikan perubahan file, bukan identitas penyerang; ia tidak seharusnya memblokir IP. `wazuh-logtest` bekerja di sandbox ruleset dan **tidak** memasukkan alert ke Indexer atau memblokir pfSense.

### 2. Siapkan lab dan catat keadaan awal

Contoh alamat dari lab sebelumnya: Kali `192.168.18.103`, WAN pfSense `192.168.18.99`, LAN pfSense/HAProxy `10.10.10.1`, server STIS `10.10.10.30`, Manager/SOC `10.10.10.20`, domain `web1.stis.local`. **Ganti sesuai hasil `ip -4 addr` pada VM Anda**. Pastikan snapshot/backup tersedia, waktu VM tersinkron, dan tidak ada uji yang diarahkan ke host di luar lab.

Di **UbuntuServer/Manager**, setelah update kode dari VM-Share, pastikan decoder dan rule proyek terbaru terpasang. Rule `100510` mengenali laporan SQLi JSON dari aplikasi; rule FIM `100304` generik untuk `/var/www/<slug>/`. Jalankan skrip yang sudah membuat backup, memvalidasi **sebelum** restart, dan memulihkan file lama jika validasi gagal:

```bash
sudo bash /media/sf_VM-Share/scripts/testing/prepare_manager.sh
sudo systemctl is-active wazuh-manager wazuh-indexer filebeat
```

Ini skrip yang sama dengan bagian 0.1; **jangan menjalankannya dua kali dalam satu siklus uji**. Jika `wazuh-analysisd -t` gagal, Manager tidak direstart dan file lama dipulihkan. Periksa pesan error, koreksi source di Windows, lalu ulangi. Uji JSON memakai decoder JSON bawaan, sedangkan rule login lama `100101/100102/100200` memakai `config/wazuh/decoders/local_decoder.xml` yang ikut dipasang skrip. Pada Wazuh 4.14.7 lab, event dengan `timestamp` dan `event_type` cocok ke parent `86600` level 0 lalu harus turun ke rule anak STIS `100300/100301/100305/100500/100501/100510`. Parent `86600` saja bukan hasil lulus.

Pada **UbuntuServer**, jalankan pemeriksaan berikut dan simpan hasilnya. Skrip `check_attack_matrix.py` mempunyai **21 skenario sintetis dasar**, termasuk XSS dengan respons 404/200 dan SSRF tunggal/berulang; satu skenario reputasi IP ditambahkan bila daftar contoh masih terpasang. Nilai `passed` mesti sama dengan `total` sebelum mengklaim cakupan rule. File ini memakai alamat dan tanggal contoh, sehingga **bukan** alert nyata.

```bash
cd /root/backend
venv/bin/python check_wazuh.py
venv/bin/python check_pfsense.py --write-test
venv/bin/python check_auto_response.py
venv/bin/python check_attack_matrix.py | tee /tmp/stis-soc-rule-matrix.json
```

Di **server STIS/target**, ikuti panduan Agent sampai Agent aktif dan path berikut terbaca. Sumber Apache global cukup satu wildcard; JSONL aplikasi cukup satu wildcard; FIM memantau `/var/www`.

```bash
sudo systemctl is-active apache2 wazuh-agent
sudo /var/ossec/bin/wazuh-agentd -t
sudo /var/ossec/bin/wazuh-logcollector -t
sudo tail -n 3 /var/log/stis-soc/apache/web1.access.log
sudo tail -n 30 /var/ossec/logs/ossec.log
```

Di **SOC Settings**, verifikasi Wazuh API/Indexer dan pfSense sukses; auto-response aktif, threshold contoh `10`, maksimum umur alert misalnya `900` detik, dan IP Kali **tidak** masuk whitelist. Di **pfSense**, pastikan alias `SOC_Blocklist` dan rule **Block** pada WAN memakai alias itu dan berada **di atas** rule pass/HAProxy yang sesuai. Uji penegakan harus lewat WAN, bukan akses langsung ke `10.10.10.30` dari LAN. Jangan menonaktifkan firewall untuk membuat simulasi berhasil.

### 3. Jika website belum punya login uji atau log JSON

Repositori SOC tidak memuat source website STIS yang berjalan di VM. Untuk menguji alur log tanpa mengubah login atau SQL aplikasi nyata, gunakan [helper PHP khusus lab](../examples/lab_probe.php) melalui `setup_target_lab.sh` pada [bagian 0.3](#03-server-stis-pasang-helper-lab-dan-periksa-persyaratan-target). Skrip membuat token privat; IP penguji tidak disimpan di Apache, sehingga pergantian IP Kali tidak memerlukan setup ulang. Request `POST` tanpa token yang tepat disamarkan sebagai `404`. Jangan memasang helper kedua secara manual pada VirtualHost. Helper hanya menghasilkan `stis_auth_failed` atau `stis_sqli_attempt`; hasilnya tidak membuktikan keamanan SQL aplikasi produksi. Setelah evaluasi, gunakan `cleanup_target_lab.sh` untuk menghapus helper dan tokennya.

### 4. Cara menjalankan setiap skenario jaringan

Di **Kali**, set variabel berikut pada shell Bash. Jangan pakai IP contoh jika alamat VM berubah:

```bash
LAB_WAN='192.168.18.99'
LAB_HOST='web1.stis.local'
LAB_URL="http://${LAB_WAN}"
soc_get() {
  curl -g --path-as-is --connect-timeout 3 --max-time 8 \
    -sS -o /dev/null -w 'HTTP %{http_code}\n' \
    -H "Host: ${LAB_HOST}" "${LAB_URL}$1"
}
```

**Sebelum setiap kasus:** pastikan IP Kali belum ada dalam `SOC_Blocklist`; jika sebelumnya diblokir, gunakan **Blocked IPs → Unblock** pada SOC, verifikasi alias pfSense sudah bersih, tunggu state lama hilang/bersihkan state IP uji di pfSense, lalu catat waktu mulai. Satu kasus bisa menghasilkan beberapa alert (misalnya rule spesifik SQLi dan HTTP 4xx). Ambil bukti rule spesifik, bukan menganggap seluruh alert berasal dari serangan berbeda. Jalankan kasus korelasi dalam timeframe rule dari **IP yang sama** (60/120/3600 detik menurut kategori); jangan menjalankan semuanya sekaligus.

Setelah setiap kasus, lihat `sudo tail -n 10 /var/log/stis-soc/apache/web1.access.log` di STIS, alert terbaru di Wazuh/SOC, tindakan di **Blocked IPs** dan **Audit Log**, serta alias/rule pfSense. `Fetch New Alerts` pada SOC membantu mengambil alert setelah Indexer menyimpannya; scheduler juga dapat mengambil sendiri pada interval Settings.

#### 4.1 Brute force login website/service — `100501` atau legacy `100102`

Jika helper bagian 3 aktif, kirim lima kegagalan. Setiap request harus `401`, JSONL harus memuat `stis_auth_failed` dengan `srcip` Kali, dan rule `100501` level 10 harus muncul setelah korelasi. `100500` level 5 untuk tiap kejadian awal belum memenuhi threshold blokir.

```bash
for n in 1 2 3 4 5; do
  curl --connect-timeout 3 --max-time 8 -sS -o /dev/null -w 'HTTP %{http_code}\n' \
    -H "Host: ${LAB_HOST}" -H "X-STIS-SOC-Lab-Token: ${LAB_TOKEN}" \
    --data-urlencode 'mode=auth-failed' --data-urlencode 'username=lab-admin' \
    "${LAB_URL}/lab_probe.php"
done
```

Jika memakai `process_login.php` nyata, isi lima password **salah** untuk akun uji tanpa memasukkan password benar; cek apakah `FAILED LOGIN USER=... IP=...` benar-benar tertulis di log yang dipantau Agent. Rule yang dicari adalah `100101` (satu gagal) lalu `100102` (lima gagal). Jika endpoint tidak ada, **jangan** mengklaim uji web login nyata; helper atau `check_attack_matrix.py` hanya membuktikan pipeline/aturan yang sesuai.

#### 4.2 SQL injection yang dilaporkan aplikasi — `100510` atau legacy `100200`

Helper menguji satu pola input SQLi tanpa memasukkannya ke database. HTTP `403`, JSONL `stis_sqli_attempt`, rule `100510` level 12, lalu blokir IP jika syarat SOC/pfSense terpenuhi:

```bash
curl --connect-timeout 3 --max-time 8 -i \
  -H "Host: ${LAB_HOST}" -H "X-STIS-SOC-Lab-Token: ${LAB_TOKEN}" \
  --data-urlencode 'mode=sqli' \
  --data-urlencode "username=admin' OR '1'='1' -- " \
  "${LAB_URL}/lab_probe.php"
```

Jika memakai login asli yang sudah mencatat `SQLI ATTEMPT`, rule `100200` menjadi bukti. Selain itu, request SQLi **di URL** dapat memicu rule Apache bawaan `31103`/`31164`/`31165` dan kenaikan `100201`/`100202`; jalankan hanya pada URL lab tanpa query database bila ingin bukti layer access log. POST body biasa tidak ada pada Apache *combined access log*, sehingga tanpa log aplikasi tidak ada dasar mengklaim deteksi SQLi dari parameter POST.

#### 4.3 Probe webshell di URL — `100400` lalu `100401`

```bash
for n in 1 2 3 4 5; do soc_get '/radio.php'; done
```

Satu probe menghasilkan rule `100400` level 7; lima dari IP sama dapat menghasilkan `100401` level 10. File `radio.php` **tidak perlu dibuat**. `404` adalah hasil yang baik untuk file tidak ada.

#### 4.4 WordPress endpoint scan — `100410` lalu `100411`

```bash
for n in 1 2 3 4 5 6 7 8; do soc_get '/wp-login.php'; done
```

WordPress **tidak perlu diinstal**. Delapan event dari IP yang sama dalam 120 detik dapat memicu `100411` level 10. Yang dibuktikan adalah deteksi probe URL, bukan keamanan plugin WordPress.

#### 4.5 Pola vulnerability scanner — `100420` lalu `100421`

```bash
for n in 1 2 3 4 5 6 7 8 9 10; do
  curl --connect-timeout 3 --max-time 8 -sS -o /dev/null \
    -H "Host: ${LAB_HOST}" -A 'nuclei/3.0 STIS-SOC-lab' \
    "${LAB_URL}/not-found"
done
```

Ini hanya **User-Agent buatan** untuk uji korelasi, bukan pemindaian kerentanan sungguhan. Cek rule `100421` level 10; whitelist scanner resmi perlu diputuskan terpisah.

#### 4.6 Percobaan akses file sensitif — `100430`

```bash
soc_get '/.env'
```

Jangan membuat `.env` asli di web root. Harapkan `404`/`403`, rule `100430` level 12, dan periksa bahwa isi file tidak tersaji.

#### 4.7 Probe RCE/PHPUnit — `100440`

```bash
soc_get '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php'
```

Jangan memasang PHPUnit rentan hanya untuk tes. Rule `100440` level 12 membuktikan pola probe ke path tersebut; `404` berarti target file tidak ada.

#### 4.8 Enumerasi endpoint admin/service — `100450` lalu `100451`

```bash
for n in 1 2 3 4 5; do soc_get '/manager/html'; done
```

Rule `100451` level 10 adalah korelasi permintaan berulang; Apache boleh menjawab `404`.

#### 4.9 Path traversal/LFI probe — `100460`

```bash
soc_get '/download?file=%2e%2e%2fetc%2fpasswd'
```

Opsi `--path-as-is` menjaga URL uji agar tidak dinormalisasi oleh `curl`. Endpoint `/download` **tidak perlu ada** dan jangan menambahkan route yang membaca `/etc/passwd`; rule `100460` level 12 hanya membuktikan deteksi pola URI.

#### 4.10 XSS probe pada URL — `100468`/`100469` lalu `100470`

```bash
for n in 1 2 3 4 5; do
  soc_get '/?q=%3Cscript%3Ealert(1)%3C/script%3E'
done
```

Ini request URL terenkode; `alert(1)` tidak dijalankan oleh server. HTTP `200` pada homepage berarti halaman berhasil merespons, **bukan** bahwa XSS berhasil dieksekusi. Pada respons non-200, rule bawaan `31105` diteruskan ke `100468`; pada respons 200, Wazuh mengeluarkan `31106` dan rule `100469` memeriksa ulang bahwa URL memang mengandung pola XSS. Kedua jalur masuk grup khusus yang dihitung oleh `100470` level 10 setelah lima probe dari IP sama dalam 60 detik. Rule `31106` yang berasal dari serangan web lain tidak dihitung sebagai XSS. Jika ambang auto-response SOC 10, IP tidak ada di whitelist, alert masih baru, dan alias pfSense dapat ditulis, SOC dapat auto-block. **Jangan** mengklaim XSS dieksekusi di browser tanpa uji aplikasi terpisah.

Untuk demo dengan homepage yang menghasilkan 200, bukti yang dicari adalah baris access log berisi URL terenkode dan IP Kali, alert `100469`/`100470` pada Manager/SOC, lalu status `BLOCKED` dan alias `SOC_Blocklist` di pfSense. Sesudah block, kirim satu koneksi baru: pemblokiran WAN terbukti bila tidak ada respons Apache maupun baris access log baru. Jika hanya terlihat `31106` level 6, ruleset Manager belum terbarui atau perlu diperiksa dengan `wazuh-logtest` memakai baris access log asli.

#### 4.11 Shellshock pada User-Agent — `31168`/`31169` atau `100490`

```bash
curl --connect-timeout 3 --max-time 8 -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  -H "Host: ${LAB_HOST}" -A '() { :; }; echo STIS_SOC_TEST' \
  "${LAB_URL}/cgi-bin/test.sh"
```

CGI/Bash **tidak perlu diaktifkan**; `404` masih bisa membuktikan bahwa header tercatat dan dikenali. Pada Wazuh 4.14 lab, rule bawaan dapat berupa `31168` untuk 2xx atau `100490` untuk 4xx/5xx; ikuti hasil `check_attack_matrix.py` aktual. Jika Anda mengaktifkan CGI yang memang rentan, itu sudah menjadi uji eksploitasi lain dan bukan bagian dari prosedur aman ini.

#### 4.12 SSRF indikatif — `100480` satu probe; `100481` setelah berulang

```bash
LAB_WAN="$LAB_WAN" LAB_HOST="$LAB_HOST" bash /root/run_web_attack_tests.sh ssrf-once

# Untuk uji independen dari ssrf-once, tunggu lebih dari 3600 detik dan pastikan IP Kali di-unblock:
LAB_WAN="$LAB_WAN" LAB_HOST="$LAB_HOST" bash /root/run_web_attack_tests.sh ssrf
```

Path sengaja tidak ada agar server tidak melakukan fetch ke alamat internal. Satu request menghasilkan `100480` level 8 untuk investigasi (`below_threshold` pada ambang SOC 10). Lima **event log** berpola sama dari IP yang sama dalam 3600 detik menghasilkan `100481` level 10 dan dapat auto-block jika kebijakan SOC, whitelist, umur alert, dan pfSense mengizinkan. Skrip mengirim lima request, tetapi Wazuh menghitung event log; pastikan satu request hanya dikoleksi sekali. Pisahkan uji satu request dan lima request lebih dari 3600 detik, atau gunakan IP sumber berbeda, supaya hitungan lama tidak ikut. Simpan bukti alert `100481`, Audit Log, alias pfSense, lalu coba koneksi baru setelah diblokir. Ini membuktikan mitigasi **probe URL berulang**, bukan SSRF berhasil; bukti server melakukan fetch memerlukan log egress/DNS dan aplikasi uji yang terisolasi.

Jika satu request menghasilkan dua alert `100480` identik, periksa field `location` pada kedua alert Wazuh dan semua `<localfile>` Agent/grup di STIS. Misalnya access log yang sama dapat dikumpulkan melalui log bawaan Apache sekaligus log STIS SOC, atau wildcard dikonfigurasi dua kali. Pastikan hanya satu sumber log untuk tiap request sebelum menafsirkan ambang lima event sebagai lima percobaan unik; jangan menghapus sumber lain tanpa memeriksa pemakaiannya.

#### 4.13 SSH brute force — `100001` lalu `100002` (opsional)

Uji nyata hanya jika SSH target memang bisa dicapai **melalui jalur pfSense yang diblokir SOC**. Jika port 22 tidak dipublikasikan, jalankan uji rule sintetis berikut pada **Manager** dan tandai uji end-to-end **tidak berlaku**; jangan membuka SSH ke internet untuk laporan. `198.51.100.77` adalah IP dokumentasi dan tidak akan diblokir oleh uji logtest:

```bash
for n in 1 2 3 4 5; do
  printf 'Oct  2 10:00:00 STIS sshd[1234]: Failed password for invalid user stis-soc-invalid from 198.51.100.77 port 40001 ssh2\n'
done | sudo /var/ossec/bin/wazuh-logtest
```

Periksa Phase 2 (`srcip`) dan Phase 3; bila rule bawaan pada versi Wazuh Anda berbeda, catat ID aktual, bukan memaksakan klaim `100002`. Untuk lab tertutup, admin dapat membuat NAT port-forward **sementara** di pfSense: WAN TCP `2222` → server STIS TCP `22`, sumber dibatasi IP Kali, rule pass hanya untuk IP itu, lalu hapus NAT/rule setelah tes. Pastikan Agent mengoleksi auth log sesuai instalasi Wazuh.

Jika jalur sementara itu sudah siap, pada Kali buat lima password salah untuk user yang **tidak ada**, lalu jalankan percobaan serial. `hydra` dipakai hanya pada host lab milik Anda:

```bash
printf '%s\n' wrong-1 wrong-2 wrong-3 wrong-4 wrong-5 > /tmp/stis-soc-wrong-passwords.txt
hydra -l stis-soc-invalid -P /tmp/stis-soc-wrong-passwords.txt \
  -t 1 -s 2222 "ssh://${LAB_WAN}"
rm -f /tmp/stis-soc-wrong-passwords.txt
```

Harapkan `100002` level 10 dengan IP Kali jika lima gagal tercatat dalam 60 detik. Jangan anggap satu rule `5716`/`100001` cukup untuk auto-block threshold 10. Jika firewall memblokir sebelum lima request, catat rule aktual dan ulangi hanya setelah reset IP uji. Kembalikan NAT/rule sementara ke keadaan awal setelah tes.

#### 4.14 Korelasi HTTP 400 generik — `31151` (opsional)

Kode SOC masih mengenali rule Wazuh bawaan `31151` untuk beberapa HTTP 400 dari IP sama. Rule ini **tidak spesifik** terhadap jenis serangan, sehingga jangan menafsirkannya sebagai bukti SQLi/XSS. Bila helper lab bagian 3 terpasang, mode tidak dikenal mengembalikan `400` tanpa menulis JSON keamanan; gunakan hanya jika ingin mengevaluasi false positive dan efek block generik:

```bash
for n in 1 2 3 4 5 6 7 8 9 10; do
  curl --connect-timeout 3 --max-time 8 -sS -o /dev/null \
    -H "Host: ${LAB_HOST}" -H "X-STIS-SOC-Lab-Token: ${LAB_TOKEN}" \
    --data-urlencode 'mode=unknown' "${LAB_URL}/lab_probe.php"
done
```

Amati apakah versi Wazuh yang terpasang menghasilkan `31151` level ≥ threshold dan bagaimana SOC memutuskan block. Bila tidak muncul, catat sebagai **tidak terpicu**; jangan membuat kesimpulan bahwa semua 400 berbahaya atau bahwa rule tersebut wajib ada pada setiap versi.

### 5. Uji perubahan file, judol/pinjol, dan webshell tanpa IP

Bagian ini berjalan **di server STIS**, tidak membutuhkan Kali. Cara operasional yang disarankan adalah `sudo bash /tmp/run_file_integrity_tests.sh prepare`, lalu `events`, dan setelah bukti disimpan `cleanup`, seperti pada [bagian 0.7](#07-uji-fim-judolpinjol-dan-pola-webshell-file). Perintah manual di bawah hanya referensi langkah yang dilakukan skrip; **jangan jalankan keduanya pada satu siklus uji**. Pastikan FIM Agent memantau `/var/www`, rule `100304` generik sudah ada di Manager, dan Website Guard terpasang. Direktori serta state uji terpisah dari baseline `web1` dan tidak berada dalam DocumentRoot `web1`.

```bash
TEST_ROOT='/var/www/stis-soc-lab-test'
TEST_STATE='/var/lib/stis-soc-guard-test'
GUARD_LOG='/var/log/mini-soc/website_guard.log'
TIMER_WAS_ACTIVE="$(systemctl is-active website-guard.timer || true)"
if [ -e "$TEST_ROOT" ] || [ -e "$TEST_STATE" ]; then
  echo 'Direktori/state uji sudah ada; periksa dahulu sebelum mengulang init.' >&2
  exit 1
fi
sudo systemctl stop website-guard.timer
sudo install -d -m 0700 "$TEST_ROOT"
printf '%s\n' 'STIS SOC FIM TEST ONLY' | \
  sudo tee "$TEST_ROOT/integrity.txt" >/dev/null
sudo /usr/local/sbin/website_guard.py init \
  --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"
```

`init` di sini hanya menyetujui **file benign uji** di `TEST_ROOT`; tidak menyetujui perubahan pada website asli. Timer dihentikan sementara agar pemindaian terjadwal dengan root `/var/www` tidak mencampur event uji dengan baseline utama. Gunakan **shell SSH yang sama** hingga bagian pembersihan karena variabel di atas dipakai lagi. Jangan gunakan `--force`. Uji penambahan, modifikasi, dan penghapusan dengan pemeriksaan terpisah:

```bash
printf '%s\n' 'STIS SOC NEW FILE' | sudo tee "$TEST_ROOT/added.txt" >/dev/null
sudo /usr/local/sbin/website_guard.py check \
  --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"
printf '%s\n' 'STIS SOC FIM TEST CHANGED' | \
  sudo tee "$TEST_ROOT/integrity.txt" >/dev/null
sudo /usr/local/sbin/website_guard.py check \
  --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"
sudo rm -f -- "$TEST_ROOT/integrity.txt"
sudo /usr/local/sbin/website_guard.py check \
  --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"
```

Harapkan Website Guard `100301` untuk *added* dan *modified*, `100302` untuk *deleted*, serta FIM `100304` pada perubahan file. File yang dihapus harus merupakan bagian baseline, seperti `integrity.txt`; menghapus file baru yang **tidak pernah dibaseline** hanya mengembalikan keadaan ke baseline dan tidak menghasilkan event `deleted` dari Website Guard. FIM sendiri dapat mengeluarkan alert tambahan untuk metadata; bukti utama adalah path dan waktu.

Untuk konten judol, pinjol, dan tanda PHP mirip webshell, gunakan **file `.txt` yang tidak dapat disajikan website** berikut, lalu jalankan satu pemeriksaan Guard:

```bash
printf '%s\n' 'STIS SOC TEST: situs slot gacor' | \
  sudo tee "$TEST_ROOT/gambling.txt" >/dev/null
printf '%s\n' 'STIS SOC TEST: pinjaman online cair cepat' | \
  sudo tee "$TEST_ROOT/loan.txt" >/dev/null
printf '%s\n' '<?php eval(base64_decode("TEST_ONLY")); ?>' | \
  sudo tee "$TEST_ROOT/webshell-pattern.txt" >/dev/null
sudo /usr/local/sbin/website_guard.py check \
  --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"
sudo tail -n 10 /var/log/mini-soc/website_guard.log
```

Harapkan event `web_content_threat` bertipe `gambling_spam`/`loan_spam` menjadi rule `100300` level 12; `webshell_code` menjadi `100305` level 14. SOC menampilkan path/hash dan tip penanganan, `action_taken=integrity_alert`, **tanpa auto-block IP**. Tanda webshell di `.txt` tidak dieksekusi. Jika Guard belum terpasang/baseline belum siap, `100300/100305` tidak dapat diklaim dari FIM saja; FIM hanya membuktikan perubahan file. Skrip Guard menahan pengiriman ulang temuan yang sama; `new_events: 0` pada pemeriksaan kedua **normal**.

Setelah screenshot/hasil disimpan, hapus **hanya** file dan direktori uji ini. Jalankan Guard **sebelum** menghapus direktori root uji agar perubahan terakhir tercatat:

```bash
test "$TEST_ROOT" = '/var/www/stis-soc-lab-test' || exit 1
sudo rm -f -- "$TEST_ROOT/added.txt" "$TEST_ROOT/integrity.txt" \
  "$TEST_ROOT/gambling.txt" "$TEST_ROOT/loan.txt" \
  "$TEST_ROOT/webshell-pattern.txt"
sudo /usr/local/sbin/website_guard.py check \
  --root "$TEST_ROOT" --state-dir "$TEST_STATE" --log "$GUARD_LOG"
sudo rmdir "$TEST_ROOT"
test "$TEST_STATE" = '/var/lib/stis-soc-guard-test' || exit 1
sudo rm -f -- "$TEST_STATE/baseline.json" "$TEST_STATE/seen.json"
sudo rmdir "$TEST_STATE"
if [ "$TIMER_WAS_ACTIVE" = active ]; then
  sudo systemctl start website-guard.timer
fi
```

Jangan menjalankan `website_guard.py approve` untuk file uji atau temuan mencurigakan. Baseline sah baru disetujui setelah investigasi.

### 6. Verifikasi Manager, SOC, dan penegakan firewall

Di **Manager/UbuntuServer**, periksa rule ID dan IP pada alert nyata (bukan output `wazuh-logtest`):

```bash
sudo tail -n 300 /var/ossec/logs/alerts/alerts.json | \
  grep -E '"id"[[:space:]]*:[[:space:]]*"(100002|100102|100501|100510|100300|100304|100305|100401|100411|100421|100430|100440|100451|100460|100468|100469|100470|100480|100481|100490)"' | \
  tail -n 20
cd /root/backend
venv/bin/python check_auto_response.py
venv/bin/python check_sqli.py --limit 1000
venv/bin/python check_defacement.py --limit 1000
```

Di **SOC**, tekan **Fetch New Alerts**, lalu lihat **Alerts → detail**: `rule_id`, level, `source IP`, agent, target path, jenis serangan, `action_taken`, dan waktu. Pada **Blocked IPs**, lihat status dan alasan. Pada **Audit Log**, cocokkan tindakan dengan waktu skenario. Jika yang terlihat hanya alert 4xx generik, catat itu sebagai hasil aktual dan periksa event spesifik di JSONL/Manager; jangan tulis bahwa SQLi/brute force spesifik berhasil tanpa rule spesifiknya.

Di **pfSense**, cocokkan IP Kali pada alias `SOC_Blocklist`, urutan rule WAN Block terhadap pass/HAProxy, dan **Diagnostics → States** untuk IP itu. Bila `pfsense_kill_states_on_block=true`, SOC mencoba membersihkan state aktif; pastikan hasilnya di audit/log. Setelah status `BLOCKED`, lakukan satu koneksi **baru** dari Kali ke website melalui WAN. Hasil sukses penegakan adalah timeout/penolakan di firewall **dan** tidak ada baris baru pada access log Apache. Jika HTTP `403` dari PHP masih muncul dan access log bertambah, trafik masih lewat; periksa interface rule, urutan, alias, state, IPv6, dan kemungkinan jalur langsung yang melewati pfSense. Hindari menyimpulkan “aman sepenuhnya” hanya dari status dashboard.

### 7. Uji negatif dan keterbatasan yang perlu dilaporkan

| Kondisi | Ekspektasi SOC | Cara verifikasi tanpa merusak lab |
| --- | --- | --- |
| Satu probe webshell/WordPress/scanner level di bawah threshold | Alert boleh muncul, tidak auto-block | Kirim **satu** request saja setelah reset dan catat `below_threshold` |
| Satu SSRF indikatif `100480` | `below_threshold`, tidak auto-block pada ambang 10 | Jalankan `ssrf-once`, lalu cek IP tidak ditambah ke alias; pengujian lima probe dilakukan pada sesi terpisah |
| FIM/Guard tanpa IP | `integrity_alert`, tidak auto-block | Jalankan bagian 5 dan cek path file serta alasan |
| IP pada whitelist | `whitelisted` walau rule tinggi | Gunakan IP uji yang memang sengaja di-whitelist pada Settings; jangan pakai IP pfSense/admin untuk uji blokir |
| Auto-response dimatikan | `disabled`, tidak ada perubahan alias | Matikan sementara melalui Settings, kirim satu event uji, lalu aktifkan kembali |
| Alert lama/format waktu salah | `stale_alert`/`invalid_timestamp`, tidak auto-block | Lihat keputusan di `check_auto_response.py`/tes kode; jangan memasukkan alert palsu ke Indexer produksi |
| IP sudah diblokir | Tidak menambah block duplikat | Ulangi pemeriksaan SOC dan pfSense; request baru seharusnya gagal sebelum Apache |
| Situs/API tanpa log yang cocok | Tidak ada bukti deteksi jenis itu | Tandai **belum memenuhi syarat**, lalu tambah event aplikasi atau sumber log sesuai panduan Agent |

Perlindungan yang diuji berlaku pada **jalur trafik yang melewati rule pfSense**. HTTPS/TLS passthrough, akses LAN langsung, IPv6, proxy lain, CDN, atau IP klien yang berubah memerlukan penilaian jalur tersendiri. Rule berbasis pola URL/User-Agent tidak membuktikan aplikasi benar-benar rentan; uji pencegahan kerentanan aplikasi memerlukan pengujian aplikasi terpisah. Tidak ada deteksi otomatis untuk seluruh jenis serangan baru tanpa log/decoder/rule yang sesuai.

### 8. Format tabel hasil untuk skripsi/evaluasi

Isi **satu baris per skenario**, termasuk kegagalan. Simpan screenshot SOC/pfSense dan cuplikan log dengan waktu yang sama; jangan mengubah hasil yang gagal menjadi `lulus` hanya karena `wazuh-logtest` lulus.

Checklist kasus yang perlu mendapat baris sendiri dalam tabel hasil: brute force web/service (4.1), SQLi (4.2), probe webshell (4.3), scan WordPress (4.4), scanner User-Agent (4.5), file sensitif (4.6), probe RCE (4.7), enumerasi (4.8), traversal/LFI (4.9), XSS (4.10), Shellshock (4.11), SSRF indikatif (4.12), brute force SSH bila ada jalur yang sesuai (4.13), korelasi HTTP 400 bila tersedia (4.14), penambahan/modifikasi/penghapusan file, konten judol/pinjol, tanda webshell pada file (bagian 5), serta penegakan dan uji negatif (bagian 6–7). Tandai setiap kasus **lulus**, **gagal**, atau **tidak berlaku** beserta alasannya.

| ID kasus | Tanggal/jam + zona | IP uji | Target dan jalur | Input/URL uji | HTTP/status | Log target bertambah? | Rule ID/level Manager | SOC action | Alias pfSense | Koneksi baru terhenti? | Tingkat bukti A–D | Keputusan/penyebab |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T01 | [isi] | [isi] | [isi] | auth-failed 5× | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] |
| T02 | [isi] | [isi] | [isi] | SQLi lab | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] |
| T03 | [isi] | [isi] | [isi] | probe URL | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] | [isi] |
| T04 | [isi] | — | file lokal | FIM/Guard | — | [isi] | [isi] | [isi] | — | — | [isi] | [isi] |

Simpan juga konfigurasi uji yang relevan (threshold, whitelist, interval, umur alert, versi Wazuh, status Agent, posisi rule pfSense) dan waktu pemulihan setelah tiap kasus. **Hasil nyata baru dapat diisi setelah perintah dijalankan pada VM**; dokumen ini tidak menyatakan bahwa semua simulasi sudah lulus di lab Anda.

### 9. Pemulihan demo dan pembersihan final

**Antarsesi demo atau saat masih menulis skripsi:** bersihkan hanya berkas uji FIM yang terisolasi. Website `web1`, helper, token, Apache, Agent, Website Guard, dan pfSense tetap dapat dipakai lagi. Perintah berikut dijalankan **di STIS**, tiap baris terpisah tanpa tanda `\` di ujung:

```bash
sudo bash /tmp/run_file_integrity_tests.sh cleanup
sudo systemctl is-active apache2 wazuh-agent website-guard.timer
```

Di SOC, lakukan **Unblock** hanya IP Kali yang digunakan untuk uji, cek alias `SOC_Blocklist`, dan hapus state **IP itu saja** melalui **pfSense → Diagnostics → States** sebelum uji berikutnya. Pertahankan WAN Block rule/alias dan seluruh konfigurasi monitoring. Inilah kondisi yang tepat bila demo akan diulang.

**Setelah seluruh demo selesai dan bukti telah disimpan:** `cleanup_target_lab.sh` menghapus hanya `/var/www/web1/lab_probe.php`, `/etc/stis-soc-lab/probe-token`, dan sisa konfigurasi Apache helper dari versi lama bila ada. Skrip tidak menghapus `/var/www/web1` atau `web1.conf`, log bukti, `CustomLog`, `RemoteIPHeader`, konfigurasi Agent/FIM, Website Guard, Wazuh Manager/SOC, maupun pfSense. Akibatnya **demo brute force dan SQLi berbasis helper tidak bisa dijalankan lagi** sampai `setup_target_lab.sh` dipasang ulang. `check_target_readiness.sh production` sengaja tidak menuntut helper/token.

```bash
# STIS, hanya setelah tidak membutuhkan helper demo
sudo bash /tmp/run_file_integrity_tests.sh cleanup
sudo bash /tmp/cleanup_target_lab.sh
sudo LAB_HAPROXY_IP=10.10.10.1 bash /tmp/check_target_readiness.sh production
sudo systemctl is-active apache2 wazuh-agent website-guard.timer
```

Jika salinan skrip tidak ada di `/tmp`, salin dari UbuntuServer sesuai langkah 0.2. Bila dulu Anda menambahkan `<Files "lab_probe.php">` manual di VirtualHost, skrip memberi peringatan; periksa `sudo grep -Rni 'lab_probe.php' /etc/apache2/sites-enabled` dan hapus **hanya blok lama** itu setelah `apache2ctl configtest` dan reload. `setup_target_lab.sh` versi sekarang tidak menambahkan blok `<Files>`/`<Location>`; helper dilindungi oleh token privat.

Jika perlu mengulang demo nanti, salin helper/skrip terbaru dari UbuntuServer lalu pada STIS jalankan lagi `sudo bash /tmp/setup_target_lab.sh 10.10.10.1 /var/www/web1 web1.stis.local` dan `sudo bash /tmp/check_target_readiness.sh lab`. Token baru dapat dibaca di STIS dengan `sudo cat /etc/stis-soc-lab/probe-token`; jangan menyimpannya di repo atau laporan.

Setelah verifikasi final, hapus hanya salinan skrip sementara bila tidak diperlukan lagi:

```bash
# STIS
sudo rm -f -- /tmp/lab_probe.php /tmp/setup_target_lab.sh \
  /tmp/check_target_readiness.sh /tmp/run_file_integrity_tests.sh \
  /tmp/cleanup_target_lab.sh

# UbuntuServer: laporan matriks sementara saja; jangan hapus alert/audit
sudo rm -f -- /tmp/stis-soc-rule-matrix.json

# Kali: salinan skrip lokal dan token sesi
unset LAB_TOKEN
sudo rm -f -- /root/run_web_attack_tests.sh /tmp/run_web_attack_tests.sh
```

### 10. PoC host Linux tambahan tanpa Windows atau Docker

| Bagian PoC yang relevan | Kondisi di STIS SOC | Bukti minimum |
| --- | --- | --- |
| IP berbahaya yang dikenal | Rule `100600` ditambahkan; auto-block bersyarat | Alert dengan IP asli, alias pfSense terisi, request ulang tertahan |
| FIM website/Linux | Sudah ada melalui Wazuh FIM dan Website Guard | Perubahan file uji, alert path dan hash |
| SSH brute force Ubuntu | Rule bawaan Wazuh dan respons SOC sudah ada | Kegagalan login berulang, alert korelasi dan status blokir bila ada IP |
| Utilitas jaringan mencurigakan di Linux | Rule `100611` ditambahkan | Proses `nc`/`nc.openbsd` terlihat dan alert muncul; status sah/tidak sah perlu investigasi |
| SQL injection website | Sudah ada dari log aplikasi/Apache | Request uji, alert SQLi, status HTTP, lalu bukti pfSense bila diblokir |
| VirusTotal/malware | Integrasi opsional, butuh API key sendiri | Hash FIM dan hasil `87105`; file **tidak** dihapus otomatis |
| CVE paket | Modul bawaan Wazuh; perlu Syscollector dan feed | Paket/CVE aktual di Wazuh Dashboard; SOC hanya menampilkan event alert |
| Rootcheck/hidden process | Modul bawaan; file tersembunyi dapat diuji | Alert `510` jika muncul; `521` belum teruji tanpa proses tersembunyi nyata |
| Eksekusi perintah mencurigakan | Rule Auditd `100610` ditambahkan | Log Auditd dan alert executable/host |
| Shellshock | Deteksi request sudah ada | Alert payload web dan blokir IP bila syarat respons terpenuhi |

Bagian Windows/RDP dan Docker dalam PDF tidak berlaku untuk lab Ubuntu saat ini. Jika Ubuntu kelak dipasang `xrdp` atau container runtime, penilaian perlu diperbarui; OS Ubuntu sendiri tidak mewajibkan keduanya. Uji berikut melengkapi kategori Linux pada [PoC Wazuh](https://documentation.wazuh.com/current/proof-of-concept-guide/index.html). Bedakan **rule lulus di `wazuh-logtest`** dari **alert nyata Agent → Manager → Indexer → SOC**, dan bedakan alert dari blokir firewall yang benar-benar menghentikan request.

**Sinkronkan kode dan Manager terlebih dahulu** di UbuntuServer. Skrip memasang daftar CDB contoh hanya bila belum ada dan mempertahankan daftar yang telah diedit operator; ia mem-backup `ossec.conf`, rule, dan decoder sebelum validasi. Daftar bawaan berisi satu alamat dokumentasi, sehingga belum memblokir pengguna nyata.

```bash
# UbuntuServer / Manager
test -f /media/sf_VM-Share/lists/stis-known-bad
test -f /media/sf_VM-Share/lists/stis-suspicious-programs
sudo bash /media/sf_VM-Share/scripts/testing/prepare_manager.sh
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl is-active wazuh-manager wazuh-indexer filebeat
```

Skrip ini juga me-restart SOC dari source terbaru. **Jika berhenti sebelum `[SELESAI]`, jangan mengklaim fitur baru sudah aktif.** Dari UbuntuServer, kirim skrip telemetri ke STIS menggunakan akun SSH yang memang dapat menerima file (sesuaikan bila bukan `vboxuser`):

Jika daftar `/var/ossec/etc/lists/stis-suspicious-programs` sudah ada dari pemasangan sebelumnya, skrip sengaja mempertahankan isinya. Untuk uji `nc.openbsd`, pastikan baris `nc.openbsd:review` ada; tambahkan sendiri bila belum ada, lalu restart Manager. Jangan mengganti daftar operator yang telah ditinjau dengan file contoh dari repositori.

```bash
scp /root/scripts/testing/prepare_linux_host_detection.sh vboxuser@10.10.10.30:/tmp/
```

```bash
# STIS / server target, setelah file ada di /tmp
sudo bash /tmp/prepare_linux_host_detection.sh
sudo auditctl -l | grep audit-wazuh-c
sudo auditctl -s | grep enabled
sudo /var/ossec/bin/wazuh-logcollector -t
sudo systemctl is-active auditd wazuh-agent
```

Skrip ini hanya menambah jalur Auditd dan pemeriksaan proses; ia tidak mengubah website, VirtualHost, pfSense, atau helper token. Sebelum menjalankannya pada host sibuk, pertimbangkan volume log `execve`. Ia memantau sesi pengguna dengan `auid >= 1000`; perintah yang berasal dari sesi root langsung tidak tercakup.

| Skenario | Pemicu dan bukti | Respons |
| --- | --- | --- |
| IP reputasi yang ditinjau | `100600`, IP/URL access log, daftar CDB Manager | SOC dapat auto-block pfSense bila level/umur/whitelist/IP lolos |
| Utilitas mencurigakan dieksekusi | Auditd `100610`, host dan `audit.exe` | Investigasi host; **tanpa** auto-block IP |
| Utilitas mencurigakan masih berjalan | `ps` berkala `100611`, full log memuat proses | Investigasi host; tanpa auto-block IP |
| Anomali Rootcheck | Rule bawaan seperti `510` atau `521` | Investigasi host; tanpa auto-block IP |
| CVE paket Linux | Event bawaan `vulnerability-detector` bila modul aktif | Patch paket; tanpa auto-block IP |
| Hash file terindikasi malware | VirusTotal `87105` **hanya jika API key diaktifkan** | Isolasi/pulihkan file setelah verifikasi; tanpa hapus otomatis atau auto-block IP |

**Uji reputasi IP dari Kali melalui website.** Catat IP Kali saat ini dari `ip -4 route get 192.168.18.99` dan masukkan **hanya alamat itu** ke daftar Manager. Jangan masukkan `10.10.10.1`, IP administrator, atau subnet luas. Contoh di bawah memakai IP Kali lama `192.168.18.103`; ganti bila berubah.

```bash
# UbuntuServer / Manager
KALI_IP='192.168.18.103'
printf '%s:\n' "$KALI_IP" | sudo tee -a /var/ossec/etc/lists/stis-known-bad
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager

# Kali, satu request kontrol melalui WAN pfSense/HAProxy
curl -i --connect-timeout 3 --max-time 8 -H 'Host: web1.stis.local' \
  http://192.168.18.99/
```

Cari `100600` dengan IP Kali pada `alerts.json` Manager, lalu di SOC **Alerts**, **Blocked IPs**, dan **Audit Log**. Setelah status blokir, request **baru** harus gagal mencapai Apache dan access log tidak bertambah. Jika HTTP masih datang dari Apache, perbaiki urutan rule WAN/alias/state pfSense; status SOC saja bukan bukti perlindungan. Setelah menyimpan bukti, hapus **baris uji tepat itu** dari `/var/ossec/etc/lists/stis-known-bad` dengan `sudo nano`, validasi dan restart Manager, lalu **Unblock** IP Kali di SOC. Tanpa langkah ini, uji berikutnya dari Kali dapat terhalang sebelum mencapai target. [Referensi CDB Wazuh](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html).

**Uji eksekusi dan proses Linux** dilakukan pada STIS dari sesi SSH sebagai akun manusia (`vboxuser` dalam contoh), bukan dari Kali dan bukan dari shell root langsung. Pasang `netcat-openbsd` bila belum ada; menjalankan `nc -h` hanya menampilkan bantuan tetapi tetap menghasilkan event eksekusi Auditd. Agar pemindaian 120 detik sempat melihat proses, jalankan listener **loopback saja**, periksa PID-nya, lalu hentikan setelah pengamatan:

```bash
# STIS sebagai vboxuser; gunakan sudo hanya untuk instalasi paket
sudo apt-get install -y netcat-openbsd
nc -h >/dev/null 2>&1 || true
nc -l 127.0.0.1 18080 >/dev/null 2>&1 &
POC_NC_PID=$!
ps -p "$POC_NC_PID" -o pid,comm,args
sleep 150
kill "$POC_NC_PID" 2>/dev/null || true
```

Di Manager, cari alert `100610` (eksekusi) dan `100611` (proses berjalan). Jika `100610` tidak ada, periksa `sudo ausearch -k audit-wazuh-c -ts recent`, `/var/log/audit/audit.log`, dan koleksi Agent. Jika `100611` tidak ada, pastikan listener benar-benar tetap hidup selama satu siklus 120 detik dan `ps -eo pid=,comm=` menampilkan `nc` atau `nc.openbsd`. Kedua uji ini mendeteksi utilitas yang *mungkin* dipakai secara tidak sah; itu bukan bukti otomatis bahwa host telah disusupi. [Referensi Auditd](https://documentation.wazuh.com/current/proof-of-concept-guide/audit-commands-run-by-user.html), [pemantauan proses Linux](https://documentation.wazuh.com/current/user-manual/capabilities/command-monitoring/use-cases/monitoring-running-processes.html).

Setelah scheduler SOC mengambil alert, pada UbuntuServer gunakan pemeriksaan baca-saja berikut untuk mencatat rule, Agent, waktu, dan keputusan SOC. Skrip memilih rule IP reputasi/Auditd/proses serta kelompok Rootcheck, VirusTotal, dan vulnerability-detector. Ia hanya menampilkan alert sejak tanggal UTC hari ini secara default agar data seed lama tidak disalahartikan sebagai hasil uji baru; bila perlu gunakan `--since YYYY-MM-DD`. Keluaran kosong berarti alert belum masuk ke database SOC meskipun mungkin sudah ada di Manager:

```bash
cd /root/backend
venv/bin/python check_linux_poc.py --limit 20
```

**Rootcheck** bawaan Wazuh dapat mencari anomali file/proses tanpa memasang rootkit sungguhan pada server skripsi. Pada STIS, pastikan blok `<rootcheck>` di `ossec.conf` tidak `disabled=yes`. Untuk uji file tersembunyi, lakukan urutan berikut hanya pada lab: buat file kosong di STIS, minta Manager memulai pemindaian Agent STIS, tunggu alert, lalu hapus file uji.

```bash
# STIS / target; file kosong ini bukan rootkit
sudo install -m 0600 /dev/null /dev/.stis-soc-poc
```

```bash
# UbuntuServer / Manager
sudo /var/ossec/bin/agent_control -lc
sudo /var/ossec/bin/agent_control -r -u 001
```

Di Manager cari `510` yang menunjuk `/dev/.stis-soc-poc`; scan dapat memerlukan waktu. Jika tidak muncul, catat hasil itu dan periksa log Rootcheck/Agent tanpa mengklaim lulus. Sesudah pengamatan, pada STIS jalankan `sudo rm -f -- /dev/.stis-soc-poc`. Hasil `521` khusus proses tersembunyi **tidak boleh diklaim lulus** tanpa proses yang benar-benar disembunyikan; proyek ini tidak memasang rootkit untuk memaksakan hasil tersebut. [Referensi Rootcheck](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/rootkits-behavior-detection.html).

**Deteksi CVE** memerlukan modul Manager `<vulnerability-detection><enabled>yes</enabled>` dan Syscollector Agent aktif. Periksa konfigurasi tersebut serta koneksi Indexer, lalu lihat **Wazuh Dashboard → Vulnerability Detection → Inventory/Events** untuk Agent STIS. SOC mengategorikan event CVE yang dikirim ke alert Indexer, tetapi inventaris seluruh CVE yang masih aktif tetap dilihat di Wazuh Dashboard. Jangan menginstal paket sengaja rentan di server website hanya agar tabel skripsi terisi. Jika tidak ada CVE aktual, catat status *modul aktif, belum ada temuan*, bukan lulus deteksi CVE. [Referensi Vulnerability Detection](https://documentation.wazuh.com/current/proof-of-concept-guide/poc-vulnerability-detection.html).

```bash
# UbuntuServer / Manager; hanya membaca konfigurasi, tidak menampilkan password
sudo sed -n '/<vulnerability-detection>/,/<\/vulnerability-detection>/p' /var/ossec/etc/ossec.conf
sudo systemctl is-active wazuh-manager wazuh-indexer
```

Pada **STIS/Agent** saja:

```bash
sudo sed -n '/<wodle name="syscollector">/,/<\/wodle>/p' /var/ossec/etc/ossec.conf
sudo systemctl is-active wazuh-agent
```

Bila blok Manager ada tetapi `<enabled>no</enabled>`, backup `/var/ossec/etc/ossec.conf`, ubah **blok yang sudah ada** menjadi `<enabled>yes</enabled>` dan `<index-status>yes</index-status>`, validasi konfigurasi lalu restart Manager. Bila Syscollector Agent `disabled=yes`, ubah blok yang sudah ada menjadi `disabled=no`, validasi Agent, lalu restart Agent. Jangan menduplikasi blok atau mengubah host/sertifikat Indexer tanpa memeriksa topologi sebenarnya; hasil CVE memerlukan sinkronisasi feed dan inventaris paket, sehingga tidak selalu muncul segera.

```bash
# Hanya bila fitur terkait masih disabled; jalankan pada VM yang tercantum.
# UbuntuServer / Manager
sudo cp -a /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
sudo nano /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

Pada **STIS/Agent** saja, dalam sesi SSH terpisah:

```bash
sudo cp -a /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
sudo nano /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-agentd -t
sudo systemctl restart wazuh-agent
```

Jangan menyalin seluruh blok `ossec.conf` dari VM lain. Ubah hanya nilai pada blok yang sudah ada, dan hentikan sebelum `restart` jika validasi gagal.

**VirusTotal bersifat opsional dan memerlukan API key milik Anda.** Pada Manager, jalankan `sudo bash /root/scripts/testing/enable_virustotal_manager.sh`; kunci diminta tanpa ditampilkan. Skrip hanya mengaktifkan pemeriksaan hash untuk FIM website rule `100304`; ia tidak menghapus file dan tidak mengatur Active Response berbasis IP. Jika belum mempunyai key atau tidak memenuhi ketentuan layanan/rate limit API, tandai uji ini *belum diaktifkan*. Untuk uji EICAR resmi, gunakan direktori uji di bawah `/var/www` yang **tidak menjadi DocumentRoot** dan hapus file segera setelah bukti FIM/`87105` tersimpan. Periksa `/var/ossec/logs/integrations.log` pada Manager bila hasil VT belum muncul. [Referensi VirusTotal Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/malware-detection/virus-total-integration.html).

```bash
# STIS, hanya pada lab terisolasi setelah memastikan /var/www/.stis-soc-poc
# tidak disajikan oleh Apache/HAProxy
sudo install -d -m 0700 /var/www/.stis-soc-poc
curl -fsSL https://secure.eicar.org/eicar.com.txt -o /tmp/stis-soc-eicar.txt
sudo install -m 0600 /tmp/stis-soc-eicar.txt /var/www/.stis-soc-poc/eicar.txt
# Tunggu alert FIM 100304 dan VirusTotal 87105, simpan bukti, lalu:
sudo rm -f -- /var/www/.stis-soc-poc/eicar.txt /tmp/stis-soc-eicar.txt
sudo rmdir /var/www/.stis-soc-poc
```

Jika unduhan EICAR diblokir keamanan setempat atau VirusTotal tidak mengembalikan `87105`, catat kondisi sebenarnya; jangan memalsukan alert. Wazuh mengirim **hash** file ke layanan VirusTotal, dan API publik memiliki batas permintaan serta ketentuan penggunaan. Gunakan key yang sesuai izin penggunaan Anda.

Semua temuan host di atas harus mencantumkan Agent, rule, waktu, path/perintah/paket, dan langkah investigasi di SOC. Tidak adanya `srcip` pada Auditd, FIM, CVE, VirusTotal, atau Rootcheck **memang alasan teknis untuk tidak memblokir IP secara otomatis**.

Jangan jalankan `cleanup_ubuntu.sh` untuk merapikan demo: skrip itu mencopot aplikasi STIS SOC dari UbuntuServer. Uninstall target dan keseluruhan lab memiliki [panduan tersendiri](PANDUAN_03_PENSIUNKAN_SERVER_WEBSITE_DAN_SERVICE.md) dan [panduan total](PANDUAN_04_BONGKAR_LAB_STIS_SOC.md).

## Catatan untuk pencatatan hasil penelitian

- Default source adalah polling 60 detik, usia maksimum 600 detik, dan auto-response mati. Nilai 30/900 pada contoh demo adalah pengaturan uji yang harus disimpan di dashboard. Foto/catat Settings sebelum setiap sesi.
- Nominal frekuensi terbaru: WordPress 8/120 detik, scanner 10/60, recon 5/120, webshell 5/120, XSS 5/60, SSRF 5/3600, brute force 5/60. Catat request ke berapa yang memicu rule; hasil dapat terpengaruh aturan Wazuh yang terpasang dan duplikasi pengumpulan.
- Satu request sah boleh menghasilkan alert informasional, seperti `100100` level 3. “Sah” tidak berarti “tidak boleh ada alert sama sekali”; ukur salah deteksi ancaman dan salah pemblokiran sesuai definisi evaluasi.
- Unblock dari SOC menghapus IP dari alias, tetapi tidak mereset hitungan korelasi Wazuh. Pisahkan sesi pengujian berdasarkan timeframe, terutama SSRF 3600 detik. Alert baru maupun alert tertunda yang dievaluasi ulang dapat memicu blokir berikutnya.
- Untuk host Linux, hasil biasa adalah `review_only` pada `100610` level 10 dan `below_threshold` pada `100611` level 8 (ambang SOC 10, auto-response aktif). IP tidak ditebak dari koneksi SSH untuk memblokir temuan proses.
- Jangan menjumlahkan baris SOC sebagai jumlah request atau jumlah serangan unik. Simpan identitas request, baris log, ID alert Indexer, dan hasil respons secara terpisah.
- Simpan bukti sebelum pembersihan alert; fitur penghapusan admin tidak menghapus file mentah Manager dan tidak mereset korelasi rule. Dataset lama di Indexer juga belum tentu seluruhnya masuk SOC karena batas 100 dokumen per panggilan.
- Dokumentasi arsitektur dan alur keputusan tersedia di [STIS_SOC.md](../STIS_SOC.md). Catat hasil pengujian dari bukti sesi aktual.
