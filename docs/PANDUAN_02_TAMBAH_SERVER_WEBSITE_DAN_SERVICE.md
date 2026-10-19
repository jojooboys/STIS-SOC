# Panduan 02: Menambah server, website, domain, dan service

**Hasil yang ingin dicapai:** satu server terdaftar di Wazuh dan website/service di dalamnya mengirim data dengan pola yang sama. Tidak ada tombol tambah server di SOC; halaman Inventaris Wazuh hanya membaca hasil yang dilaporkan Manager. Penjelasan alur program tersedia di [STIS_SOC.md](../STIS_SOC.md).

**Cara memahami pola umum:** satu Agent dipasang per server. Setiap website mempunyai nama singkat (slug) untuk file log. Agent membaca direktori log bersama, bukan daftar website satu per satu. Website tetap perlu dipasang dan diarahkan melalui DNS/HAProxy oleh administrator; direktori log tidak membuat website secara otomatis.


Panduan ini khusus untuk **server target Ubuntu**: memasang Wazuh Agent, mengirim log dan FIM, lalu menambahkan website, domain, endpoint, atau service. Untuk memasang Wazuh Manager/Indexer, pfSense, HAProxy, dan aplikasi SOC, gunakan [panduan instalasi sistem](PANDUAN_01_INSTALASI_PFSENSE_WAZUH_DAN_STIS_SOC.md). Untuk melepas satu aset atau server tanpa mengganggu yang lain, ikuti [panduan uninstall target](PANDUAN_03_PENSIUNKAN_SERVER_WEBSITE_DAN_SERVICE.md). Jangan menjalankan perintah `/var/ossec/bin/wazuh-analysisd` atau mengubah `local_rules.xml` pada server target: keduanya milik Manager.

## 1. Cara kerja dan batasnya

```text
klien -> pfSense/HAProxy -> website/service di server target
                                    | log Apache + JSON + FIM
                                    v
                               Wazuh Agent -> Manager -> Indexer -> STIS SOC
```

STIS SOC membaca daftar Agent dan konfigurasi log/FIM melalui API Wazuh. Agent yang berhasil terdaftar muncul setelah menekan **Inventaris Wazuh → Refresh**; tidak ada tombol tambah/edit/hapus di SOC. Alert baru muncul setelah log cocok dengan rule Wazuh dan sampai ke Indexer. Wazuh tidak mempunyai inventaris domain atau website terstruktur hanya dari DNS/vhost: nama target ditentukan oleh path log baku atau field `domain`/`asset_name` pada JSON aplikasi. Daftar paket, service, dan port berasal dari Syscollector; itu bukti inventaris host, bukan bukti bahwa suatu domain telah dilindungi.

Konfigurasi di bawah dipasang **sekali pada setiap server target**. Situs atau service berikutnya cukup menulis log pada lokasi baku dan, untuk situs, menyimpan berkas di bawah `/var/www/<slug>/`. Tidak perlu membuat rule baru pada Manager ataupun entri pada database SOC **selama log mengikuti format yang sudah dikenali**. Format baru yang tidak cocok dengan decoder/rule tetap memerlukan integrasi Wazuh tersendiri. DNS, HAProxy, sertifikat, firewall, dan source code aplikasi juga tetap dikelola pada komponennya masing-masing.

| Jenis target | Nama baku `<slug>` | Log yang dikoleksi | Lokasi file yang diawasi |
| --- | --- | --- | --- |
| Website/domain/vhost Apache | `web1`, `sipadu`, `api-stis` | `/var/log/stis-soc/apache/<slug>.access.log` | `/var/www/<slug>/` |
| Service/API dengan peristiwa keamanan | `api-stis`, `auth-service` | `/var/log/stis-soc/apps/<slug>.jsonl` | Opsional, bila file service ada di bawah `/var/www/` |
| Endpoint URL di dalam website | Gunakan slug website induk | Log Apache website induk dan/atau JSON service | Website induk |

Gunakan huruf kecil, angka, `-`, atau `_` untuk slug. Domain sebenarnya, misalnya `web1.stis.local`, dicatat pada VirtualHost dan sebaiknya di field `domain` peristiwa JSON. Satu server dapat mempunyai banyak slug; tiap server memasang satu Agent. **IP klien untuk auto-block harus berasal dari sumber tepercaya**, bukan header HTTP yang dikirim bebas oleh klien.

## 2. Prasyarat pada server target

Contoh lab: Manager `10.10.10.20`, server target STIS `10.10.10.30`, pfSense LAN/HAProxy `10.10.10.1`. Ganti alamat sesuai jaringan. Pastikan waktu tersinkron, DNS/routing benar, dan Agent dapat menjangkau Manager di TCP 1514 dan TCP 1515 saat enrollment. Port 55000/9200 dipakai SOC ke Manager/Indexer, **bukan** Agent ke Manager. Pada Manager, pastikan layanan Wazuh aktif dan rule lokal proyek sudah dipasang satu kali. Untuk dukungan semua root `/var/www/<slug>/`, versi `config/wazuh/rules/local_rules.xml` yang baru memakai rule `100304` generik; pasang ulang file itu pada Manager **sekali** setelah memvalidasi `wazuh-analysisd -t`. Setelah itu penambahan slug baru tidak perlu mengubahnya lagi.

Periksa versi Manager (di **UbuntuServer**):

```bash
/var/ossec/bin/wazuh-control info
sudo systemctl is-active wazuh-manager
```

Pilih Agent dengan versi tidak lebih baru dari Manager. Pada **Manager**, baca versi paket aktif dengan `dpkg-query -W -f='${Version}\n' wazuh-manager`; jangan menebak dari URL installer. Contoh di bawah memakai `4.14.7-1` **hanya bila hasil Manager memang 4.14.7-1**. Instalasi baru dari kanal 4.14 dapat menghasilkan patch lebih baru. Rujukan resmi: [instalasi Agent Linux](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html).

## 3. Pasang dan daftarkan Wazuh Agent (sekali per server)

Jalankan bagian ini melalui SSH **pada server target**, bukan pada UbuntuServer. Jika Agent sudah terpasang, mulai dari `systemctl status` dan jangan memasang ulang agar identitas Agent tetap sama.

```bash
dpkg-query -W wazuh-agent 2>/dev/null || true
sudo systemctl status wazuh-agent --no-pager
```

Untuk pemasangan baru di Ubuntu amd64, sesuaikan versi dengan Manager:

```bash
WAZUH_AGENT_VERSION='4.14.7-1'  # ganti dengan hasil dpkg-query pada Manager
WAZUH_MANAGER_IP='10.10.10.20'
curl -fLO "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_${WAZUH_AGENT_VERSION}_amd64.deb"
sudo WAZUH_MANAGER="$WAZUH_MANAGER_IP" dpkg -i "./wazuh-agent_${WAZUH_AGENT_VERSION}_amd64.deb"
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
sudo systemctl is-active wazuh-agent
sudo /var/ossec/bin/wazuh-agentd -t
```

Jika `dpkg` melaporkan dependensi belum terpenuhi, selesaikan dependensi paket terlebih dahulu; jangan mengulangi enrollment dengan nama Agent berbeda. Bila jaringan memakai enrollment password, lihat parameter enrollment resmi dan minta kredensial dari admin Manager. Periksa koneksi pada target dan registrasi pada Manager:

```bash
# Server target
sudo grep -E 'server|address' /var/ossec/etc/ossec.conf
sudo tail -n 30 /var/ossec/logs/ossec.log

# UbuntuServer / Manager
sudo /var/ossec/bin/agent_control -lc
```

Agent `active` dengan ID selain `000` berarti host telah terdaftar. Pada SOC, buka **Inventaris Wazuh**, klik **Refresh**, lalu pilih Agent tersebut. Bila belum muncul, uji API Manager dari Settings SOC dan pastikan Agent aktif di Manager.

## 4. Pasang pola monitoring lokal (sekali per server)

Pertama, buat direktori tetap. Simpan log **di luar web root**, supaya log tidak bisa diminta lewat HTTP dan tidak menjadi noise FIM:

```bash
sudo install -d -m 0755 /var/log/stis-soc
sudo install -d -m 0755 /var/log/stis-soc/apache
sudo install -d -m 0755 /var/log/stis-soc/apps
sudo install -d -m 0755 /var/www
sudo cp -a /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
sudo nano /var/ossec/etc/ossec.conf
```

Di dalam konfigurasi Agent, tambahkan tiga blok `<localfile>` berikut **tepat satu kali**. File Agent lama mungkin sudah memiliki beberapa blok `<ossec_config>`; itu dapat dipertahankan. Yang penting, jangan menduplikasi sumber log yang sama di blok lokal atau konfigurasi grup Manager. Wildcard Wazuh pada Linux dapat mengambil file baru di direktori tersebut; tidak perlu edit Agent setiap kali slug baru dibuat ([rujukan `localfile`](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)).

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

Di dalam **blok `<syscheck>` yang sudah ada**, tambahkan satu direktori berikut. FIM memantau seluruh website di bawah `/var/www`, termasuk slug yang dibuat nanti. Hindari root lain di luar pola ini bila tidak perlu; pantau kapasitas inotify dan volume alert untuk host besar ([rujukan `syscheck`](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html)).

```xml
<directories check_all="yes" realtime="yes">/var/www</directories>
```

Jika `/var/www` memuat `cache`, `uploads`, session, atau file yang berubah sangat sering, tinjau dan tambahkan `<ignore>` yang spesifik di blok `<syscheck>`; jangan mengabaikan seluruh website. Bila service tidak menjalankan Website Guard, blok log terakhir boleh dihilangkan. Untuk Website Guard dengan beberapa situs, scanner lama yang mengarah ke `/var/www/web1` **hanya melindungi web1**; lihat bagian 7.

Validasi dan restart **Agent target**:

```bash
sudo /var/ossec/bin/wazuh-agentd -t
sudo /var/ossec/bin/wazuh-logcollector -t
sudo /var/ossec/bin/wazuh-syscheckd -t
sudo systemctl restart wazuh-agent
sudo systemctl is-active wazuh-agent
sudo grep -iE 'stis-soc|logcollector|syscheck' /var/ossec/logs/ossec.log | tail -n 30
```

Jika Agent sudah menjadi anggota grup `stis-soc` hasil fitur CRUD lama, konfigurasi grup itu mungkin masih mengoleksi log/path yang sama. **Periksa konfigurasi aktif di inventaris SOC dan grup di Wazuh**, lalu migrasikan hanya path yang ganda. Jangan menghapus Agent atau grup lain secara otomatis. Setelah memastikan event muncul dari pola lokal baru, admin Wazuh dapat melepas Agent dari grup `stis-soc` lama melalui dashboard Wazuh. Basis data SOC lama tetap tersimpan sebagai arsip, tetapi tidak lagi mengendalikan monitoring.

## 5. Tambah website dan domain Apache

Bagian ini dilakukan pada **server target** setiap menambah situs; tidak ada perubahan pada Manager/SOC. Selesaikan pola direktori dan Agent di bagian 4 lebih dulu. Pastikan DNS dan pfSense/HAProxy mengarah ke server yang benar. Contoh slug `web1`, root `/var/www/web1`, domain `web1.stis.local` berikut hanya membuat direktori/log; **source website tidak disediakan oleh repositori ini**. Deploy konten aplikasi Anda sendiri sebelum mengharapkan halaman utama berstatus HTTP 200.

```bash
sudo apt update
sudo apt install -y apache2
sudo install -d -m 0755 /var/www/web1
sudo touch /var/log/stis-soc/apache/web1.access.log
sudo chmod 0640 /var/log/stis-soc/apache/web1.access.log
```

Pemasangan format log Apache dan `mod_remoteip` dilakukan **sekali per server Apache**. Periksa apakah directive berikut sudah aktif di `apache2.conf`, `conf-enabled`, atau VirtualHost lama. Jika belum, buka `sudo nano /etc/apache2/conf-available/stis-soc-logging.conf` dan isi **hanya directive yang belum ada**:

```apache
LogFormat "%a %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" stis_soc_combined
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 10.10.10.1
```

Aktifkan melalui `sudo a2enmod remoteip` dan, **bila file `stis-soc-logging.conf` dibuat**, `sudo a2enconf stis-soc-logging`. Helper demo `setup_target_lab.sh` versi baru juga memakai file baku ini bila perlu menambahkan directive; salinan helper lama dapat memakai `stis-soc-logformat.conf`/`stis-soc-remoteip.conf`, jadi periksa file aktif dan jangan membuat definisi kedua. **Hanya alamat HAProxy yang tepercaya** boleh dicantumkan di `RemoteIPInternalProxy`; pada lab ini IP klien `192.168.x.x` bersifat privat dan Apache hanya akan menerimanya dari proxy yang dinyatakan *internal*. Tanpa pembatasan proxy, klien dapat memalsukan IP pada header ([dokumentasi Apache mod_remoteip](https://httpd.apache.org/docs/2.4/mod/mod_remoteip.html)). Pada setiap VirtualHost, atur `ServerName` dan satu `CustomLog` sesuai slug:

```apache
<VirtualHost *:80>
    ServerName web1.stis.local
    DocumentRoot /var/www/web1
    CustomLog /var/log/stis-soc/apache/web1.access.log stis_soc_combined
    ErrorLog /var/log/apache2/web1_error.log
</VirtualHost>
```

Untuk website baru, salin pola ini dengan slug/domain/root yang baru. Untuk `web1` yang sudah aktif, edit VirtualHost yang ada; pastikan tepat satu `CustomLog` menuju log STIS SOC. Apache boleh tetap menulis log lama untuk kebutuhan lain, tetapi **jangan biarkan Agent mengirim kedua salinan request yang sama** ke Manager; lihat bagian 9. Jika file log baru dimiliki root, proses utama Apache biasanya menulisnya sebagai root. Periksa log bila hak akses berbeda pada instalasi Anda.

```bash
sudo nano /etc/apache2/sites-available/web1.conf
sudo a2ensite web1.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
curl -I -H 'Host: web1.stis.local' http://127.0.0.1/
sudo tail -n 2 /var/log/stis-soc/apache/web1.access.log
```

Baris access log harus dimulai dengan **IP klien asli**, bukan `10.10.10.1`, ketika request datang lewat HAProxy. Nama domain tidak muncul otomatis pada format `combined`; slug file log mengaitkan alert dengan situs. Bila beberapa domain memakai satu VirtualHost/log, pisahkan log per domain jika perlu atribusi domain yang tepat. Log error Apache sendiri belum dikoleksi oleh pola ini.

## 6. Tambah service/API atau peristiwa keamanan aplikasi

Service yang tidak menggunakan Apache tetap dapat dimonitor. Buat satu berkas JSON Lines per service, misalnya `api-stis.jsonl`. Proses service harus memiliki izin menulis file; Agent yang berjalan sebagai root akan membacanya:

```bash
sudo touch /var/log/stis-soc/apps/api-stis.jsonl
sudo chown SERVICE_USER:SERVICE_GROUP /var/log/stis-soc/apps/api-stis.jsonl
sudo chmod 0640 /var/log/stis-soc/apps/api-stis.jsonl
```

Ganti `SERVICE_USER`/`SERVICE_GROUP` dengan akun nyata milik proses service; jangan jalankan perintah contoh tanpa menggantinya. Setiap baris harus satu objek JSON utuh dan menyertakan `timestamp` serta `event_type`. Pada Wazuh 4.14.7 lab ini, kedua field membuat event melewati parent bawaan `86600` level 0; rule anak STIS seperti `100500`, `100510`, `100300`, atau `100301` kemudian memberi alert spesifik. Parent `86600` saja tidak menjadi bukti deteksi serangan. Kontrak peristiwa yang didukung rule Manager saat ini:

```json
{"timestamp":"2026-10-03T10:00:00Z","event_type":"stis_auth_failed","srcip":"192.0.2.20","dstuser":"test-user","url":"/v1/login","domain":"api.stis.local","asset_name":"api-stis"}
```

`event_type=stis_auth_failed` memicu rule `100500`; lima kegagalan dari `srcip` yang sama dalam 60 detik dapat memicu `100501` level 10. `srcip` harus berupa IP yang diverifikasi oleh reverse proxy/aplikasi, bukan nilai `X-Forwarded-For` mentah dari internet. Tidak semua JSON otomatis menjadi alert: Wazuh membutuhkan rule yang cocok. Untuk autentikasi sukses atau event aplikasi lain tanpa rule, log mungkin terkumpul tetapi tidak muncul pada daftar alert SOC. Kategori SQLi, Shellshock, webshell probe, dan pemindaian pada proyek ini terutama berasal dari **Apache access log** dan rule yang sudah terpasang.

Aplikasi yang **sudah menolak** input mencurigakan juga dapat melaporkan percobaan SQLi dengan kontrak JSON berikut; setelah rule Manager terbaru dipasang, event ini memicu `100510` level 12. Ini pencatatan keputusan aplikasi, bukan pengganti prepared statement atau validasi input:

```json
{"timestamp":"2026-10-03T10:00:00Z","event_type":"stis_sqli_attempt","srcip":"192.0.2.20","dstuser":"test-user","url":"/v1/login","domain":"api.stis.local","asset_name":"api-stis"}
```

Untuk beberapa endpoint dalam service yang sama, gunakan file JSON yang sama dan bedakan `url`. Field `domain` dan `asset_name` membantu panel detail insiden mengidentifikasi target tanpa database CRUD. Sesuaikan rotasi log agar file tetap berbasis baris dan Agent dapat membacanya sesudah rotasi.

## 7. Website Guard, FIM, dan keterbatasan perlindungan file

Wazuh FIM di langkah 4 meminta pemantauan subdirektori `/var/www`, sesuai atribut, kedalaman, dan pengecualian konfigurasi Agent yang aktif. Rule `100304` mengangkat temuan FIM dengan path `/var/www/<nama-situs>/...`; file langsung di root `/var/www` tidak selalu cocok dengan pola rule lokal itu. FIM sendiri tidak membuktikan siapa penyerangnya; jangan auto-block IP hanya berdasarkan perubahan file. Auditd/whodata dan log deployment diperlukan untuk menelusuri pelaku proses.

Website Guard adalah pemindai konten tambahan untuk tanda judol/pinjol dan webshell. Template service terbaru menjalankan `--root /var/www`, sehingga semua situs di bawah direktori itu ikut dipindai. Instalasi STIS lama mungkin masih menjalankan service khusus `/var/www/web1`. Untuk migrasi pada **server target**, periksa isi seluruh `/var/www` terlebih dahulu dan simpan state lama:

Salin tiga file terbaru dari **UbuntuServer** ke akun SSH server target (ganti IP/akun jika jaringan berubah). Pada server baru, selesaikan instalasi awal Guard pada Panduan 01 sebelum membuat baseline:

```bash
scp /media/sf_VM-Share/website_guard/website_guard.py \
  /media/sf_VM-Share/website_guard/website-guard.service \
  /media/sf_VM-Share/website_guard/website-guard.timer \
  vboxuser@10.10.10.30:/tmp/
```

```bash
sudo systemctl stop website-guard.timer website-guard.service
sudo cp -a /var/lib/mini-soc-website-guard \
  "/root/website-guard-state-$(date +%Y%m%d-%H%M%S).bak"
sudo install -m 0750 /tmp/website_guard.py /usr/local/sbin/website_guard.py
sudo install -m 0644 /tmp/website-guard.service /etc/systemd/system/website-guard.service
sudo install -m 0644 /tmp/website-guard.timer /etc/systemd/system/website-guard.timer
```

Periksa `systemctl cat website-guard.service`: `ExecStart` dan `ReadOnlyPaths` harus menunjuk `/var/www`. Baseline lama untuk `/var/www/web1` tidak berlaku pada root baru; buat baseline hanya setelah isi seluruh `/var/www` bersih, lalu aktifkan kembali timer:

```bash
sudo /usr/local/sbin/website_guard.py init --root /var/www
sudo systemctl daemon-reload
sudo systemctl enable --now website-guard.timer
sudo systemctl start website-guard.service
sudo systemctl status website-guard.service --no-pager
```

Jika `init` menemukan konten mencurigakan, investigasi dahulu; jangan memakai `--force` atau `approve` untuk menutupi temuan. Untuk instalasi Guard awal, lihat [bagian terkait pada Panduan 01](PANDUAN_01_INSTALASI_PFSENSE_WAZUH_DAN_STIS_SOC.md#11-mengaktifkan-perlindungan-web-defacement).

```bash
# Contoh pemeriksaan manual setelah root global dan baseline yang sah disiapkan
sudo /usr/local/sbin/website_guard.py check --root /var/www
sudo tail -n 5 /var/log/mini-soc/website_guard.log
sudo systemctl status website-guard.timer --no-pager
```

FIM bisa menampilkan perubahan sah akibat deployment. Baca path, waktu, checksum, akun/proses, dan isi perubahan sebelum menyimpulkan kompromi.

## 8. Pembuktian end-to-end dan diagnosis

1. Di server target, lakukan satu request uji ke website; lihat apakah baris baru muncul di `/var/log/stis-soc/apache/<slug>.access.log` dengan IP klien yang benar. Untuk service, hasilkan satu event aplikasi sesuai kontrak dan periksa berkas JSONL.
2. Di server target, jalankan `sudo /var/ossec/bin/wazuh-agentd -t` dan cek `sudo tail -n 50 /var/ossec/logs/ossec.log` bila sumber log belum terbaca.
3. Di Manager, pastikan Agent aktif: `sudo /var/ossec/bin/agent_control -lc`. Uji **satu baris log** menggunakan `sudo /var/ossec/bin/wazuh-logtest`; perhatikan ID dan level rule pada Phase 3. `wazuh-logtest` tidak mengirim alert ke Indexer.
4. Buat event sungguhan di server target, lalu pada Manager periksa `sudo tail -f /var/ossec/logs/alerts/alerts.json`. Sesudah alert muncul, tekan **Fetch New Alerts** di SOC. Jika Manager punya alert tetapi SOC belum, periksa Filebeat/Indexer dan waktu kejadian.
5. Klik server di **Inventaris Wazuh**. Lihat `Sumber log aktif` dan `Konfigurasi FIM`. Bagian ini dapat kosong bila Agent offline, hak API kurang, atau konfigurasi belum diterapkan. Nama website/domain belum tentu tampil sebagai entri tersendiri; path log per slug adalah bukti konfigurasi, sedangkan request dan alert nyata adalah bukti pengiriman.

Jika data tidak muncul, telusuri berurutan: aplikasi menulis log → Agent membaca path (hindari koleksi ganda) → Manager mendekode dan membuat alert → Indexer menerima → SOC mengambil alert. Untuk auto-block, periksa juga level rule, `srcip`, whitelist/umur alert, dan alias/rule pfSense. Jangan menguji pemblokiran dari IP admin/pfSense yang masuk whitelist.

## 9. Migrasi dari konfigurasi web1 lama

Situs `web1` yang telah dikonfigurasi langsung di `/var/log/apache2/web1_access.log` dan `/var/www/web1/logs/login_attempt.log` tetap bisa berjalan. Untuk memakai pola global: buat log baru, ubah `CustomLog` menjadi `/var/log/stis-soc/apache/web1.access.log`, dan arahkan aplikasi ke `/var/log/stis-soc/apps/web1.jsonl` **hanya jika aplikasi sudah mampu mengeluarkan JSON sesuai kontrak**. Jangan sekadar mengganti nama `login_attempt.log` teks lama menjadi `.jsonl`: decoder/rule lama memakai format berbeda. Jika aplikasi belum siap JSON, pertahankan koleksi log login lama satu kali di Agent, sementara situs baru memakai pola baku.

Sebelum menghapus entri lama dari `ossec.conf` atau melepas grup Wazuh lama, buktikan dulu event dari jalur baru muncul di `alerts.json`. Setelah itu nonaktifkan hanya sumber duplikat. Untuk lab sekarang gunakan `scripts/maintenance/normalize_wazuh_sources.py` seperti di bawah; mode awal hanya membaca. Skrip membuat backup, menjalankan validasi, dan memulihkan konfigurasi bila restart gagal. Ia menghapus entri identik berulang dan kolektor `<slug>_access.log` lama hanya bila VirtualHost aktif sudah menunjuk log baku `<slug>.access.log`. Ia **tidak** menghapus `/var/log/apache2/access.log`, log login aplikasi lama, atau FIM khusus `web1` secara otomatis karena penggunaan/atributnya belum bisa disimpulkan dari nama file saja.

Dari **UbuntuServer**, salin skrip terbaru ke target:

```bash
scp /media/sf_VM-Share/scripts/maintenance/normalize_wazuh_sources.py \
  vboxuser@10.10.10.30:/tmp/
```

```bash
# Jalankan di target STIS setelah source terbaru disalin ke /tmp.
sudo python3 /tmp/normalize_wazuh_sources.py --role agent
sudo python3 /tmp/normalize_wazuh_sources.py --role agent --apply

# Jalankan di UbuntuServer untuk menghapus kolektor Apache lokal Manager
# hanya jika file lognya memang tidak ada di UbuntuServer.
sudo python3 /media/sf_VM-Share/scripts/maintenance/normalize_wazuh_sources.py --role manager
sudo python3 /media/sf_VM-Share/scripts/maintenance/normalize_wazuh_sources.py --role manager --apply
```

Periksa `/var/log/apache2/access.log` di target secara manual: bila masih menampung request situs yang belum punya log baku, migrasikan situs itu dahulu. Setelah semua situs memakai log baku dan alert darinya terbukti, hapus blok `<localfile>` untuk `access.log` lama dari Agent, validasi dengan `wazuh-logcollector -t`, lalu restart Agent. Bila file `login_attempt.log` masih ditulis aplikasi, tetap koleksi sampai event login setara benar-benar muncul dari JSONL; menghapusnya lebih awal dapat memutus deteksi brute force. Dua direktori FIM `/var/www` dan `/var/www/web1` juga perlu keputusan terpisah karena blok khusus `web1` memakai `whodata` dan `report_changes`; jangan kehilangan atribut itu tanpa sengaja.

Periksa konfigurasi grup Agent pada Manager (`/var/ossec/etc/shared/*/agent.conf`) sebelum menganggap duplikasi selesai; konfigurasi terpusat dapat menambah kolektor yang sama. Database `MonitoredAsset`/`MonitoredServer` SOC lama tidak dihapus oleh pembaruan ini, namun tidak lagi menjadi sumber konfigurasi Agent.

## 10. Telemetri host Linux untuk PoC

Bagian ini berlaku untuk Agent Ubuntu/Debian. Tidak ada syarat memasang Windows, RDP, atau Docker pada target; bila service tersebut kelak benar-benar dijalankan, buat sumber log dan uji tersendiri sesuai layanan yang aktif.

Untuk server Ubuntu yang juga ingin memantau eksekusi utilitas mencurigakan dan proses yang masih berjalan, salin `scripts/testing/prepare_linux_host_detection.sh` dari source SOC ke server target, lalu jalankan **pada target**:

```bash
sudo bash /tmp/prepare_linux_host_detection.sh
sudo auditctl -l | grep audit-wazuh-c
sudo auditctl -s | grep enabled
sudo /var/ossec/bin/wazuh-logcollector -t
sudo systemctl is-active auditd wazuh-agent
```

Skrip membuat backup `ossec.conf`, memasang Auditd bila belum ada, merekam `execve` dari sesi akun manusia (`auid >= 1000`), mengatur kernel auditing aktif (`auditctl -s` menunjukkan `enabled 1`), mengoleksi `/var/log/audit/audit.log` dengan format `audit` (termasuk memperbaiki blok lama yang memakai `syslog`), dan meminta Wazuh memeriksa `ps -eo pid=,comm=` tiap 120 detik. Ini menambah volume log Auditd; periksa kapasitas dan sesuaikan kebijakan pada host ramai. Perintah yang dijalankan langsung dari sesi `root` dengan `auid=0` tidak termasuk; uji dari sesi SSH `vboxuser`/akun manusia. Rule `100610` melaporkan eksekusi `nc`, `ncat`, atau `socat`, sedangkan `100611` dapat melaporkan proses yang masih berjalan saat pemindaian. Temuan ini tidak membawa IP penyerang yang dapat dipercaya untuk blokir pfSense.

Rootcheck dan Syscollector bawaan Wazuh tetap diperlukan untuk anomali rootkit dan inventaris kerentanan. Periksa blok `<rootcheck>` dan `<wodle name="syscollector">` dalam `ossec.conf` target; keduanya jangan `disabled=yes`. Di Manager, periksa `<vulnerability-detection><enabled>yes</enabled>` dan koneksi Indexer. Langkah pembuktian masing-masing, termasuk opsi VirusTotal dengan API key milik operator, ada di [Panduan 05](PANDUAN_05_UJI_FUNGSIONAL_TARGET_NYATA_DAN_DEMO.md#10-poc-host-linux-tambahan-tanpa-windows-atau-docker).

## 11. Batas konfigurasi umum dan inventaris

Pola direktori umum menghindari edit daftar website pada SOC/Manager setiap kali situs ditambah **selama format peristiwanya sudah didukung rule**. Jenis log atau protokol baru tetap dapat memerlukan decoder/rule baru. Restart Agent dan periksa logcollector bila file baru belum dikenali; jangan hanya memeriksa bahwa direktorinya ada.

Field `domain`/nama layanan pada detail insiden berasal dari JSON aplikasi atau arsip metadata lama. Access log combined tidak menyimpan seluruh daftar domain. Nama file seperti `web1.access.log` memberi slug situs, bukan bukti domain tersebut telah ditemukan otomatis.

Inventaris mengambil maksimal 1.000 Agent dan 500 item per bagian paket/service/port per panggilan. Bagian yang tidak didukung API/izin dapat menghasilkan pesan error tanpa menghilangkan bagian lainnya. Inventaris bukan pemindai ketersediaan aktif atau installer service.

Untuk perintah/proses Linux, kategori yang tidak layak auto-block dihentikan pada `review_only` bila level memenuhi ambang; level 8 biasanya `below_threshold` pada ambang 10. Jangan mengharapkan `no_source_ip` untuk semua alert tanpa IP karena urutan penyaring berbeda menurut kategori.
