# Panduan 01: Instalasi pfSense, Wazuh, dan STIS SOC

**Hasil yang ingin dicapai:** dashboard dapat dibuka dari Windows, koneksi Wazuh dan pfSense dapat diperiksa, dan target siap mengirim kejadian. Memasang aplikasi SOC saja belum memasang seluruh sistem keamanan. Untuk penjelasan program dan bahan skripsi, baca [STIS_SOC.md](../STIS_SOC.md).

**Istilah singkat:** Agent adalah pengumpul data di target; Manager mengolah data menjadi alert; Indexer menyimpan alert; alias adalah daftar IP yang dipakai rule firewall; polling adalah pengambilan data berkala. Konfigurasi di bawah dibuat pada VM yang disebutkan, bukan pada folder Windows.


Dokumen ini menyiapkan pfSense/HAProxy, Wazuh Manager/Indexer/Dashboard, STIS SOC, serta Website Guard dari awal hingga siap menerima data target. Penambahan Agent/website/service ada di [Panduan 02](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md); uji target nyata dan demo ada di [Panduan 05](PANDUAN_05_UJI_FUNGSIONAL_TARGET_NYATA_DAN_DEMO.md).

Panduan memakai topologi lab yang sudah digunakan selama pengembangan. Ganti alamat IP hanya jika topologi Anda berbeda dan lakukan perubahan secara konsisten.

**Asal file:** repositori ini berisi kode SOC, `website_guard/`, `examples/lab_probe.php`, rule/decoder, serta skrip `scripts/testing/` dan `scripts/maintenance/`. Repositori **tidak** berisi source website STIS (`/var/www/web1`), `process_login.php`, atau `/etc/apache2/sites-available/web1.conf`; ketiganya milik server target dan harus diperiksa di sana. `backend/venv`, `frontend/node_modules`, `/root/backend/instance/soc.db`, file Wazuh di `/var/ossec`, dan salinan `/tmp` dibuat pada tahap instalasi/salin file; jangan menganggapnya sudah ada sebelum tahap tersebut selesai.

## Daftar isi

1. [Ruang lingkup dan aturan membaca](#1-ruang-lingkup-dan-aturan-membaca)
2. [Topologi akhir](#2-topologi-akhir)
3. [Menyiapkan VM dan jaringan](#3-menyiapkan-vm-dan-jaringan)
4. [Memasang Wazuh all-in-one](#4-memasang-wazuh-all-in-one)
5. [Menyiapkan server web dan Wazuh Agent](#5-menyiapkan-server-web-dan-wazuh-agent) (panduan terpisah)
6. [Mempertahankan IP klien melalui HAProxy](#6-mempertahankan-ip-klien-melalui-haproxy)
7. [Memasang decoder dan rule Wazuh](#7-memasang-decoder-dan-rule-wazuh)
8. [Menyiapkan REST API dan firewall pfSense](#8-menyiapkan-rest-api-dan-firewall-pfsense)
9. [Memasang STIS SOC di UbuntuServer](#9-memasang-stis-soc-di-ubuntuserver)
10. [Mengisi Settings dan memeriksa integrasi](#10-mengisi-settings-dan-memeriksa-integrasi)
11. [Mengaktifkan perlindungan web defacement](#11-mengaktifkan-perlindungan-web-defacement)
12. [Gerbang sebelum pengujian](#12-gerbang-sebelum-pengujian)
13. [Operasional dashboard](#13-operasional-dashboard)
14. [Update kode tanpa instalasi ulang](#14-update-kode-tanpa-instalasi-ulang)
15. [Backup, pemulihan, dan respons insiden](#15-backup-pemulihan-dan-respons-insiden)
16. [Troubleshooting](#16-troubleshooting)
17. [Validasi kode untuk pengembang](#17-validasi-kode-untuk-pengembang)
18. [Onboarding server dan target monitoring](#18-onboarding-server-dan-target-monitoring)
19. [Matriks deteksi dan kebijakan respons](#19-matriks-deteksi-dan-kebijakan-respons)
20. [Rujukan pengujian dan uninstall](#20-rujukan-pengujian-dan-uninstall)

## 1. Ruang lingkup dan aturan membaca

Ada empat VM serta Windows Host dengan tugas berbeda. Selalu perhatikan label sebelum menjalankan perintah:

- **Windows Host**: tempat source code, VirtualBox, dan browser analis.
- **UbuntuServer**: Wazuh Manager, Indexer, Dashboard, dan STIS SOC.
- **Server STIS**: Apache/PHP dan Wazuh Agent.
- **pfSense**: router, HAProxy, REST API, alias, dan rule firewall.
- **Kali**: klien luar untuk pengujian yang diizinkan.

Jangan menjalankan perintah Wazuh Manager pada Server STIS. Server STIS hanya memiliki Wazuh Agent. Jangan menyalin `venv` atau `node_modules` dari Windows ke Ubuntu karena keduanya berisi dependensi yang khusus untuk sistem operasi asal.

Pengujian serangan dalam dokumen ini hanya untuk lab milik sendiri. Gunakan snapshot VM sebelum mengubah konfigurasi besar.

## 2. Topologi akhir

| Mesin | Adapter/alamat | Fungsi |
| --- | --- | --- |
| pfSense | WAN DHCP `x.x.x.x` | Menerima trafik Kali |
| pfSense | LAN `10.10.10.1/24` | Gateway internal dan endpoint REST API dari SOC |
| pfSense | OPT1 `192.168.1.20/24` | WebGUI dari Windows Host |
| UbuntuServer | LAN `10.10.10.20/24` | Wazuh dan STIS SOC |
| UbuntuServer | host-only `192.168.1.10/24` | Dashboard STIS SOC dari Windows |
| Server STIS | LAN `10.10.10.30/24` | Backend HAProxy, Apache, Wazuh Agent |
| Server STIS | host-only `192.168.1.30/24` | Administrasi SSH dari Windows |
| Kali | WAN `x.x.x.x` | Klien uji di sisi luar pfSense |

Alur web:

```text
Kali → WAN pfSense → HAProxy → LAN pfSense → Apache STIS
     → Wazuh Agent → Manager → Indexer → STIS SOC
     → REST API pfSense → SOC_Blocklist → Block WAN
```

STIS SOC memakai `https://10.10.10.1` untuk API pfSense karena alamat LAN ini tetap walaupun WAN mendapat alamat baru dari DHCP. Interface API tidak menentukan lokasi rule; pemblokiran tetap bekerja pada rule WAN.

## 3. Menyiapkan VM dan jaringan

### 3.1 Spesifikasi yang disarankan

| VM | vCPU | RAM | Disk | OS |
| --- | ---: | ---: | ---: | --- |
| pfSense | 2 | 2 GB | 16 GB | pfSense CE sesuai paket REST API |
| UbuntuServer | 4 | 8 GB | 50 GB | Ubuntu Server 22.04/24.04 64-bit |
| Server STIS | 2 | 4 GB | 30 GB | Ubuntu Server 22.04 |
| Kali | 2 | 4 GB | 30 GB | Kali Linux |

UbuntuServer membutuhkan RAM terbesar karena menjalankan Wazuh Indexer.

### 3.2 Adapter VirtualBox

Saat VM mati, atur:

**pfSense**

1. Adapter 1: Bridged Adapter sebagai WAN.
2. Adapter 2: Internal Network sebagai LAN.
3. Adapter 3: Host-only Adapter sebagai OPT1.

**UbuntuServer dan Server STIS**

1. Adapter 1: Internal Network yang sama dengan LAN pfSense.
2. Adapter 2: Host-only Adapter.
3. Adapter 3: NAT untuk instalasi paket.

**Kali**

Gunakan Bridged Adapter/jaringan yang sama dengan WAN pfSense. Kali tidak boleh menyerang langsung ke `10.10.10.30`, karena trafik seperti itu tidak melewati rule WAN.

### 3.3 IP pfSense

Melalui console assignment pfSense, tetapkan:

```text
LAN  : 10.10.10.1/24
OPT1 : 192.168.1.20/24
WAN  : DHCP
```

Di WebGUI, buat rule OPT1 yang mengizinkan subnet OPT1 mengakses `This Firewall` pada HTTPS agar Windows dapat membuka WebGUI. Jangan memakai `pfctl -d` untuk pengujian rutin karena perintah itu mematikan seluruh filtering.

### 3.4 IP UbuntuServer

Periksa nama interface terlebih dahulu:

```bash
ip -br link
```

Edit file Netplan yang sudah ada:

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Contoh berikut mengasumsikan `enp0s3` internal, `enp0s8` host-only, dan `enp0s9` NAT:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [10.10.10.20/24]
    enp0s8:
      dhcp4: false
      addresses: [192.168.1.10/24]
    enp0s9:
      dhcp4: true
```

Terapkan dan periksa:

```bash
sudo netplan try
sudo netplan apply
ip -br address
ping -c 3 10.10.10.1
```

Gunakan `netplan try` dari console VM agar konfigurasi otomatis dibatalkan jika SSH terputus.

### 3.5 IP Server STIS

Gunakan pola yang sama dengan alamat berikut:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: false
      addresses: [10.10.10.30/24]
    enp0s8:
      dhcp4: false
      addresses: [192.168.1.30/24]
    enp0s9:
      dhcp4: true
```

Kemudian:

```bash
sudo netplan try
sudo netplan apply
ping -c 3 10.10.10.20
```

### 3.6 Shared folder source code

Di VirtualBox → **Settings → Shared Folders**, tambahkan folder project Windows:

```text
Folder Name : VM-Share
Auto-mount  : aktif
Read-only   : boleh aktif jika Ubuntu hanya menarik update
```

Pada UbuntuServer:

```bash
sudo apt update
sudo apt install -y virtualbox-guest-utils rsync
sudo usermod -aG vboxsf "$USER"
```

Logout/login atau reboot, lalu periksa:

```bash
ls /media/sf_VM-Share
```

Jika auto-mount tidak tersedia:

```bash
sudo mkdir -p /mnt/shared
sudo mount -t vboxsf -o uid="$(id -u)",gid="$(id -g)" VM-Share /mnt/shared
ls /mnt/shared
```

Folder yang benar memuat `backend`, `frontend`, `website_guard`, dan `setup_ubuntu.sh`.

## 4. Memasang Wazuh all-in-one

Bagian ini dijalankan pada **UbuntuServer**. Contoh mengikuti jalur Wazuh 4.14 yang dipakai pada pengembangan lab; catat versi terpasang dan gunakan versi komponen yang selaras. Pemeriksaan source tidak menggantikan verifikasi instalasi VM.

```bash
cd /root
sudo apt update
sudo apt install -y curl unzip wget gnupg apt-transport-https
curl -fsSLO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
dpkg-query -W -f='${Version}\n' wazuh-manager
```

Catat versi Manager yang benar-benar terpasang untuk memilih paket Agent di Panduan 02; URL `4.14` dapat mengambil patch yang lebih baru dari lab contoh 4.14.7. Simpan output password installer secara aman. Jangan menaruhnya di source code atau dokumentasi. Periksa service dan port:

```bash
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo ss -lntp | grep -E ':(1514|1515|55000|9200)\b'
```

Jika UFW aktif, buka port Agent hanya dari Server STIS:

```bash
sudo ufw allow from 10.10.10.30 to any port 1514 proto tcp
sudo ufw allow from 10.10.10.30 to any port 1515 proto tcp
```

### 4.1 Mengenali dua jenis akun Wazuh

STIS SOC membutuhkan dua akun berbeda:

| Koneksi | Username umum | Port |
| --- | --- | --- |
| Manager API | `wazuh` atau `wazuh-wui` | `55000` |
| Indexer/OpenSearch | `admin` | `9200` |

Password `admin` Indexer bukan password user `wazuh` Manager API.

Jika arsip hasil installer tersedia:

```bash
sudo find /root -maxdepth 2 -name wazuh-install-files.tar -print
if sudo test -f /root/wazuh-install-files.tar; then
  sudo tar -axf /root/wazuh-install-files.tar \
    wazuh-install-files/wazuh-passwords.txt -O
else
  echo 'Arsip installer tidak ada di /root; periksa lokasi hasil find atau gunakan akun API yang sudah aktif.'
fi
```

Perintah `tar` menampilkan **semua secret instalasi**; jalankan hanya di terminal pribadi dan jangan menyalin hasilnya ke laporan, tangkapan layar, atau chat. Jika `find` menunjukkan arsip di lokasi lain, ganti path setelah memeriksa file tersebut.

Tes tanpa mencetak password:

```bash
read -rsp "Password API user wazuh: " WAZUH_API_PASSWORD; echo
curl -sk -o /dev/null -w 'Manager API HTTP %{http_code}\n' \
  -u "wazuh:${WAZUH_API_PASSWORD}" -X POST \
  'https://127.0.0.1:55000/security/user/authenticate?raw=true'
unset WAZUH_API_PASSWORD

read -rsp "Password Indexer admin: " WAZUH_INDEXER_PASSWORD; echo
curl -sk -o /dev/null -w 'Indexer HTTP %{http_code}\n' \
  -u "admin:${WAZUH_INDEXER_PASSWORD}" 'https://127.0.0.1:9200/'
unset WAZUH_INDEXER_PASSWORD
```

Keduanya harus menghasilkan HTTP `200`. Jika arsip installer hilang, API tidak perlu dipasang ulang. Kredensial `wazuh-wui` yang aktif dapat diperiksa secara lokal:

```bash
sudo sed -n '/^[[:space:]]*username:[[:space:]]*wazuh-wui/,+1p' \
  /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
```

Tes username `wazuh-wui` pada port 55000. Jika HTTP `200`, username dan password tersebut dapat dipakai sebagai Manager API di STIS SOC. Jangan menjalankan `--change-all` hanya untuk memperbaiki satu HTTP 401 karena perintah itu mengubah banyak akun Indexer dan komponen internal sekaligus.

## 5. Menyiapkan server web dan Wazuh Agent

Ikuti [Panduan Agent dan Target Monitoring](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md) untuk memasang Agent pada server target dan menambahkan website, domain, endpoint, atau service dengan pola log/FIM yang sama. Lakukan konfigurasi Agent satu kali per host; target berikutnya cukup memakai direktori dan format log baku pada panduan tersebut.
## 6. Mempertahankan IP klien melalui HAProxy

HAProxy membuat koneksi baru ke Apache, sehingga tanpa konfigurasi tambahan Apache melihat `10.10.10.1`. XFF membawa identitas klien pada lapisan HTTP; sumber paket TCP ke Apache tetap pfSense.

### 6.1 pfSense HAProxy

Pada **Services → HAProxy → Frontend**, pastikan frontend bekerja dalam mode HTTP atau SSL offloading. Di **Advanced pass thru**, gunakan:

```haproxy
http-request set-header X-Forwarded-For %[src]
```

Baris ini mengganti header yang dikirim klien sehingga nilai palsu tidak dipercaya. Jangan mengaktifkannya bersamaan dengan checkbox `forwardfor`.

Jika memakai TLS passthrough/mode TCP, HAProxy tidak dapat mengubah header HTTP. Rancangan tersebut membutuhkan PROXY protocol dan tidak menggunakan langkah XFF ini.

### 6.2 Apache mod_remoteip

Pada Server STIS, gunakan pola global dalam [panduan Agent](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md#5-tambah-website-dan-domain-apache). Untuk `web1`, simpan cadangan VirtualHost sebelum mengubahnya:

```bash
test -f /etc/apache2/sites-available/web1.conf
sudo cp -a /etc/apache2/sites-available/web1.conf \
  "/etc/apache2/sites-available/web1.conf.$(date +%Y%m%d-%H%M%S).bak"
sudo a2enmod remoteip
sudo nano /etc/apache2/sites-available/web1.conf
```

Di dalam `<VirtualHost *:80>`, gunakan:

```apache
CustomLog /var/log/stis-soc/apache/web1.access.log stis_soc_combined
```

`RemoteIPHeader`, `RemoteIPInternalProxy`, dan `LogFormat` harus aktif satu kali di Apache; file `stis-soc-logging.conf` adalah lokasi baku untuk instalasi baru. Pada web1 lama, sebagian directive mungkin sudah ada di konfigurasi lain. Periksa konfigurasi aktif sebelum menambahkannya agar tidak duplikat. Gunakan `RemoteIPInternalProxy` karena IP klien lab berada di rentang privat; percayai hanya alamat HAProxy, bukan seluruh subnet. Jangan membaca `$_SERVER['HTTP_X_FORWARDED_FOR']` langsung dari PHP.

```bash
sudo apache2ctl configtest
sudo systemctl reload apache2
sudo apache2ctl -M | grep remoteip
```

Dari Kali:

```bash
curl -v -H 'Host: web1.stis.local' 'http://<IP_WAN_PFSENSE>/'
curl -v -H 'Host: web1.stis.local' \
  -H 'X-Forwarded-For: 203.0.113.99' \
  'http://<IP_WAN_PFSENSE>/'
```

Pada Server STIS, kedua request harus tercatat sebagai IP Kali, bukan `10.10.10.1` atau `203.0.113.99`:

```bash
sudo tail -n 10 /var/log/stis-soc/apache/web1.access.log
```

## 7. Memasang decoder dan rule Wazuh

Topologi pada panduan ini memakai Ubuntu Server sebagai Manager/SOC dan Ubuntu STIS sebagai target. Ubuntu tidak memerlukan RDP untuk menjalankan Wazuh; konfigurasi RDP baru relevan bila host sengaja menyediakan layanan seperti `xrdp`. Docker juga tidak dipasang hanya demi meniru PoC ketika target tidak menjalankan container.

Jalankan pada **UbuntuServer/Wazuh Manager** setelah source tersedia melalui VM-Share. Backup dahulu:

```bash
BACKUP_TAG="$(date +%Y%m%d-%H%M%S)"
test -f '/media/sf_VM-Share/config/wazuh/decoders/local_decoder.xml'
test -f '/media/sf_VM-Share/config/wazuh/rules/local_rules.xml'
sudo cp -a /var/ossec/etc/ossec.conf "/var/ossec/etc/ossec.conf.${BACKUP_TAG}.bak"
for name in stis-known-bad stis-suspicious-programs; do
  if ! sudo test -f "/var/ossec/etc/lists/$name"; then
    sudo install -o root -g wazuh -m 0640 "/media/sf_VM-Share/lists/$name" "/var/ossec/etc/lists/$name"
  fi
done
if sudo test -f /var/ossec/etc/decoders/local_decoder.xml; then
  sudo cp -a /var/ossec/etc/decoders/local_decoder.xml \
    "/var/ossec/etc/decoders/local_decoder.xml.${BACKUP_TAG}.bak"
fi
if sudo test -f /var/ossec/etc/rules/local_rules.xml; then
  sudo cp -a /var/ossec/etc/rules/local_rules.xml \
    "/var/ossec/etc/rules/local_rules.xml.${BACKUP_TAG}.bak"
fi

sudo cp "/media/sf_VM-Share/config/wazuh/decoders/local_decoder.xml" \
  /var/ossec/etc/decoders/local_decoder.xml
sudo cp "/media/sf_VM-Share/config/wazuh/rules/local_rules.xml" \
  /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh \
  /var/ossec/etc/decoders/local_decoder.xml \
  /var/ossec/etc/rules/local_rules.xml
sudo chmod 0640 \
  /var/ossec/etc/decoders/local_decoder.xml \
  /var/ossec/etc/rules/local_rules.xml
```

Sebelum validasi, buka `sudo nano /var/ossec/etc/ossec.conf` dan tambahkan **sekali** di dalam blok `<ruleset>` yang sudah ada:

```xml
<list>etc/lists/stis-known-bad</list>
<list>etc/lists/stis-suspicious-programs</list>
```

Daftar IP bawaan hanya memakai alamat dokumentasi `198.51.100.99`; daftar aktual dikelola operator pada Manager. Jangan memasukkan IP HAProxy, admin, atau jaringan tepercaya. Pada pembaruan berikutnya, `prepare_manager.sh` mempertahankan isi daftar yang telah diedit.

Jangan restart sebelum tes berhasil:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Rule yang dipasang:

| Rule | Level | Fungsi |
| --- | ---: | --- |
| `100001` | 5 | Satu kegagalan SSH |
| `100002` | 10 | Lima kegagalan SSH dalam 60 detik |
| `100101` | 5 | Satu login web gagal |
| `100102` | 10 | Lima login web gagal dalam 60 detik |
| `100103` | 3 | Login web berhasil |
| `100200` | 12 | SQL Injection pada form login |
| `100201` | 12 | SQL Injection pada URL/access log |
| `100202` | 12 | SQL Injection dengan encoding yang ditangkap rule `31164`/`31165` |
| `100300` | 12 | Konten judol/pinjol ditemukan |
| `100301` | 10 | File web ditambah/diubah |
| `100302` | 12 | File web dihapus/symlink muncul |
| `100304` | 10 | Perubahan web dari FIM Wazuh |
| `100305` | 14 | Isi file menyerupai webshell PHP terobfuskasi |
| `100400`/`100401` | 7/10 | Probe webshell tunggal/berulang |
| `100410`/`100411` | 6/10 | Probe endpoint WordPress tunggal/berulang |
| `100420`/`100421` | 5/10 | Scanner User-Agent tunggal/berulang |
| `100430` | 12 | Akses file konfigurasi sensitif |
| `100440` | 12 | Probe endpoint RCE/PHPUnit/CGI |
| `100450`/`100451` | 6/10 | Enumerasi service tunggal/berulang |
| `100460` | 12 | Path traversal/LFI |
| `100468`/`100469` | 6 | Probe XSS dari rule Wazuh `31105` atau respons HTTP 200 `31106` yang URL-nya tetap cocok pola XSS |
| `100470` | 10 | Lima probe XSS dari IP yang sama dalam 60 detik, baik respons 200 maupun 404 |
| `100480` | 8 | Indikator SSRF pada URL, investigasi manual |
| `100481` | 10 | Lima event log dengan indikator URL SSRF dari IP sama dalam 3600 detik; kandidat auto-block, bukan bukti fetch server |
| `100490` | 12 | Payload Shellshock pada respons 4xx/5xx |
| `100500`/`100501` | 5/10 | Login service JSON gagal/berulang |
| `100510` | 12 | SQLi yang dilaporkan aplikasi JSON |
| `100600` | 12 | Request dari IP dalam daftar reputasi operator |
| `100610` | 10 | Program mencurigakan dieksekusi dan dicatat Auditd |
| `100611` | 8 | Program jaringan mencurigakan tampak pada pemindaian proses |

Tes parser secara interaktif:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Masukkan satu per satu:

```text
[2026-09-30 10:20:30] FAILED LOGIN USER=admin IP=192.168.18.103
[2026-09-30 10:20:31] SQLI ATTEMPT USER=admin_OR_1=1 IP=192.168.18.103
```

Hasil pertama harus menuju `100101`; hasil kedua menuju `100200` level 12. `wazuh-logtest` menguji decoder/rule tetapi tidak menulis alert produksi ke Indexer dan tidak memicu auto-block.

## 8. Menyiapkan REST API dan firewall pfSense

### 8.1 Paket REST API

Pada console/SSH pfSense:

```sh
cat /etc/version
pkg info | grep -i RESTAPI
```

REST API di sini adalah [paket komunitas pfREST](https://github.com/pfrest/pfSense-pkg-RESTAPI), bukan komponen bawaan pfSense. Cocokkan versi paket dengan versi pfSense yang ditampilkan `cat /etc/version`; contoh berikut hanya untuk CE 2.8.1:

```sh
pkg-static add https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-2.8.1-pkg-RESTAPI.pkg
```

Jangan memasang paket 2.8.1 pada pfSense versi lain.

Di WebGUI → **System → REST API → Settings**, aktifkan API Key authentication. Buat user khusus SOC dan API key pada **System → REST API → Keys**. Key perlu privilege untuk:

- membaca system version;
- membaca, membuat, dan mengubah firewall alias;
- membaca firewall rules;
- apply konfigurasi firewall;
- menghapus firewall states jika fitur pembersihan state aktif.

Jika nilai key lama tidak dapat dilihat, revoke key tersebut dan buat key baru.

### 8.2 Alias dan rule

Di **Firewall → Aliases → IP**, buat:

```text
Name : SOC_Blocklist
Type : Host(s)
```

Jika GUI mewajibkan satu alamat awal, gunakan `198.51.100.1` sementara dan hapus setelah pengujian.

Di **Firewall → Rules → WAN**, buat rule:

```text
Action      : Block
Address     : IPv4
Protocol    : Any
Source      : SOC_Blocklist
Destination : Any
Description : SOC Auto-Blocklist
```

Letakkan rule di atas rule Pass yang mengarahkan trafik ke HAProxy, lalu **Save** dan **Apply Changes**. Alias saja tidak memblokir trafik tanpa rule ini.

Tes API dari UbuntuServer:

```bash
read -rsp "pfSense API key: " PFSENSE_API_KEY; echo
curl -sk -H "X-API-Key: ${PFSENSE_API_KEY}" \
  'https://10.10.10.1/api/v2/system/version' | python3 -m json.tool
curl -sk -H "X-API-Key: ${PFSENSE_API_KEY}" \
  'https://10.10.10.1/api/v2/firewall/aliases' | python3 -m json.tool
unset PFSENSE_API_KEY
```

Respons harus memiliki code/status `200`.

## 9. Memasang STIS SOC di UbuntuServer

### 9.1 Salin source pertama kali

Panduan ini mempertahankan layout lab saat ini: file proyek berada langsung di `/root`, sehingga terdapat `/root/backend`, `/root/frontend`, dan `/root/start_soc.sh`.

```bash
sudo apt install -y rsync
sudo rsync -rcv \
  --exclude='.git/' \
  --exclude='venv/' \
  --exclude='.venv/' \
  --exclude='node_modules/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='instance/' \
  --exclude='*.db*' \
  --exclude='*.sqlite*' \
  --exclude='.env' \
  --include='.env.example' \
  --exclude='.env.*' \
  --exclude='*.log' \
  --exclude='*.pid' \
  --exclude='dist/' \
  /media/sf_VM-Share/ /root/
```

Jika share dipasang di `/mnt/shared`, ganti path sumber. Pastikan:

```bash
ls /root/backend/app /root/frontend/src /root/setup_ubuntu.sh
```

### 9.2 Instal dependensi dan database

```bash
cd /root
chmod +x setup_ubuntu.sh start_soc.sh stop_soc.sh update_from_vm_share.sh
bash setup_ubuntu.sh
```

Skrip memasang Python dan, bila Node.js belum ada atau versinya tidak cocok dengan lockfile frontend, memasang Node.js 22. Node.js 20 dan 22 ke atas yang sudah terpasang tetap dipakai agar pembaruan SOC tidak mengganti runtime yang bekerja. Skrip kemudian membuat virtual environment, memasang paket Python/npm dari lockfile, dan membuat tabel SQLite serta akun awal. `init_db.py` bersifat idempotent: ia membuat tabel/akun yang belum ada dan tidak membersihkan data yang sudah tersimpan.

Buat secret aplikasi:

```bash
openssl rand -hex 32
sudo nano /root/backend/.env
sudo chmod 0600 /root/backend/.env
```

Isi dengan nilai acak yang baru dihasilkan:

```env
FLASK_CONFIG=development
SECRET_KEY=GANTI_DENGAN_NILAI_ACAK
LOG_LEVEL=INFO
```

### 9.3 Jalankan aplikasi

```bash
cd /root
bash start_soc.sh
```

Periksa:

```bash
curl -I http://127.0.0.1:5173
curl -s http://127.0.0.1:5000/api/docs | head
tail -n 50 /root/backend.log
tail -n 50 /root/frontend.log
```

Buka dari Windows:

```text
http://192.168.1.10:5173
```

Akun awal:

```text
Username: admin
Password: admin123
```

Untuk debugging foreground:

```bash
# Terminal 1
cd /root/backend
source venv/bin/activate
python run.py

# Terminal 2
cd /root/frontend
npm run dev
```

Jangan menjalankan foreground dan `start_soc.sh` bersamaan karena dua backend dapat membuat dua scheduler.

Mode prototipe memakai Flask `development` dan Vite pada port tetap `5173`. Reloader dan debugger interaktif Flask dinonaktifkan agar scheduler tidak berjalan ganda. `start_soc.sh` dapat mengenali proses lama milik instalasi `/root` walaupun file PID hilang; `stop_soc.sh` menghentikan proses yang direktori kerja dan perintahnya cocok dengan instalasi ini. Proses milik aplikasi lain pada port yang sama tidak dihentikan.

Setelah UbuntuServer reboot, masuk lewat SSH lalu jalankan `cd /root && bash start_soc.sh`. File PID dari sesi sebelum reboot dibersihkan saat start. Skrip ini belum memasang layanan autostart systemd, jadi aplikasi tidak otomatis hidup sesudah reboot.

Setelah pembaruan source dari Windows, jalankan `bash /media/sf_VM-Share/update_from_vm_share.sh /root` di UbuntuServer. Skrip itu menyalin source, menghentikan instance lama, lalu menjalankan ulang backend dan frontend. Untuk pemeriksaan manual sesudahnya:

```bash
ss -lntp | grep -E ':(5000|5173)\b'
curl -I http://127.0.0.1:5000/api/docs
curl -I http://127.0.0.1:5173/
tail -n 20 /root/backend.log /root/frontend.log
```

Jika `start_soc.sh` tetap melaporkan port dipakai proses lain, periksa `ss -lntp '( sport = :5173 )'`, `readlink -f /proc/PID/cwd`, dan `tr '\0' ' ' </proc/PID/cmdline` (ganti `PID` dari output `ss`). Jangan menghentikan PID sebelum memastikan pemiliknya.

### 9.4 Preview lokal di Windows

Preview UI dapat dijalankan tanpa Wazuh/pfSense memakai CSV sintetis publik. `seed_demo_data.py` selalu mengisi `backend/instance/demo.db`, terpisah dari database operasional dan tanpa scheduler. Pengisian ulang memerlukan `--reset`; opsi ini hanya mengganti data demo. Jangan isi kredensial integrasi nyata pada demo. Buka PowerShell pada root project:

```powershell
cd backend
py -3.13 -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python seed_demo_data.py
python run.py --demo
```

Buka PowerShell kedua:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

Untuk preview yang benar-benar berjalan di Windows pada dua terminal di atas, buka `http://127.0.0.1:5173/`. Alamat `http://192.168.1.10:5173/` tetap digunakan untuk aplikasi yang berjalan di VM UbuntuServer. Data seed hanya untuk demonstrasi UI; record seed tidak membuktikan Wazuh/pfSense terhubung dan tidak seharusnya dipakai sebagai pengujian auto-response nyata.

## 10. Mengisi Settings dan memeriksa integrasi

Jalankan default topologi tanpa menimpa secret yang sudah tersimpan:

```bash
cd /root/backend
venv/bin/python apply_lab_defaults.py
```

Di halaman **Settings**, isi:

| Kolom | Nilai lab |
| --- | --- |
| Wazuh Host | `127.0.0.1` |
| Manager API Port | `55000` |
| Indexer Port | `9200` |
| API Username | `wazuh` atau akun API yang lulus HTTP 200 |
| API Password | password akun Manager API tersebut |
| Indexer Username | `admin` |
| Indexer Password | password Indexer admin |
| pfSense Host | `https://10.10.10.1` |
| pfSense API Key | key user SOC |
| Block Interface | `wan` |
| Alias | `SOC_Blocklist` |
| Threshold | `10` |
| Polling Interval | `60` detik |
| Maximum Alert Age | Default `600` detik; `900` hanya jika operator menyimpannya untuk uji |
| Whitelist | `127.0.0.1,10.10.10.0/24,192.168.1.0/24` |

Biarkan Auto-Response mati dahulu. Klik **Save Changes**, lalu **Test Connection**. Tes terminal:

```bash
cd /root/backend
venv/bin/python check_wazuh.py
venv/bin/python check_pfsense.py
```

Hasil Wazuh yang benar:

```text
manager: true
indexer: true
alerts_readable: true
```

Uji hak tulis pfSense secara reversibel:

```bash
venv/bin/python check_pfsense.py --write-test
```

Skrip memakai IP dokumentasi `198.51.100.254`, lalu menghapusnya kembali. Jika cleanup gagal, hapus IP tersebut dari alias secara manual.

Setelah tes tulis berhasil, coba block/unblock manual `198.51.100.2` dari halaman **Blocked IPs**. Pastikan alias pfSense berubah. Baru setelah itu aktifkan Auto-Response dan simpan Settings.

```bash
venv/bin/python check_auto_response.py
```

Panel Scheduler harus menunjukkan `Running: yes`, siklus terakhir terus berubah, dan status `success`.

## 11. Mengaktifkan perlindungan web defacement

Perlindungan terdiri dari permission source, Wazuh FIM, audit/Who-data, dan Website Guard.

### 11.1 Salin Website Guard ke Server STIS

Website Guard memindai semua situs di bawah `/var/www`, termasuk situs yang ditambahkan kemudian. Periksa dahulu di target bahwa direktori itu berisi konten yang sah. Ikuti [Panduan 02](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md) untuk memasang Agent dan pola log umum. File website tidak disediakan oleh repositori SOC.

Jalankan dari **UbuntuServer**:

```bash
scp /root/website_guard/website_guard.py \
  /root/website_guard/website-guard.service \
  /root/website_guard/website-guard.timer \
  USER_STIS@10.10.10.30:/tmp/
```

Gunakan akun SSH biasa milik Server STIS. Password yang diminta adalah password akun tersebut, bukan password STIS SOC/Wazuh.

Pada **Server STIS**:

```bash
sudo install -m 0750 /tmp/website_guard.py /usr/local/sbin/website_guard.py
sudo install -m 0644 /tmp/website-guard.service /etc/systemd/system/website-guard.service
sudo install -m 0644 /tmp/website-guard.timer /etc/systemd/system/website-guard.timer
sudo install -d -m 0700 /var/lib/mini-soc-website-guard
sudo install -d -m 0750 /var/log/mini-soc
sudo touch /var/log/mini-soc/website_guard.log
sudo chmod 0640 /var/log/mini-soc/website_guard.log
```

Periksa website bersih, lalu buat baseline:

```bash
sudo /usr/local/sbin/website_guard.py init --root /var/www
```

Hasil harus `baseline_created`. Jangan memakai `--force` pada website yang belum diperiksa. Pada target yang dahulu memakai baseline khusus `/var/www/web1`, simpan salinan direktori state lama lalu buat baseline baru untuk `/var/www` sebelum memasang service terbaru; detail migrasi ada di Panduan 02.

### 11.2 Periksa izin file website

Source `web1` dan kebutuhan tulis aplikasinya **tidak ada di repositori SOC**. Jangan menjalankan `chown -R`/`chmod -R` secara umum: itu dapat merusak uploads, cache, atau sesi aplikasi yang sedang berjalan. Simpan backup dan temukan file yang dapat ditulis semua pengguna:

```bash
test -d /var/www/web1
sudo tar -C /var/www -czf "/root/web1-clean-$(date +%Y%m%d-%H%M%S).tar.gz" web1
sudo find /var/www/web1 -xdev -type f -perm /002 -print
```

Perbaiki izin hanya pada path yang pemilik dan kebutuhan tulisnya sudah diketahui. Log keamanan aplikasi sebaiknya berada di `/var/log/stis-soc/apps/web1.jsonl` sesuai Panduan 02, bukan membuat `login_attempt.log` baru di web root tanpa dukungan kode aplikasi. Jika website **memang** mempunyai direktori `uploads`, larang eksekusi PHP di direktori itu melalui VirtualHost:

```apache
<Directory /var/www/web1/uploads>
    Options -ExecCGI -Indexes
    AllowOverride None
    <FilesMatch "\.(?i:php[0-9]?|phtml|phar)$">
        Require all denied
    </FilesMatch>
</Directory>
```

Jangan menambahkan blok `uploads` bila direktori tersebut tidak ada atau aplikasi memakai jalur unggah lain; sesuaikan path setelah diperiksa. Jalankan `sudo apache2ctl configtest` dan reload Apache setelah mengubah VirtualHost.

### 11.3 Hubungkan Website Guard dan FIM ke Agent

Konfigurasi satu kali untuk sumber log Website Guard dan FIM seluruh `/var/www` ada di [Panduan Agent dan Target Monitoring](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md#4-pasang-pola-monitoring-lokal-sekali-per-server). Jangan menambahkan path `web1` lagi bila sudah tercakup oleh konfigurasi global, karena dapat menghasilkan alert ganda. Who-data/auditd adalah opsi tambahan bila Anda perlu atribusi proses lokal.

Auditd bersifat **opsional** untuk atribusi proses. Memasang paket saja tidak mengaktifkan Wazuh who-data; konfigurasi Agent perlu diubah mengikuti [panduan FIM Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html) dan diuji pada host. Jika fitur itu diperlukan, pasang auditd:

```bash
sudo apt update
sudo apt install -y auditd audispd-plugins
sudo systemctl enable --now auditd
sudo /var/ossec/bin/wazuh-agentd -t
sudo systemctl restart wazuh-agent
```

Aktifkan scanner:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now website-guard.timer
sudo systemctl start website-guard.service
sudo systemctl status website-guard.timer --no-pager
sudo journalctl -u website-guard.service -n 30 --no-pager
```

Perubahan website yang sah harus diperiksa lebih dahulu, kemudian baseline diperbarui:

```bash
sudo /usr/local/sbin/website_guard.py check --root /var/www
sudo /usr/local/sbin/website_guard.py approve --root /var/www
```

`approve` tidak boleh dijalankan ketika insiden masih berlangsung.

## 12. Gerbang sebelum pengujian

Seluruh perintah simulasi, persyaratan aplikasi target nyata, server demo `web1`, bukti empat lapisan, serta pembersihan antarsesi ada di [Panduan Pengujian Lengkap](PANDUAN_05_UJI_FUNGSIONAL_TARGET_NYATA_DAN_DEMO.md). Instalasi pada bab ini harus selesai sebelum uji end-to-end. `wazuh-logtest` sendiri tidak membuktikan alur target atau pemblokiran pfSense.

## 13. Operasional dashboard

- **Dashboard**: statistik, timeline, severity, source IP, dan alert terbaru.
- **Alerts**: pencarian/filter, detail raw alert, jenis serangan, source IP, block manual, dan penghapusan riwayat alert oleh administrator.
- **Inventaris Wazuh**: pilih Agent untuk membaca paket, service, port, sumber log, dan FIM. Penambahan target dilakukan pada host sesuai panduan Agent.
- **Blocked IPs**: detail record, unblock, block ulang, sync, serta hapus riwayat unblocked terpilih.
- **Audit Log**: hasil login, fetch, konfigurasi, block/unblock, dan error integrasi.
- **Settings**: koneksi, threshold, whitelist, usia alert, interval, dan status scheduler.
- **Lonceng**: enam alert terbaru level 7+, diperbarui setiap 30 detik; status dibaca tersimpan di browser per akun.
- **Profil**: identitas sesi, waktu login, Settings, Audit Log, dan Sign out.

### Menghapus alert lama dari dashboard

Masuk sebagai **admin**, buka **Alerts → Hapus alert lama**. Pilih **1 minggu**, **1 bulan**, **6 bulan**, atau **1 tahun** untuk menghapus alert yang **lebih tua** dari batas itu. Minggu dihitung sebagai 7 hari; bulan dan tahun dihitung sebagai bulan kalender, sehingga tanggal 31 disesuaikan ke akhir bulan bila perlu. Contoh: memilih 1 minggu pada 5 Oktober pukul 19.00 menghapus alert sebelum 28 September pukul 19.00; alert sejak batas tersebut tetap disimpan. Perhitungan menggunakan waktu Indonesia Barat dan cutoff UTC yang dibekukan saat pratinjau. Pilihan **Semua alert sampai sekarang** menghapus seluruh alert sebelum waktu pratinjau, termasuk alert hari ini. Pilihan ini sengaja diberi label tersendiri karena dampaknya lebih luas.

1. Tekan **Tahap 1: Lihat pratinjau**. Dashboard menampilkan jumlah dokumen Indexer dan salinan database SOC secara terpisah. Kedua jumlah boleh berbeda karena SOC hanya menyimpan alert yang pernah diambilnya. Pratinjau berlaku 5 menit.
2. Periksa batas waktu dan jumlah. Masukkan **password akun admin**, lalu ketik persis frasa **`HAPUS ALERT WAZUH`**. Tekan **Tahap 2: Hapus permanen**. Jika jumlah berubah sebelum konfirmasi, sistem membatalkan pratinjau dan meminta hitung ulang. Tiga kegagalan verifikasi dalam 15 menit mengunci pembuatan pratinjau baru sementara.
3. Tunggu status selesai pada halaman Alerts. Operasi berjalan sebagai tugas Indexer; penarikan alert SOC dijeda selama tugas aktif. Database SOC dibersihkan hanya setelah Indexer melaporkan tugas selesai tanpa kegagalan. Periksa **Audit Log** untuk catatan jumlah yang dihapus.

Penghapusan ini hanya mencakup dokumen `wazuh-alerts-*` di Wazuh Indexer dan tabel alert SOC. Riwayat blokir IP serta audit SOC dipertahankan. File alert mentah Manager di `/var/ossec/logs/alerts/` tidak tersentuh; penghapusan dokumen Indexer juga tidak selalu langsung mengembalikan ruang disk karena segment indeks perlu digabung atau dihapus. Untuk retensi penyimpanan jangka panjang, atur **Index State Management (ISM)** pada Indexer dan kebijakan rotasi/retensi file Manager secara terpisah. Jangan samakan hasil kosong di dashboard dengan seluruh jejak alert sudah terhapus dari disk.

Sebelum penghapusan untuk kebutuhan skripsi, ekspor atau cadangkan bukti alert yang masih diperlukan. Bila status **failed**, periksa Audit Log dan kesehatan Indexer sebelum membuat pratinjau baru; salinan SOC sengaja dipertahankan jika tugas Indexer gagal atau hanya berhasil sebagian. Akun Indexer pada Settings harus memiliki hak baca serta hapus dokumen `wazuh-alerts-*`; akun `admin` pada lab memenuhi kebutuhan ini.

Arti keputusan auto-response yang umum:

| Nilai | Makna |
| --- | --- |
| `blocked` | Alias/rule lulus pemeriksaan API; uji koneksi baru masih diperlukan |
| `block_reinforced` | IP sudah tercatat; alias/rule diperiksa ulang dan pembersihan state dicoba |
| `below_threshold` | Level lebih rendah dari threshold |
| `whitelisted` | IP/subnet dilindungi whitelist |
| `stale_alert` | Alert melewati Maximum Alert Age |
| `no_source_ip` | Wazuh tidak menyediakan IP valid |
| `invalid_timestamp` | Timestamp tidak dapat dibaca; alert tidak boleh memicu blokir |
| `integrity_alert` | Perubahan file perlu investigasi/korelasi |
| `review_only` | Indikator ada, tetapi bukti tidak cukup untuk blokir IP otomatis |
| `block_failed` | Periksa Audit Log, backend log, dan privilege API |

Urutan penyaring ada di `ResponseEngine.evaluate_threat`: saklar auto-response, level, kategori integritas, eligibility, IPv4, whitelist, lalu timestamp/usia. Karena itu alert host yang tidak layak auto-block biasanya menghasilkan `review_only`, bukan selalu `no_source_ip`; level rendah lebih dahulu menghasilkan `below_threshold`. Nilai `block`/`reinforce_block` adalah instruksi internal sebelum hasil API, bukan status sukses akhir.

## 14. Update kode tanpa instalasi ulang

Perubahan yang disimpan di Windows langsung terlihat pada VM-Share. Jalankan pada UbuntuServer:

```bash
bash /media/sf_VM-Share/update_from_vm_share.sh /root
```

Skrip mempertahankan `venv`, `node_modules`, database, `.env`, log, dan PID; lalu me-restart aplikasi. Setelah selesai:

```bash
cd /root/backend
venv/bin/python check_wazuh.py
venv/bin/python check_pfsense.py
venv/bin/python check_auto_response.py
venv/bin/python check_sqli.py
venv/bin/python check_defacement.py
```

Tekan `Ctrl+F5` pada browser.

Jika dependency berubah:

```bash
# requirements.txt berubah
/root/backend/venv/bin/python -m pip install -r /root/backend/requirements.txt

# package.json/package-lock.json berubah
cd /root/frontend
npm install
```

Jangan menjalankan `setup_ubuntu.sh` atau menghapus database untuk update kode biasa.

## 15. Backup, pemulihan, dan respons insiden

### 15.1 Backup konfigurasi dan data

Pada UbuntuServer:

```bash
cd /root
bash stop_soc.sh
sudo install -d -m 0700 /root/mini-soc-backups
sudo cp -a /root/backend/instance/soc.db \
  "/root/mini-soc-backups/soc-$(date +%Y%m%d-%H%M%S).db"
sudo cp -a /var/ossec/etc/rules/local_rules.xml \
  "/root/mini-soc-backups/local_rules-$(date +%Y%m%d-%H%M%S).xml"
sudo cp -a /var/ossec/etc/decoders/local_decoder.xml \
  "/root/mini-soc-backups/local_decoder-$(date +%Y%m%d-%H%M%S).xml"
bash start_soc.sh
```

SOC dihentikan sejenak agar salinan SQLite konsisten. Pastikan `soc.db` sudah dibuat oleh `setup_ubuntu.sh`; jika path itu tidak ada, periksa `DATABASE_URL` yang aktif sebelum menyalin.

Pada Server STIS:

```bash
sudo tar -C /var/www -czf "/root/web1-$(date +%Y%m%d-%H%M%S).tar.gz" web1
sudo cp -a /var/ossec/etc/ossec.conf \
  "/root/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
sudo cp -a /etc/apache2/sites-available/web1.conf \
  "/root/web1.conf.$(date +%Y%m%d-%H%M%S).bak"
```

Jika benar-benar perlu mengosongkan database lab, hentikan aplikasi dan pindahkan database lama sebagai backup sebelum inisialisasi:

```bash
cd /root
bash stop_soc.sh
BACKUP_TAG="$(date +%Y%m%d-%H%M%S)"
sudo mv /root/backend/instance/soc.db \
  "/root/mini-soc-backups/soc-before-reset-${BACKUP_TAG}.db"
/root/backend/venv/bin/python /root/backend/init_db.py
bash start_soc.sh
```

Perintah `init_db.py` tanpa memindahkan database lama tidak menghapus data. Reset di atas menghilangkan settings dari database aktif, sehingga kredensial Wazuh/pfSense harus diisi kembali.

### 15.2 Web defacement nyata

Jika konten berbahaya tampil:

1. Hentikan Apache atau nonaktifkan backend HAProxy web1.
2. Jangan menjalankan Website Guard `approve`.
3. Simpan website, hash, log Apache, Website Guard, Wazuh, auth, dan auditd.
4. Periksa proses/user Who-data, web shell, file PHP di uploads, cron, SSH key, dan akun baru.
5. Pulihkan seluruh web root dari backup bersih.
6. Rotasi password aplikasi, database, SSH, dan API yang mungkin bocor.
7. Tutup celah upload/CMS/aplikasi, scan ulang, lalu buat baseline baru.

Contoh pengumpulan bukti:

```bash
INCIDENT_DIR="/root/incidents/web-defacement-$(date +%Y%m%d-%H%M%S)"
sudo install -d -m 0700 "$INCIDENT_DIR"
sudo cp -a /var/www/web1 "$INCIDENT_DIR/website"
sudo cp -a /var/log/apache2 "$INCIDENT_DIR/apache2-logs"
sudo cp -a /var/log/stis-soc "$INCIDENT_DIR/stis-soc-logs"
sudo cp -a /var/log/mini-soc/website_guard.log "$INCIDENT_DIR/"
sudo find "$INCIDENT_DIR/website" -type f -exec sha256sum {} \; \
  | sudo tee "$INCIDENT_DIR/sha256.txt" >/dev/null
sudo ausearch -f /var/www/web1 -ts recent -i | tail -n 100
```

Memblokir IP saja tidak memulihkan defacement dan tidak menghapus persistence.

## 16. Troubleshooting

### 16.1 Dashboard blank atau gagal login

```bash
cd /root
bash stop_soc.sh
bash start_soc.sh
tail -n 100 backend.log
tail -n 100 frontend.log
curl -i http://127.0.0.1:5000/api/dashboard/stats
```

Lakukan hard refresh. HTTP 401 berarti sesi belum valid; HTTP 500 perlu diperiksa pada backend log. Pastikan hanya satu backend berjalan.

### 16.2 `check_wazuh.py` gagal

| Hasil | Periksa |
| --- | --- |
| Manager 401 | Username/password Manager API; jangan gunakan password Indexer |
| Indexer 401 | Password user Indexer `admin` |
| Connection refused | Service, bind address, dan port 55000/9200 |
| `alerts_readable: false` 403 | Role Indexer tidak dapat membaca `wazuh-alerts-*` |
| 404 indeks | Manager/Filebeat belum membentuk indeks alert |

```bash
sudo systemctl is-active wazuh-manager wazuh-indexer filebeat
sudo filebeat test output
read -rsp "Password Indexer admin: " WAZUH_INDEXER_PASSWORD; echo
curl -sk -u "admin:${WAZUH_INDEXER_PASSWORD}" \
  'https://127.0.0.1:9200/_cat/indices/wazuh-alerts-*?v'
unset WAZUH_INDEXER_PASSWORD
```

### 16.3 `check_pfsense.py` gagal

| Status | Penyebab umum |
| --- | --- |
| 401 | Key salah/dicabut atau API Key auth mati |
| 403 | User key tidak memiliki privilege endpoint |
| Timeout | Routing/rule ke `This Firewall` bermasalah |
| Alias terbaca, write gagal | Kurang privilege PATCH/apply |
| Alias berisi IP, trafik lolos | Rule WAN tidak ada/salah urutan atau state lama |

Periksa `check_pfsense.py --write-test`, rule WAN, firewall log, dan **Diagnostics → States**.

### 16.4 Source IP menjadi `10.10.10.1`

Periksa berurutan:

1. HAProxy memakai mode HTTP dan `set-header X-Forwarded-For`.
2. Apache memuat `remoteip_module`.
3. `RemoteIPInternalProxy` hanya `10.10.10.1`.
4. `CustomLog` memakai `%a`.
5. Request uji melalui WAN/HAProxy, bukan langsung ke server.
6. Alert yang dilihat berasal dari log baru.

### 16.5 SQL Injection terdeteksi tetapi block beralasan Web Attack

Satu request dapat menghasilkan alert aplikasi level 12 dan alert Apache generik. Versi saat ini meningkatkan alasan record ketika alert spesifik tiba. Pastikan rule SQLi yang sesuai sumbernya (`100200` untuk login legacy atau `100510` untuk JSON aplikasi) masuk Indexer, tunggu polling berikutnya, lalu periksa `check_sqli.py` dan detail Blocked IP.

### 16.6 FIM muncul tetapi konten Website Guard tidak muncul

Pada Server STIS:

```bash
sudo grep -n -B 2 -A 4 'website_guard.log' /var/ossec/etc/ossec.conf
sudo grep -iE 'website_guard|logcollector' /var/ossec/logs/ossec.log | tail -n 50
```

Pastikan format `json`, `timestamp`, dan `event_type` ada, restart Agent, lalu buat event baru. Pada Wazuh 4.14.7 lab, event JSON melewati parent bawaan `86600` level 0 dan harus turun ke rule spesifik seperti `100300`. Jika `wazuh-logtest` berhenti di `86600`, rule anak STIS belum cocok; periksa rule yang terpasang dan field event.

### 16.7 Service Wazuh Manager gagal setelah rule diubah

Pulihkan backup terbaru:

```bash
LATEST_RULE_BACKUP="$(sudo ls -1t /var/ossec/etc/rules/local_rules.xml.*.bak 2>/dev/null | head -n 1)"
test -n "$LATEST_RULE_BACKUP" || { echo "Backup tidak ditemukan"; exit 1; }
sudo cp "$LATEST_RULE_BACKUP" /var/ossec/etc/rules/local_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/local_rules.xml
sudo chmod 0640 /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

### 16.8 Lupa password akun SOC

Password SOC tersimpan sebagai hash bcrypt dan tidak dapat dibaca kembali. Akun default `admin/admin123` hanya berlaku jika belum pernah diubah. Password SOC berbeda dari akun Wazuh, SSH, dan pfSense. Untuk menetapkan password baru, jalankan di **UbuntuServer**, bukan di STIS atau Kali:

```bash
cd /root
bash stop_soc.sh
install -d -m 0700 /root/mini-soc-backups
cp -a /root/backend/instance/soc.db \
  "/root/mini-soc-backups/soc-before-password-reset-$(date +%Y%m%d-%H%M%S).db"
cd /root/backend
venv/bin/python - <<'PY'
from getpass import getpass
from app import create_app
from app.extensions import db
from app.models import User

app = create_app(start_scheduler=False)
with app.app_context():
    user = User.query.filter_by(username='admin').first()
    if user is None:
        raise SystemExit('Akun admin tidak ada; periksa database yang aktif.')
    password = getpass('Password SOC baru: ')
    confirmation = getpass('Ulangi password baru: ')
    if not password or password != confirmation:
        raise SystemExit('Password kosong atau konfirmasi berbeda; tidak diubah.')
    user.set_password(password)
    db.session.commit()
    print('Password akun admin diperbarui tanpa menghapus data alert.')
PY
cd /root
bash start_soc.sh
```

Jika instalasi memakai `DATABASE_URL` lain, periksa lokasi tersebut dan sesuaikan backup sebelum menjalankan prosedur. Password baru tidak dicetak pada terminal. Lakukan logout/login pada browser; prosedur ini tidak membuat halaman pengelolaan akun baru.

## 17. Validasi kode untuk pengembang

Pada Linux:

```bash
cd /root
backend/venv/bin/python scripts/run_backend_tests.py
backend/venv/bin/python scripts/check_repository.py
backend/venv/bin/python modelling/evaluate_response.py
cd frontend
npm run build
```

Pada Windows PowerShell:

```powershell
# Buka PowerShell pada root clone proyek.
.\backend\venv\Scripts\python.exe scripts/run_backend_tests.py
.\backend\venv\Scripts\python.exe scripts/check_repository.py
.\backend\venv\Scripts\python.exe modelling/evaluate_response.py
cd frontend
npm.cmd run build
```

Build frontend dapat memberi warning ukuran chunk; warning tersebut tidak menggagalkan build. Tes unit memakai mock dan database sementara. Diagnosis `check_*.py` di UbuntuServer tetap diperlukan untuk membuktikan integrasi aktual.

## 18. Onboarding server dan target monitoring

Pendaftaran Agent, website, domain, endpoint, dan service dijelaskan terpisah di [Panduan Agent dan Target Monitoring](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md). Halaman **Inventaris Wazuh** di SOC membaca Agent, paket, service, port, sumber log, dan FIM dari Manager. SOC tidak lagi menyediakan CRUD server/resource ataupun menulis konfigurasi grup Wazuh. Data server/resource yang pernah dibuat lewat fitur lama tetap berada di database untuk arsip; Agent dan konfigurasi Wazuh yang sudah berjalan tidak dihapus otomatis.

Jika `web1` pernah dikonfigurasi melalui grup `stis-soc` lama, periksa koleksi ganda saat migrasi ke pola Agent lokal. Uji event dari jalur baru lebih dulu, lalu lepaskan hanya sumber yang duplikat sesuai langkah migrasi dalam panduan Agent. Wazuh tidak menyimpan daftar domain dari DNS atau VirtualHost sebagai inventaris terpisah; identitas situs pada detail alert berasal dari path log standar atau metadata JSON aplikasi.
## 19. Matriks deteksi dan kebijakan respons

Matriks ini mengikuti rule dan klasifikasi pada source proyek. Kategori penelitian merujuk pula ke `Analisis_Serangan_Log_STIS.xlsx`, tetapi workbook tersebut bukan bagian instalasi sistem. Nama kategori adalah indikator pola request; probe ke suatu file **tidak membuktikan** file itu ada atau data telah bocor. Ambang bawaan level 10, auto-response aktif, umur alert valid, dan IP bukan whitelist tetap harus dipenuhi.

Workbook dan dataset penelitian disediakan terpisah dari repositori. Angka jumlah request dan hasil pelabelannya harus dirujuk ke dataset serta metode analisis yang dapat diperiksa; daftar fitur atau rule pada source tidak membuktikan angka tersebut. Dokumentasi arsitektur dan alur implementasi tersedia dalam `STIS_SOC.md`.

| Jenis | Rule utama | Lokasi yang ditampilkan | Auto-block IP |
| --- | --- | --- | --- |
| SSH/web/service brute force | `100002`, `100102`, `100501` | Host, akun, endpoint bila ada | Ya, korelasi berulang |
| SQL injection | `100200`–`100202`, `100510` | Form/URL, host, domain | Ya |
| Shellshock | `31168`/`31169`, `100490` | URL/host dan User-Agent di raw log | Ya pada level ≥ ambang |
| Webshell filename probe | `100400`, `100401` | URL file yang diminta | Ya setelah berulang; satu probe level 7 hanya alert |
| WordPress scan | `100410`, `100411` | URL seperti `/wp-login.php` | Ya setelah berulang |
| Vulnerability scanner | `100420`, `100421` | URL dan User-Agent | Ya setelah berulang; evaluasi scanner resmi |
| File konfigurasi sensitif | `100430` | URL seperti `/.env` | Ya; cek apakah respons benar-benar menyajikan file |
| Probe RCE/PHPUnit/CGI | `100440` | Endpoint rawan | Ya; verifikasi eksekusi secara terpisah |
| Enumerasi service | `100450`, `100451` | URL admin/diagnostik | Ya setelah berulang |
| Path traversal/LFI | `100460` | URL dan parameter | Ya |
| XSS | `100468`/`100469`, `100470` | URL/parameter | Ya setelah lima probe dalam 60 detik dari IP sama |
| SSRF indikatif | `100480`, `100481` | Parameter target URL | Satu event tidak; lima event cocok dari IP sama dalam 3600 detik dapat diblokir. Verifikasi fetch lewat log egress/DNS |
| Defacement/judol/pinjol | `100300`, `100301`, `100302`, `100304` | Path file dari Website Guard/FIM | Tidak; IP web request bukan bukti pengubah file |
| Kemungkinan file webshell | `100305` | Path dan hash file dari Website Guard | Tidak; isolasi eksekusi, simpan bukti, telusuri uploader |
| IP reputasi yang ditinjau operator | `100600` | IP dan URL pada access log | Ya, melalui SOC/pfSense setelah daftar CDB dipasang; tidak memakai Windows `netsh` |
| Eksekusi perintah/utilitas mencurigakan | `100610`, `100611` | Host, path executable atau proses | Tidak; event lokal tidak membuktikan IP penyerang |
| Rootcheck, CVE, VirusTotal | Rule bawaan Wazuh, misalnya `510`/`521`, `87105` | Host, file, paket/CVE | Tidak; investigasi dan pemulihan pada host |

Untuk semua rule IP, SOC memeriksa source IP IPv4, whitelist CIDR, usia alert, dan daftar block. Rule Wazuh `31151` untuk banyak HTTP 4xx tetap didukung demi kompatibilitas lab, tetapi satu error 4xx tidak cukup untuk block. Lihat **Alerts → detail** untuk `Asset`, `Target path/endpoint`, `Log source`, `Mitigation tip`, raw event, serta status respons. Setelah block, pulihkan aplikasi yang rentan; firewall hanya menghentikan koneksi baru dari IP itu pada jalur rule.

### Membaca frekuensi rule dan batas polling

Nilai `frequency` pada XML menghitung event yang cocok menurut mesin rule Wazuh, bukan jumlah baris pada dashboard. Waktu korelasi saat ini: brute force 5/60 detik, webshell 5/120, WordPress 8/120, scanner 10/60, recon 5/120, XSS 5/60, dan SSRF 5/3600. Verifikasi jumlah request yang benar-benar memicu rule pada versi terpasang; jangan menyimpulkan hitungan hanya dari jumlah alert.

Pengambilan Indexer dibatasi 100 alert per panggilan. Polling memakai checkpoint timestamp, belum paginasi lengkap dengan penanda dokumen untuk timestamp yang sama. Karena itu SOC tidak menjamin seluruh histori atau semua event pada beban tinggi tersalin. Daftar alert pada Wazuh dan SOC dapat berbeda. Grafik harian SOC menggunakan waktu pengambilan (`fetched_at`) dalam UTC, bukan otomatis waktu kejadian target.

## 20. Rujukan pengujian dan uninstall

Panduan pengujian terpusat di [Panduan Pengujian Lengkap](PANDUAN_05_UJI_FUNGSIONAL_TARGET_NYATA_DAN_DEMO.md). Di sana Bagian I membahas server target nyata; Bagian II membahas demo `web1`, termasuk matriks rule, request Kali, FIM/Website Guard, bukti SOC/pfSense dan pemulihan. Untuk membongkar satu target atau seluruh sistem, gunakan [Uninstall Target](PANDUAN_03_PENSIUNKAN_SERVER_WEBSITE_DAN_SERVICE.md) atau [Uninstall Keseluruhan](PANDUAN_04_BONGKAR_LAB_STIS_SOC.md).
