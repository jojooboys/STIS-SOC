# Panduan 04: Membongkar seluruh komponen lab STIS SOC

**Hasil yang ingin dicapai:** seluruh komponen khusus lab dilepas setelah bukti penelitian disimpan. Panduan ini bukan prosedur merapikan demo atau mengosongkan alert. Daftar file yang dihapus skrip lebih sempit daripada seluruh kemungkinan file di VM; periksa sisa konfigurasi manual pada langkah akhir. Konteks sistem tersedia di [STIS_SOC.md](../STIS_SOC.md).


Dokumen ini untuk **dekomisioning seluruh lab**: semua Agent/target, aplikasi STIS SOC, Wazuh Manager/Indexer/Dashboard/Filebeat, dan konfigurasi pfSense/HAProxy yang dibuat untuk lab. Ini berbeda dari menutup satu sesi demo. Untuk mempertahankan demo `web1`, **jangan jalankan panduan ini maupun `cleanup_ubuntu.sh`**. Jika hanya satu target yang dilepas, pakai [Panduan Uninstall Target](PANDUAN_03_PENSIUNKAN_SERVER_WEBSITE_DAN_SERVICE.md).

“Tanpa sisa” di sini berarti tidak ada proses, paket, rule, rute, alias, token, database atau berkas proyek aktif di VM lab setelah retensi bukti dan backup yang dipilih selesai. Snapshot VirtualBox, arsip di luar VM, browser history, dan salinan Windows/shared folder adalah lokasi terpisah; hapus hanya bila kebijakan penelitian mengizinkan. Jangan menghapus komponen bersama yang masih dipakai sistem lain.

## 1. Inventaris dan backup sebelum membongkar

Catat Agent ID, alamat VM, daftar domain/HAProxy, alias/rule pfSense, direktori instalasi SOC, dan lokasi bukti skripsi. Ekspor konfigurasi pfSense melalui **Diagnostics → Backup & Restore** ([Netgate](https://docs.netgate.com/pfsense/en/latest/backup/configuration.html)); salin konfigurasi Wazuh dan database SOC ke media arsip yang memang diinginkan. File backup mengandung secret, simpan dengan akses terbatas.

```bash
# UbuntuServer, baca saja
sudo /var/ossec/bin/agent_control -l
dpkg-query -W wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true
sudo systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
ls -ld /root/backend /root/frontend /root/scripts /root/website_guard
```

Jangan memindahkan backup ke `/root` lalu menghapus `/root` secara rekursif; `/root` adalah home sistem dan dapat menyimpan data lain.

## 2. Lepas semua target dan jalur publik

Ikuti [Panduan Uninstall Target](PANDUAN_03_PENSIUNKAN_SERVER_WEBSITE_DAN_SERVICE.md) untuk setiap server dan situs: lepaskan route DNS/HAProxy, hentikan service uji, bersihkan helper demo bila ada, lepas Website Guard dan Wazuh Agent, kemudian hapus ID Agent yang cocok dari Manager. Lakukan **sebelum** Manager dicopot agar daftar Agent dapat diverifikasi.

Di pfSense, hapus frontend/backend HAProxy yang **khusus STIS SOC**, rule NAT/port forward uji, WAN Block rule dengan sumber `SOC_Blocklist`, lalu alias `SOC_Blocklist` dan API key user SOC. Gunakan **Save/Apply** setelah setiap perubahan. Jika HAProxy/REST API dipakai proyek lain, pertahankan paket dan hanya hapus objek proyek ini. Bila benar-benar khusus lab, buka **System → Packages → Installed Packages** dan hapus paket HAProxy dan REST API melalui tombol hapus; ini mengikuti [Netgate Package Manager](https://docs.netgate.com/pfsense/en/latest/packages/manager.html). Hapus state IP uji tertentu melalui **Diagnostics → States**; tidak perlu reset seluruh state table ([Netgate States](https://docs.netgate.com/pfsense/en/latest/monitoring/status/firewall-states-gui.html)).

## 3. Hentikan dan lepaskan aplikasi STIS SOC di UbuntuServer

`cleanup_ubuntu.sh` yang diperbarui adalah **uninstaller aplikasi SOC saja**. Ia tidak menghapus Wazuh, Agent, pfSense, Apache, atau seluruh `/root`. Baca daftar file lebih dahulu, lalu jalankan mode eksekusi hanya pada instalasi `/root` yang memang khusus lab:

```bash
# UbuntuServer
cd /root
bash stop_soc.sh
bash /root/cleanup_ubuntu.sh --list /root
sudo bash /root/cleanup_ubuntu.sh --execute /root
```

Skrip memeriksa penanda aplikasi, berhenti bila path tidak sesuai, menghentikan proses dari PID instalasi tersebut, dan menghapus berkas proyek yang terdaftar termasuk database `backend/instance/soc.db`. Tidak ada rollback setelah `--execute`. Salinan source di VM-Share/Windows tidak ikut terhapus. Daftar versi terbaru mencakup `soc_processes.sh`, `STIS_SOC.md`, `config/wazuh/`, `datasets/`, dan `modelling/`. Periksa mode `--list` untuk daftar aktual sebelum eksekusi. Jangan menjalankan `rm -rf /root`.

Jika Anda memakai unit systemd atau reverse proxy yang dibuat manual di luar proyek, cari dan hapus unit/vhost khusus SOC itu setelah memastikan tidak dipakai layanan lain:

```bash
# Baca sebelum mengubah; nama unit/vhost dapat berbeda
sudo systemctl list-unit-files | grep -i soc || true
sudo ls /etc/systemd/system/*soc* /etc/nginx/sites-enabled/*soc* 2>/dev/null || true
```

Aturan UFW `5000/tcp` dan `5173/tcp` yang dipasang hanya untuk SOC dapat dihapus jika tercatat sebagai milik SOC. Periksa `sudo ufw status numbered`, lalu hapus rule yang benar; jangan menghapus akses Wazuh atau SSH yang masih digunakan. Jika Node.js/Python dipasang khusus SOC, pencopotan paket bersifat opsional dan perlu memeriksa aplikasi lain dahulu. Komponen tersebut bukan data STIS SOC.

```bash
# UbuntuServer, hanya jika kedua rule ini memang khusus STIS SOC
sudo ufw status numbered
sudo ufw delete allow 5000/tcp
sudo ufw delete allow 5173/tcp
sudo ufw status numbered
```

## 4. Copot Wazuh pusat

Pada setiap target Linux yang sudah dipensiunkan, selesaikan juga pembersihan aturan Auditd `stis-soc-exec.rules` menurut [panduan pensiun target](PANDUAN_03_PENSIUNKAN_SERVER_WEBSITE_DAN_SERVICE.md#4-lepas-satu-server-target-sepenuhnya). Aturan ini berada di luar paket Wazuh Agent dan tidak hilang otomatis saat Agent dicopot.

Integrasi VirusTotal (bila pernah diaktifkan) dan dua daftar CDB STIS SOC berada di konfigurasi/direktori Wazuh Manager. Pencopotan Manager membersihkannya bersama `/var/ossec`; sebelum itu arsipkan hanya bukti yang diperlukan dan jangan menyimpan API key dalam laporan atau repositori.

Pada instalasi all-in-one Wazuh 4.14.x, [dokumentasi resmi Wazuh](https://documentation.wazuh.com/current/installation-guide/uninstalling-wazuh/central-components.html) menyediakan assistant `--uninstall` untuk Manager, Indexer, dan Dashboard. Jalankan pada UbuntuServer **setelah semua Agent dan SOC dilepas**:

```bash
# UbuntuServer; periksa bahwa ini VM Wazuh yang akan dibongkar
cd /root
curl -fsSO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh --uninstall
```

Jika assistant tidak cocok dengan cara instalasi awal, gunakan prosedur package manager pada halaman resmi yang sama untuk `wazuh-dashboard`, `wazuh-manager`, `filebeat`, dan `wazuh-indexer`; jangan menjalankan kedua metode sekaligus. Periksa residu **setelah** uninstall:

```bash
dpkg-query -W wazuh-manager wazuh-indexer wazuh-dashboard filebeat 2>/dev/null || true
sudo systemctl list-unit-files | grep -E 'wazuh|filebeat' || true
sudo ls -ld /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer \
  /etc/wazuh-dashboard /var/lib/wazuh-dashboard /etc/filebeat /var/lib/filebeat 2>/dev/null || true
```

Jika residual data Wazuh masih ada dan retensi/backup sudah diputuskan selesai, hapus **path Wazuh yang sudah diverifikasi** satu per satu. Jangan menggunakan wildcard `/var/*` atau menghapus `/var/ossec` ketika Agent/Manager lain masih bergantung padanya. Hapus repository APT Wazuh dan keyring hanya bila dipasang untuk lab dan tidak dipakai sistem lain.

```bash
# UbuntuServer yang memang khusus Wazuh; periksa dulu keluaran ls di atas
sudo rm -rI -- /var/ossec /etc/wazuh-indexer /var/lib/wazuh-indexer \
  /etc/wazuh-dashboard /var/lib/wazuh-dashboard /etc/filebeat /var/lib/filebeat

# Tinjau berkas installer, repositori, keyring, dan password yang mungkin tersisa.
sudo find /root -maxdepth 1 -iname '*wazuh*' -print
sudo find /etc/apt/sources.list.d /usr/share/keyrings -maxdepth 1 \
  -iname '*wazuh*' -print 2>/dev/null
```

Baris `rm -rI` hanya boleh dijalankan setelah assistant selesai, paket telah hilang, arsip bukti dipindahkan, dan **tidak ada komponen Wazuh lain pada VM tersebut**. Hapus hasil `find` satu per satu dengan `rm -i` setelah memastikan berkas itu milik lab; jangan meneruskan seluruh hasil `find` ke perintah hapus secara otomatis. File password yang disimpan di luar VM juga masuk kebijakan retensi secret.

## 5. Bersihkan VM, host, dan bukti yang memang sudah boleh dihapus

- Windows: hapus entri `web1.stis.local` yang ditambahkan sendiri di `C:\Windows\System32\drivers\etc\hosts`; pertahankan baris lain.
- VirtualBox: lepaskan shared-folder VM-Share dari pengaturan VM; hapus snapshot/VM lab satu per satu hanya setelah ekspor bukti dan backup selesai.
- pfSense: cek kembali bahwa frontend/backend, NAT uji, API key, WAN Block rule, alias, dan paket khusus lab telah hilang. Jangan reset konfigurasi firewall penuh jika perangkat masih menjalankan jaringan lain.
- UbuntuServer/STIS: cek sisa unit, cron/timer, log, token, path file dan proses milik proyek. File arsip yang sengaja disimpan harus dicatat sebagai pengecualian retensi.

```bash
# UbuntuServer dan STIS: pemeriksaan akhir, tidak mengubah sistem
ss -lntp | grep -E ':5000|:5173|:55000|:9200|:1514|:1515' || true
systemctl list-units --all | grep -Ei 'wazuh|filebeat|website-guard|soc' || true
find /tmp -maxdepth 1 -name '*stis-soc*' -print 2>/dev/null
```

“Bersih” baru dapat diklaim setelah objek pfSense, paket/proses Linux, Agent, rute DNS, berkas proyek, dan data yang diputuskan tidak disimpan semuanya diperiksa. Perintah di dokumen ini **tidak dijalankan otomatis** dari Windows; keluaran di setiap VM tetap harus diverifikasi oleh operator.
