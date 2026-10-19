# Panduan 03: Mempensiunkan server, website, domain, atau service dari lab

**Hasil yang ingin dicapai:** target yang dipensiunkan berhenti dipantau tanpa mengganggu website atau layanan lain. Menghentikan pemantauan, menghapus aplikasi website, dan menghapus bukti historis adalah tiga tindakan berbeda. Pilih hanya tindakan yang diperlukan. Konteks sistem dan struktur kode tersedia di [STIS_SOC.md](../STIS_SOC.md).


Panduan ini berlaku saat **satu website/domain/service atau satu server target benar-benar dipensiunkan dari lab**, termasuk rute dan layanan khusus target itu. Ini **bukan** tombol untuk berhenti memantau website yang masih harus melayani pengguna: konfigurasi Agent saat ini mengoleksi wildcard log dan FIM seluruh `/var/www`, sedangkan Website Guard dapat memindai root bersama. Menghapus log saja tidak menghentikan seluruh monitoring pada situs yang masih aktif. Jangan jalankan langkah menonaktifkan DNS/HAProxy/VirtualHost bila layanan harus tetap online. Untuk membongkar seluruh lab, gunakan [Panduan 04](PANDUAN_04_BONGKAR_LAB_STIS_SOC.md).

Mempensiunkan satu target tidak mencopot Wazuh Manager, Indexer, SOC, atau pfSense bersama. Halaman Inventaris Wazuh hanya membaca data Agent; tidak ada database CRUD target yang perlu dihapus di SOC. Hapus hanya konfigurasi yang telah dipastikan milik target tersebut.

## 1. Catat kepemilikan dan simpan bukti

Sebelum mengubah apa pun, catat ID Agent, slug log, domain, VirtualHost, root website, nama service, rute HAProxy, DNS, dan apakah Website Guard memindai seluruh `/var/www` atau satu situs. Satu Agent dapat memantau banyak aset; **jangan mencopot Agent bila masih ada situs atau service lain di server yang sama**. Simpan alert/audit yang diperlukan untuk laporan atau retensi insiden. Penghapusan konfigurasi monitoring tidak otomatis menghapus alert historis di Indexer/SOC.

```bash
# Pada target Ubuntu, baca saja
sudo apache2ctl -S
sudo grep -Rni 'stis_soc_combined\|/var/log/stis-soc' /etc/apache2/sites-enabled /var/ossec/etc/ossec.conf
sudo systemctl list-units --type=service --state=running
sudo find /var/log/stis-soc -maxdepth 2 -type f -print

# Pada Manager/UbuntuServer, baca saja
sudo /var/ossec/bin/agent_control -l
```

Di pfSense, ekspor konfigurasi melalui **Diagnostics → Backup & Restore → Download Configuration as XML** sebelum mengubah rute atau rule. Ini adalah prosedur backup resmi pfSense: [Netgate Backup](https://docs.netgate.com/pfsense/en/latest/backup/configuration.html).

## 2. Lepas satu website/domain Apache, server tetap dimonitor

Contoh ini memakai slug `web1`. Ganti hanya dengan slug yang benar, lalu cocokkan hasil perintah baca di atas.

1. Hapus atau nonaktifkan DNS record dan mapping Host/Backend HAProxy khusus domain tersebut. Jika satu frontend melayani beberapa situs, **jangan hapus seluruh frontend**. Simpan dan Apply perubahan pfSense.
2. Di target, nonaktifkan hanya VirtualHost situs. Bila konfigurasi VirtualHost juga melayani domain lain, edit mapping domain/log untuk domain yang dilepas, bukan `a2dissite` seluruhnya.

```bash
# Target STIS, contoh bila web1.conf hanya milik web1
sudo cp -a /etc/apache2/sites-available/web1.conf \
  "/etc/apache2/sites-available/web1.conf.$(date +%Y%m%d-%H%M%S).bak"
sudo a2dissite web1.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
sudo apache2ctl -S
```

3. Hentikan penulisan log aplikasi untuk situs itu. Simpan log `web1.access.log` dan `web1.jsonl` selama periode bukti/retensi. Setelah periode itu, hapus **hanya** berkas situs:

```bash
# Target STIS, jalankan hanya setelah path dan retensi diperiksa
for log in /var/log/stis-soc/apache/web1.access.log /var/log/stis-soc/apps/web1.jsonl; do
  if sudo test -f "$log"; then sudo rm -i -- "$log"; fi
done
```

Wildcard Agent `/var/log/stis-soc/apache/*.access.log` dan `/var/log/stis-soc/apps/*.jsonl` **tetap** diperlukan untuk aset lain. Jangan hapus blok `<localfile>` atau FIM `/var/www` bila masih ada situs di server tersebut.

4. Bila website memang akan dimatikan, arsipkan root-nya di luar web root; setelah arsip diverifikasi dan retensi selesai, hapus path spesifik. Jangan jalankan ini hanya untuk berhenti memantau website yang masih aktif.

```bash
# Target STIS; contoh web1 yang memang dipensiunkan
sudo tar -C /var/www -czf "/root/web1-retired-$(date +%Y%m%d-%H%M%S).tar.gz" web1
if [ "$(realpath -e /var/www/web1)" = /var/www/web1 ]; then
  sudo rm -rI -- /var/www/web1
else
  echo 'Path web1 tidak sesuai; tidak dihapus.' >&2
fi
```

Jika Website Guard memindai `/var/www`, perubahan/hilangnya situs akan menghasilkan alert FIM/Guard yang sah. Periksa baseline dan jalankan proses `approve` **hanya setelah** perubahan pensiun situs diverifikasi; jangan menekan `approve` untuk menutupi defacement. Jika Guard khusus `web1`, hentikan timer saat migrasi dan ubah root/baseline ke situs yang masih aktif; panduannya ada di [Panduan Agent](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md#7-website-guard-fim-dan-keterbatasan-perlindungan-file).

## 3. Lepas satu service/API atau endpoint

Jika hanya endpoint dalam suatu service yang dihentikan, ubah routing aplikasi/HAProxy dan dokumentasi service tersebut; file JSONL dan Agent tetap dipakai oleh endpoint lainnya. Untuk service tersendiri, hentikan service sesuai unit yang benar, lepaskan rute DNS/HAProxy khusus service, lalu arsipkan dan hapus hanya log miliknya sesudah retensi:

```bash
# Contoh: ganti nama unit dan slug dengan nilai hasil inventaris, jangan jalankan mentah
sudo systemctl disable --now NAMA_SERVICE.service
sudo ls -l /var/log/stis-soc/apps/SLUG_SERVICE.jsonl
sudo rm -i -- /var/log/stis-soc/apps/SLUG_SERVICE.jsonl
```

Jangan hapus service atau source code aplikasi bila permintaan hanya berhenti memantau. Jika service masih berjalan tetapi lognya dihapus, ia dapat membuat ulang file itu dan Wazuh kembali menerima event.

## 4. Lepas satu server target sepenuhnya

Lakukan bagian 2–3 untuk **semua** aset di host, lalu pastikan tidak ada website/service lain yang memerlukan Agent. Pada target Ubuntu, hentikan Website Guard **hanya bila instalasinya khusus server itu**; lepaskan paket Agent. Perintah purge mengikuti [dokumentasi Wazuh](https://documentation.wazuh.com/current/installation-guide/uninstalling-wazuh/agent.html).

```bash
# Target yang dipensiunkan
sudo systemctl disable --now website-guard.timer website-guard.service 2>/dev/null || true
sudo systemctl disable --now wazuh-agent
sudo apt-get remove --purge wazuh-agent
sudo systemctl daemon-reload
sudo ls -ld /var/ossec 2>/dev/null || true
```

Jika paket telah terhapus tetapi `/var/ossec` masih ada, periksa bahwa host ini memang **hanya** bekas Agent dan semua bukti sudah diarsipkan; baru hapus residual dengan `sudo rm -rI -- /var/ossec`. Jangan menjalankan perintah itu pada UbuntuServer yang menjadi Manager.

Jika telemetri PoC Linux dari `prepare_linux_host_detection.sh` pernah dipasang, aturan Auditd milik proyek tetap ada setelah paket Agent dicopot. Pada host yang dipensiunkan, periksa dulu apakah file ini benar milik STIS SOC, lalu lepaskan hanya aturan tersebut dan muat ulang Auditd. Jangan mencopot paket `auditd` bila dipakai layanan lain; simpan `/var/log/audit/audit.log` sesuai retensi bukti.

```bash
# Target yang dipensiunkan, sesudah memastikan tidak ada pemantauan lain yang memakainya
sudo cat /etc/audit/rules.d/stis-soc-exec.rules 2>/dev/null || true
if sudo test -f /etc/audit/rules.d/stis-soc-exec.rules; then
  sudo rm -i -- /etc/audit/rules.d/stis-soc-exec.rules
fi
sudo augenrules --load
sudo auditctl -l | grep audit-wazuh-c || true
```

Jika baris terakhir masih menampilkan `audit-wazuh-c`, sumbernya mungkin file aturan lain yang bukan milik proyek; tinjau file tersebut secara terpisah.

File `stis-soc-exec.rules` juga berisi `-e 1` agar audit kernel aktif. Setelah file dihapus, `auditctl -s` dapat tetap menunjukkan `enabled 1` sampai perubahan status kernel/reboot; itu bukan bukti aturan STIS SOC masih ada. Periksa `auditctl -l` dan pertahankan Auditd bila rule `web_change`, FIM who-data, atau aplikasi lain masih memakainya. Jangan menonaktifkan audit global hanya untuk menghilangkan angka status tersebut.

File Website Guard buatan proyek bukan bagian paket Agent. Setelah memastikan tidak ada situs yang memakainya, lepaskan hanya file yang dipasang oleh proyek:

```bash
# Target yang dipensiunkan, setelah bukti/baseline disimpan
for file in /usr/local/sbin/website_guard.py \
  /etc/systemd/system/website-guard.service \
  /etc/systemd/system/website-guard.timer; do
  if sudo test -e "$file"; then sudo rm -i -- "$file"; fi
done
sudo systemctl daemon-reload
sudo find /var/lib/mini-soc-website-guard /var/log/mini-soc /var/log/stis-soc \
  -maxdepth 2 -print 2>/dev/null
```

Direktori state/log di atas perlu ditinjau sebelum dihapus karena berisi bukti. Untuk **penghapusan permanen** setelah retensi, gunakan path eksplisit yang sudah diperiksa, misalnya `sudo rm -rI -- /var/lib/mini-soc-website-guard /var/log/mini-soc /var/log/stis-soc`; jangan jalankan jika dipakai aplikasi lain.

Di **Manager**, cocokkan ID yang sudah dicatat dengan nama/IP Agent, lalu hapus hanya ID itu. `000` adalah Manager sendiri dan tidak boleh dihapus. Perintah CLI resmi: [Wazuh remove agents](https://documentation.wazuh.com/current/user-manual/agent/agent-management/remove-agents/remove.html).

```bash
sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/manage_agents -r ID_AGENT_TARGET
sudo /var/ossec/bin/agent_control -l
```

Hapus grup Wazuh khusus target hanya jika grup itu **tidak** dipakai Agent lain. Lepas IP target dari rule/rute pfSense yang khusus target. Alias `SOC_Blocklist`, WAN Block umum, Wazuh Manager, dan SOC tetap ada untuk server lain. Di SOC klik **Inventaris Wazuh → Refresh**; Agent yang dihapus tidak lagi muncul. Alert historis tetap dapat muncul sampai masa retensi data berakhir. Hapus riwayat hanya menurut kebijakan retensi, bukan dengan menghapus indeks bersama seluruh server.

## 5. Verifikasi akhir

```bash
# Target, jika host tetap hidup
systemctl is-active wazuh-agent website-guard.timer 2>/dev/null || true
sudo apache2ctl -S 2>/dev/null || true
sudo find /var/log/stis-soc -maxdepth 2 -type f -print 2>/dev/null || true

# Manager
sudo /var/ossec/bin/agent_control -l
```

Pastikan domain tidak lagi diarahkan oleh DNS/HAProxy, VirtualHost atau service lama tidak aktif, log situs berhenti bertambah, Agent yang dipensiunkan hilang dari inventaris, dan aset lain tetap mengirim alert. Itulah kriteria penghapusan target yang bersih; data bukti yang sengaja dipertahankan harus dicatat sebagai arsip.

## 6. Riwayat setelah target dilepas

Melepas Agent tidak menghapus alert Indexer, salinan alert SOC, audit, atau riwayat blokir. Jika alert historis perlu dibersihkan setelah retensi laporan, gunakan fitur admin **Alerts → Hapus alert lama** dengan dua verifikasi sebagaimana Panduan 01. Unblock IP target/penguji dilakukan terpisah; menghapus alert tidak membuka blokir firewall.

Tabel `monitored_servers` dan `monitored_assets` lama bukan daftar target aktif. SOC tetap mempertahankannya sebagai arsip/atribusi event lama; tidak perlu menghapus database SOC untuk mempensiunkan satu Agent.
