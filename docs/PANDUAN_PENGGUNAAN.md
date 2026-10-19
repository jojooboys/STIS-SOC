# Panduan penggunaan STIS SOC

## Memilih mode

**Demo lokal** digunakan untuk mempelajari antarmuka tanpa menyiapkan VM Wazuh/pfSense. Ikuti [instalasi cepat](../README.md#demo-lokal) lalu jalankan `python seed_demo_data.py` dan `python run.py --demo` dari `backend/`. Database demo selalu `backend/instance/demo.db`; scheduler tidak diaktifkan. Akun awal demo `admin` / `admin123`. Data berstatus blocked pada mode ini adalah ilustrasi UI, bukan hasil API firewall. Jangan isi kredensial operasional atau memakai tombol integrasi untuk menguji demo offline.

Untuk memuat ulang contoh, hentikan backend demo, jalankan `python seed_demo_data.py --reset`, lalu mulai lagi dengan `python run.py --demo`. Pengisian ulang tanpa `--reset` ditolak jika data sudah ada. Database operasional `soc.db` tidak menjadi tujuan seeder.

**Lab terintegrasi** memerlukan [Panduan 01](PANDUAN_01_INSTALASI_PFSENSE_WAZUH_DAN_STIS_SOC.md). Jalankan `bash start_soc.sh` pada UbuntuServer dan akses alamat frontend lab dari browser. Ganti password awal admin mengikuti bagian 16.8 Panduan 01 sebelum menggunakan kredensial integrasi. Aplikasi belum menyediakan menu ubah password akun.

## Login dan membaca dashboard

1. Buka `http://127.0.0.1:5173/` untuk demo lokal atau `http://192.168.1.10:5173/` untuk topologi VM contoh.
2. Masukkan akun SOC. Akun ini berbeda dari Wazuh, pfSense, dan SSH.
3. Lihat total alert, alert hari ini, blokir aktif, kategori ancaman, dan lini masa. Tidak adanya alert belum berarti target aman; periksa koneksi dan status scheduler.
4. Lonceng menampilkan enam alert terbaru level 7 ke atas. Penanda sudah dibaca disimpan di browser per akun, bukan di database server.

## Meninjau Alerts

Gunakan pencarian, kategori, severity, dan pagination. Buka detail untuk memeriksa rule, waktu, Agent, IP sumber, sasaran, log asli, keputusan, dan saran. **Fetch New Alerts** mengambil data dari Indexer pada lab terintegrasi; bukan generator serangan.

| Keputusan | Makna dan tindakan operator |
| --- | --- |
| `blocked`, `reinforce_block` | Respons blokir dicatat; verifikasi alias dan koneksi baru di pfSense |
| `below_threshold` | Level belum mencapai ambang respons |
| `whitelisted` | Sumber dikecualikan oleh kebijakan whitelist |
| `disabled` | Auto-response mati |
| `stale_alert`, `invalid_timestamp` | Event terlalu lama atau waktunya tidak dapat dievaluasi |
| `integrity_alert`, `review_only` | Investigasi file/host/konteks; jangan menebak IP pelaku |
| `no_source_ip` | IP sumber tidak ada atau tidak valid untuk respons IPv4 |
| `block_failed` | Periksa audit dan koneksi pfSense sebelum mencoba ulang |

Untuk perubahan file, simpan bukti/hash, investigasi, pulihkan dari sumber tepercaya, lalu setujui baseline baru. Website Guard tidak menghapus malware atau memulihkan file otomatis.

## Mengelola Blocked IPs

Block manual membutuhkan IPv4 dan alasan. Unblock menghapus IP dari alias firewall dan mencatat riwayat; block ulang tersedia pada riwayat unblocked. Sinkronisasi membaca daftar alias. Menghapus riwayat unblocked tidak sama dengan unblock firewall. Periksa Audit Log ketika tindakan gagal.

Pemblokiran terjadi sesudah event. Untuk membuktikan penegakan, cocokkan alert, riwayat, alias `SOC_Blocklist`, dan percobaan koneksi baru melalui WAN pfSense. Status HTTP sebelumnya dan label dashboard saja tidak cukup.

## Inventaris dan Settings

Inventaris menampilkan Agent, paket, service, port, sumber log, dan FIM yang dilaporkan Wazuh. Pendaftaran/pemasangan Agent dilakukan pada target sesuai Panduan 02, bukan melalui CRUD dashboard.

Pada Settings, isi koneksi Manager API, Indexer, dan pfSense. Uji koneksi terlebih dahulu, periksa whitelist jaringan admin, lalu tentukan apakah auto-response perlu diaktifkan. Default instalasi: auto-response mati, level 10, polling 60 detik, usia maksimum 600 detik. Status scheduler menunjukkan hasil siklus terakhir.

Kredensial yang tidak ditampilkan ulang tetap tersimpan pada database lokal. Jangan membagikan database atau screenshot berisi rahasia. Demo sebaiknya tetap memakai konfigurasi kosong tanpa integrasi.

## Audit dan penghapusan alert

Audit mencatat tindakan, pelaksana, waktu, hasil, dan pesan kegagalan. Penghapusan alert hanya untuk admin: pilih rentang, pratinjau jumlah, masukkan password, lalu frasa `HAPUS ALERT WAZUH`. Proses ini menghapus data pada Indexer dan cache SOC sesuai rentang; simpan bukti penelitian terlebih dahulu. Riwayat blokir dan audit tetap ada. Ini berbeda dari membersihkan data demo.

## Mengakhiri sesi

Logout melalui profil. Untuk demo, hentikan masing-masing terminal dengan `Ctrl+C`. Untuk lab Ubuntu, jalankan `bash stop_soc.sh` dari direktori aplikasi. Menutup tab browser tidak menghentikan aplikasi atau scheduler. Instalasi lab belum memasang autostart SOC sesudah reboot.
