# Dataset publik STIS SOC

Repositori hanya menyertakan **12 baris data sintetis** pada [dummy/alerts.csv](dummy/alerts.csv). Dataset dibuat sepenuhnya dengan [generator](../scripts/generate_dummy_dataset.py), bukan diekspor dari database, log kampus, atau hasil pengujian nyata. Dataset ini dapat dibagikan untuk pembelajaran, demonstrasi, dan reproduksi contoh kebijakan proyek dengan mencantumkan sumber repositori.

Data operasional belum dinyatakan terbuka untuk publik. Karena itu `backend/instance/`, database SQLite, log, kredensial, dan folder `datasets/private/` dikecualikan dari Git. Ketentuan minimum lima baris dummy dipenuhi dengan 12 baris; data sensitif diwakili `USER_MASKED` dan `HOST_MASKED`. IP contoh menggunakan `192.0.2.x` dan `198.51.100.x`, hostname memakai `.example`, dan ID Agent memakai `DEMO-001`. Semuanya dibuat khusus untuk contoh.

## Kamus data

| Kolom | Tipe | Arti |
| --- | --- | --- |
| `alert_id` | string | ID kasus dummy unik |
| `rule_id` | integer | Referensi rule Wazuh; `999999` adalah kasus kategori tidak dikenal |
| `rule_level` | integer | Level alert input |
| `rule_groups` | JSON array dalam CSV | Kelompok ancaman input |
| `agent_id`, `agent_name` | string | Identitas Agent sintetis |
| `src_ip` | IPv4 atau kosong | IP sumber contoh; kosong berarti tidak diketahui |
| `dst_ip` | IPv4 | IP target contoh |
| `age_seconds` | integer | Usia relatif event saat pemuatan, bukan timestamp log asli |
| `rule_description` | string | Penanda skenario sintetis |
| `full_log` | string | Log ilustrasi dengan akun/host yang dimasking |
| `expected_threat` | string | Label kategori yang diharapkan |
| `expected_action` | string | Label keputusan respons yang diharapkan |

Label disusun manual dari spesifikasi kebijakan: block, di bawah ambang, investigasi integritas, whitelist, sumber IP tidak ada, event kedaluwarsa, dan review operator. Ambang evaluasi 10, usia maksimum 600 detik, whitelist `127.0.0.1,192.0.2.254`; konfigurasi ini khusus evaluasi dan tidak mengganti whitelist lab aplikasi.

## Reproduksi

Jalankan dari root proyek pada lingkungan Python dengan dependensi backend:

```bash
python scripts/generate_dummy_dataset.py
python modelling/evaluate_response.py --output reports/evaluation.json
```

Generator menimpa hanya CSV dummy. Timestamp untuk evaluasi dibuat dari waktu pemuatan dikurangi `age_seconds`, sehingga contoh tidak otomatis menjadi kedaluwarsa setelah repositori lama disimpan. Data CSV asli tetap deterministik.

Hasil evaluasi menunjukkan kesesuaian implementasi dengan label contoh. Data ini tidak mewakili distribusi trafik nyata, hasil eksperimen skripsi, performa deteksi end-to-end Wazuh, atau keberhasilan pemblokiran pfSense. Jangan memakai metrik dummy sebagai hasil penelitian.

Untuk publikasi data penelitian kelak, tentukan izin sumber terlebih dahulu, hapus payload/kredensial/identitas, samarkan IP dan hostname secara konsisten, lalu tinjau seluruh field termasuk log mentah. Data yang belum mendapat izin tetap berada di luar Git.
