# Pemodelan deteksi dan respons

Penelitian ini menggunakan **pemodelan berbasis aturan**. Tidak ada training machine learning atau bobot model dalam implementasi. Model ORM pada `backend/app/models/` adalah skema basis data; model deteksi/keputusan berada pada file berikut.

| Tahap | Implementasi | Masukan dan keluaran |
| --- | --- | --- |
| Decoder | [local_decoder.xml](../config/wazuh/decoders/local_decoder.xml) | Log aplikasi menjadi field akun/IP |
| Deteksi/korelasi | [local_rules.xml](../config/wazuh/rules/local_rules.xml) | Event menjadi alert berdasarkan pola, level, frequency, timeframe |
| Indikator CDB | [lists](../config/wazuh/lists/) | IP reputasi contoh dan nama utilitas untuk ditinjau |
| Integritas/konten | [website_guard.py](../website_guard/website_guard.py) | Hash baseline dan pola konten menjadi temuan file |
| Klasifikasi | [threats.py](../backend/app/utils/threats.py) | ID rule, kelompok, dan deskripsi menjadi kategori ancaman |
| Kelayakan respons | [response_engine.py](../backend/app/services/response_engine.py) | Alert dan kebijakan menjadi block/review/pengecualian |
| Evaluasi offline | [evaluate_response.py](evaluate_response.py) | CSV berlabel menjadi kesesuaian kategori/aksi dan confusion matrix |

## Aturan keputusan

`ResponseEngine.evaluate_threat` memeriksa secara berurutan: auto-response aktif, level memenuhi ambang, jenis ancaman layak diblokir, IPv4 sumber valid, sumber di luar whitelist, timestamp valid, dan usia alert dalam batas. Temuan perubahan file diarahkan untuk investigasi. Catatan IP yang sudah diblokir dapat menghasilkan `reinforce_block`. Eksekusi API firewall dilakukan terpisah dari evaluasi kelayakan.

Parameter korelasi Wazuh berada di XML, parameter respons aplikasi berada di Settings, dan pola Website Guard berada di `CONTENT_PATTERNS`. Perubahan parameter perlu dicatat bersama versi source ketika penelitian dilakukan.

## Menjalankan evaluasi

Setelah memasang `backend/requirements.txt`, jalankan dari root:

```bash
python modelling/evaluate_response.py
python modelling/evaluate_response.py --dataset datasets/dummy/alerts.csv --output reports/evaluation.json
```

Evaluator menjalankan fungsi keputusan aplikasi yang sama dengan dashboard, memakai SQLite memory, tanpa scheduler dan dengan HTTP dinonaktifkan. Ia tidak menjalankan `process_alerts`/`execute_block`, tidak mengubah database lab, dan tidak memanggil firewall.

Confusion matrix menggunakan kelas positif **layak diblokir menurut label kebijakan**: TP = label block dan keputusan block; FP = label selain block tetapi keputusan block; FN = label block tetapi keputusan selain block; TN = keduanya selain block. Precision = TP/(TP+FP), recall = TP/(TP+FN), dan F1 = 2TP/(2TP+FP+FN); pembagi nol ditulis `null`. Ini bukan confusion matrix keberhasilan deteksi serangan dari request jaringan.

Program keluar dengan status 1 jika kategori atau aksi tidak sesuai label, sehingga bisa dipakai dalam pemeriksaan otomatis. Dataset dummy hanya untuk reproduksi contoh. Evaluasi pada lab memerlukan trafik berlabel, request kontrol sah, bukti alert Manager, alias firewall, koneksi baru, serta timestamp latensi; prosedurnya tersedia di [panduan pengujian](../docs/PANDUAN_05_UJI_FUNGSIONAL_TARGET_NYATA_DAN_DEMO.md).
