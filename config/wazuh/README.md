# Konfigurasi deteksi Wazuh

| Sumber repositori | Lokasi pemasangan pada Wazuh Manager |
| --- | --- |
| `rules/local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` |
| `decoders/local_decoder.xml` | `/var/ossec/etc/decoders/local_decoder.xml` |
| `lists/stis-known-bad` | `/var/ossec/etc/lists/stis-known-bad` |
| `lists/stis-suspicious-programs` | `/var/ossec/etc/lists/stis-suspicious-programs` |

Daftar IP bawaan adalah contoh sintetis. Operator harus meninjau setiap entri reputasi sebelum menggunakannya. Penempatan source berubah dari nama `.txt` menjadi XML, sedangkan lokasi konfigurasi aktif di VM tetap sama.

Ikuti [Panduan 01](../../docs/PANDUAN_01_INSTALASI_PFSENSE_WAZUH_DAN_STIS_SOC.md#7-memasang-decoder-dan-rule-wazuh). Skrip [prepare_manager.sh](../../scripts/testing/prepare_manager.sh) membuat backup dan memvalidasi konfigurasi sebelum restart; gunakan `SOC_SOURCE`/`SOC_TARGET` sesuai lokasi clone. Jangan menyalin file langsung dari Windows lalu menganggap Manager otomatis sudah diperbarui.

Validasi XML lokal hanya memeriksa struktur. `wazuh-analysisd -t` dan `wazuh-logtest` tetap harus dijalankan pada Manager untuk membuktikan aturan kompatibel dengan ruleset Wazuh yang terpasang.
