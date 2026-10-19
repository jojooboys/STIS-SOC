# Indeks dokumentasi

Mulai dari [README proyek](../README.md) untuk identitas, struktur, instalasi cepat, dan cakupan penelitian.

| Keperluan | Dokumen |
| --- | --- |
| Arsitektur, alur kode, API, basis data, batas sistem | [Dokumentasi sistem](../STIS_SOC.md) |
| Menggunakan dashboard sehari-hari | [Panduan penggunaan](PANDUAN_PENGGUNAAN.md) |
| Instalasi VM pfSense, Wazuh, target, dan SOC | [Panduan 01](PANDUAN_01_INSTALASI_PFSENSE_WAZUH_DAN_STIS_SOC.md) |
| Menambah server, website, atau layanan | [Panduan 02](PANDUAN_02_TAMBAH_SERVER_WEBSITE_DAN_SERVICE.md) |
| Melepas satu target dari monitoring | [Panduan 03](PANDUAN_03_PENSIUNKAN_SERVER_WEBSITE_DAN_SERVICE.md) |
| Membongkar seluruh lab | [Panduan 04](PANDUAN_04_BONGKAR_LAB_STIS_SOC.md) |
| Uji target nyata dan demo | [Panduan 05](PANDUAN_05_UJI_FUNGSIONAL_TARGET_NYATA_DAN_DEMO.md) |
| Model berbasis aturan dan evaluator | [Pemodelan](../modelling/README.md) |
| Asal, masking, dan kamus data | [Dataset](../datasets/README.md) |

Panduan VM memakai contoh lab: source instalasi `/root`, shared folder `/media/sf_VM-Share`, target `10.10.10.30`, dan host-only `192.168.1.10`. Alamat tersebut adalah contoh topologi, bukan daftar host kampus yang dipublikasikan. Jika memakai clone di direktori lain, sesuaikan path. `cleanup_ubuntu.sh` khusus layout `/root`; jangan menjalankannya untuk menghapus clone di lokasi lain.

Pengujian kode lokal dan pengujian integrasi pada VM merupakan pemeriksaan terpisah. Ikuti Panduan 05 untuk verifikasi alur dari target melalui Wazuh dan SOC hingga pfSense.
