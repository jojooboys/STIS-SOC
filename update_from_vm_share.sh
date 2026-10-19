#!/usr/bin/env bash
# Sinkronkan source STIS SOC dari VirtualBox shared folder ke instalasi Ubuntu.
# Pemakaian: bash /media/sf_VM-Share/update_from_vm_share.sh /root

set -uo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-}"

if [ -z "$TARGET_DIR" ]; then
    echo "Pemakaian: bash $0 /lokasi/instalasi"
    echo "Contoh untuk instalasi saat ini: bash $0 /root"
    exit 2
fi

TARGET_DIR="$(cd "$TARGET_DIR" 2>/dev/null && pwd)" || {
    echo "Folder tujuan tidak ditemukan: $TARGET_DIR"
    exit 2
}

if [ "$SOURCE_DIR" = "$TARGET_DIR" ]; then
    echo 'Folder sumber dan tujuan harus berbeda; sinkronisasi ke folder sendiri dibatalkan.' >&2
    exit 2
fi

if [ ! -f "$SOURCE_DIR/backend/check_wazuh.py" ] || [ ! -f "$SOURCE_DIR/frontend/src/App.jsx" ]; then
    echo "Sumber bukan folder kode SOC yang lengkap: $SOURCE_DIR"
    exit 2
fi

if [ ! -x "$TARGET_DIR/backend/venv/bin/python" ] || [ ! -f "$TARGET_DIR/start_soc.sh" ]; then
    echo "Tujuan bukan instalasi SOC Ubuntu yang sudah siap: $TARGET_DIR"
    exit 2
fi

if ! command -v rsync >/dev/null 2>&1; then
    echo "rsync belum tersedia. Jalankan sekali: sudo apt install rsync"
    exit 2
fi

if [ ! -f "$SOURCE_DIR/frontend/package-lock.json" ]; then
    echo 'frontend/package-lock.json tidak ditemukan; dependensi frontend tidak dapat disinkronkan secara konsisten.' >&2
    exit 2
fi

# Compare dependency manifests before rsync replaces the installed copies.
BACKEND_DEPS_CHANGED=false
if ! cmp -s -- "$SOURCE_DIR/backend/requirements.txt" "$TARGET_DIR/backend/requirements.txt" ||
   ! cmp -s -- "$SOURCE_DIR/backend/requirements-lock.txt" "$TARGET_DIR/backend/requirements-lock.txt"; then
    BACKEND_DEPS_CHANGED=true
fi
FRONTEND_DEPS_CHANGED=false
if ! cmp -s -- "$SOURCE_DIR/frontend/package.json" "$TARGET_DIR/frontend/package.json" ||
   ! cmp -s -- "$SOURCE_DIR/frontend/package-lock.json" "$TARGET_DIR/frontend/package-lock.json" ||
   [ ! -d "$TARGET_DIR/frontend/node_modules" ] ||
   ! (cd "$TARGET_DIR/frontend" && npm ls --depth=0 --silent >/dev/null 2>&1); then
    FRONTEND_DEPS_CHANGED=true
fi

echo "Sumber : $SOURCE_DIR"
echo "Tujuan: $TARGET_DIR"
echo "Menyinkronkan kode sambil mempertahankan database dan konfigurasi..."

RSYNC_ARGS=(
    -rcv --itemize-changes
    --exclude='.git/'
    --exclude='.agents/'
    --exclude='.codex/'
    --exclude='catatan_pribadi/'
    --exclude='reports/'
    --exclude='venv/'
    --exclude='.venv/'
    --exclude='node_modules/'
    --exclude='__pycache__/'
    --exclude='*.pyc'
    --exclude='instance/'
    --exclude='*.db*'
    --exclude='*.sqlite*'
    --exclude='.env'
    --include='.env.example'
    --exclude='.env.*'
    --exclude='*.log'
    --exclude='*.pid'
    --exclude='dist/'
    --exclude='*.tar.gz'
)

if ! rsync "${RSYNC_ARGS[@]}" "$SOURCE_DIR/" "$TARGET_DIR/"; then
    echo "Sinkronisasi gagal; aplikasi tidak direstart."
    exit 1
fi

# Keep the existing venv and installed frontend packages in step with the
# copied manifests. A failed install stops before restarting the SOC.
if [ "$BACKEND_DEPS_CHANGED" = true ]; then
    echo 'requirements.txt berubah; memperbarui dependensi backend...'
    "$TARGET_DIR/backend/venv/bin/python" -m pip install -r "$TARGET_DIR/backend/requirements.txt" || {
        echo 'Dependensi backend gagal dipasang; SOC tidak direstart.' >&2
        exit 1
    }
else
    echo 'Dependensi backend tidak berubah; venv yang sudah ada dipertahankan.'
fi
if [ "$FRONTEND_DEPS_CHANGED" = true ]; then
    echo 'Dependensi frontend berubah atau tidak lengkap; menjalankan npm ci...'
    (cd "$TARGET_DIR/frontend" && npm ci) || {
        echo 'Dependensi frontend gagal dipasang; SOC tidak direstart.' >&2
        exit 1
    }
fi
if ! (cd "$TARGET_DIR/frontend" && npm run build); then
    echo 'Build frontend gagal; SOC tidak direstart. Periksa kesalahan JavaScript di atas.' >&2
    exit 1
fi

# Hapus nama dokumentasi lama yang sudah dikonsolidasikan ke satu panduan.
# Daftar eksplisit ini menjaga file lain di docs tetap aman walaupun rsync
# sengaja dijalankan tanpa opsi --delete.
LEGACY_DOCS=(
    'PANDUAN_LENGKAP_STIS_SOC.md'
    'PANDUAN_AGENT_DAN_TARGET_MONITORING.md'
    'PANDUAN_UNINSTALL_TARGET_MONITORING.md'
    'PANDUAN_03_HAPUS_SERVER_WEBSITE_DAN_SERVICE.md'
    'PANDUAN_UNINSTALL_KESELURUHAN.md'
    'PANDUAN_UJI_FUNGSIONAL_SERANGAN.md'
    'OUTLINE_PRESENTASI_CARA_KERJA_STIS_SOC.md'
    'PANDUAN_LENGKAP_MINI_SOC.md'
    'PANDUAN_OPERASIONAL_UJI_DAN_PEMBERSIHAN.md'
    'DIAGNOSIS_LOGIN_DAN_WAZUH.md'
    'INSTALLATION.md'
    'PANDUAN_IP_KLIEN_HAPROXY_WAZUH.md'
    'PANDUAN_KONEKSI_PFSENSE_SOC.md'
    'PANDUAN_KONFIGURASI_MANUAL_LAB.md'
    'PANDUAN_MIGRASI_DAN_LAUNCHING_UBUNTU.md'
    'PANDUAN_PERLINDUNGAN_WEB_DEFACEMENT.md'
    'PANDUAN_SQL_INJECTION.md'
    'PANDUAN_TOPOLOGI_DAN_SHARED_FOLDER.md'
    'PENYESUAIAN_LAB_WAZUH_PFSENSE.md'
    'TESTING.md'
    'TUTORIAL_PREVIEW.md'
    'UBUNTU_VIRTUALBOX_DEPLOYMENT.md'
    'UPDATE_VIA_VM_SHARE.md'
)

for legacy_doc in "${LEGACY_DOCS[@]}"; do
    rm -f -- "$TARGET_DIR/docs/$legacy_doc"
done

# rsync intentionally keeps installed data and does not use --delete. Remove
# only the two obsolete CRUD source files so stale tests/services cannot run
# after this read-only inventory update. Neither file contains user data.
rm -f -- "$TARGET_DIR/backend/app/services/asset_service.py"
rm -f -- "$TARGET_DIR/backend/tests/test_asset_onboarding.py"

cd "$TARGET_DIR"
if ! bash stop_soc.sh; then
    echo 'SOC belum berhenti sepenuhnya; pembaruan source sudah tersalin, tetapi start dibatalkan.' >&2
    exit 1
fi
if ! bash start_soc.sh; then
    echo 'SOC gagal dijalankan; periksa backend.log, frontend.log, dan port 5000/5173.' >&2
    exit 1
fi

echo "Update selesai. Verifikasi diagnostik Wazuh dengan:"
echo "cd $TARGET_DIR/backend && venv/bin/python check_wazuh.py"
echo "Verifikasi diagnostik pfSense dengan:"
echo "cd $TARGET_DIR/backend && venv/bin/python check_pfsense.py"
echo "Verifikasi auto-response dengan:"
echo "cd $TARGET_DIR/backend && venv/bin/python check_auto_response.py"
echo "Verifikasi deteksi SQL Injection dengan:"
echo "cd $TARGET_DIR/backend && venv/bin/python check_sqli.py"
echo "Verifikasi deteksi Web Defacement dengan:"
echo "cd $TARGET_DIR/backend && venv/bin/python check_defacement.py"
echo "Setelah rule Wazuh diperbarui, validasi matriks deteksi dengan:"
echo "cd $TARGET_DIR/backend && venv/bin/python check_attack_matrix.py"
