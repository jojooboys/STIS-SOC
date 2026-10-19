#!/usr/bin/env bash
# Install Linux-only PoC telemetry on a Wazuh Agent host (for example STIS).
# Existing web monitoring stays untouched; repeated runs do not add duplicates.
set -euo pipefail

CONF='/var/ossec/etc/ossec.conf'
AUDIT_RULE='/etc/audit/rules.d/stis-soc-exec.rules'
PROCESS_COMMAND='ps -eo pid=,comm='

die() { printf '[GAGAL] %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die 'Jalankan sebagai root/sudo pada server target.'
[ -f "$CONF" ] || die "Wazuh Agent tidak ditemukan: $CONF"
command -v apt-get >/dev/null || die 'Skrip ini untuk Ubuntu/Debian.'

if ! command -v auditctl >/dev/null || ! command -v augenrules >/dev/null; then
    apt-get install -y auditd || die 'Gagal memasang auditd.'
fi
systemctl enable --now auditd

stamp="$(date +%Y%m%d-%H%M%S)"
cp -a -- "$CONF" "${CONF}.${stamp}.bak"
audit_rule_existed=false
if [ -e "$AUDIT_RULE" ]; then
    cp -a -- "$AUDIT_RULE" "${AUDIT_RULE}.${stamp}.bak"
    audit_rule_existed=true
fi
restore_audit_rule() {
    if [ "$audit_rule_existed" = true ]; then
        cp -a -- "${AUDIT_RULE}.${stamp}.bak" "$AUDIT_RULE"
    else
        rm -f -- "$AUDIT_RULE"
    fi
    augenrules --load || true
}

# Track human login sessions, including commands run through sudo. Kernel or
# service accounts (unset audit UID) are excluded to limit log volume.
# Reuse an existing Wazuh audit key if this host already collects execve.
existing_audit_rule=false
for active_rule in /etc/audit/rules.d/*.rules; do
    if [ -f "$active_rule" ] && grep -Fq 'audit-wazuh-c' "$active_rule"; then
        existing_audit_rule=true
        break
    fi
done
if [ "$existing_audit_rule" = false ]; then
cat > "$AUDIT_RULE" <<'EOF'
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k audit-wazuh-c
EOF
    chmod 0640 "$AUDIT_RULE"
elif [ "$audit_rule_existed" = false ]; then
    echo '[INFO] Aturan audit-wazuh-c sudah ada; aturan baru tidak ditambahkan.'
fi
# On some Ubuntu images auditd runs while kernel auditing remains disabled.
# augenrules moves the last -e directive to the end of the compiled rules.
if ! grep -Eq '^-e[[:space:]]+1[[:space:]]*$' "$AUDIT_RULE" 2>/dev/null; then
    printf '\n-e 1\n' >> "$AUDIT_RULE"
    chmod 0640 "$AUDIT_RULE"
fi
if ! augenrules --load; then
    restore_audit_rule
    die 'Audit rules tidak dapat dimuat; file aturan lama dipulihkan.'
fi
if ! auditctl -l | grep -Fq 'audit-wazuh-c'; then
    restore_audit_rule
    die 'Aturan execve belum aktif di kernel; periksa status Auditd.'
fi
if ! auditctl -s | grep -Eq '^enabled[[:space:]]+[12]$'; then
    restore_audit_rule
    die 'Auditd berjalan tetapi audit kernel belum aktif.'
fi

if ! python3 - "$CONF" "$PROCESS_COMMAND" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
command = sys.argv[2]
content = path.read_text()
blocks = list(re.finditer(r'<localfile>.*?</localfile>', content, re.S))
audit_blocks = [block for block in blocks if re.search(
    r'<location>\s*/var/log/audit/audit\.log\s*</location>', block.group())]
if len(audit_blocks) > 1:
    raise SystemExit('Ada beberapa blok koleksi audit.log; periksa manual agar tidak menduplikasi log.')

addition = ''
if audit_blocks:
    block = audit_blocks[0]
    updated = re.sub(r'<log_format>[^<]*</log_format>',
                     '<log_format>audit</log_format>', block.group(), count=1)
    if updated == block.group() and '<log_format>audit</log_format>' not in updated:
        updated = updated.replace('<localfile>',
                                  '<localfile>\n    <log_format>audit</log_format>', 1)
    content = content[:block.start()] + updated + content[block.end():]
else:
    addition += '''  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
'''

if f'<command>{command}</command>' not in content:
    addition += f'''  <localfile>
    <log_format>full_command</log_format>
    <command>{command}</command>
    <frequency>120</frequency>
  </localfile>
'''
if addition:
    content += f'\n<ossec_config>\n{addition}</ossec_config>\n'
path.write_text(content)
PY
then
    cp -a -- "${CONF}.${stamp}.bak" "$CONF"
    restore_audit_rule
    die 'Blok audit.log ambigu atau gagal diperbarui; konfigurasi lama dipulihkan.'
fi
if ! /var/ossec/bin/wazuh-agentd -t ||
   ! /var/ossec/bin/wazuh-logcollector -t ||
   ! /var/ossec/bin/wazuh-syscheckd -t; then
    cp -a -- "${CONF}.${stamp}.bak" "$CONF"
    restore_audit_rule
    die 'Validasi Agent gagal; ossec.conf dan aturan Auditd lama dipulihkan.'
fi
if ! systemctl restart wazuh-agent || ! systemctl is-active --quiet wazuh-agent; then
    cp -a -- "${CONF}.${stamp}.bak" "$CONF"
    restore_audit_rule
    systemctl restart wazuh-agent || true
    die 'Agent tidak aktif setelah restart; konfigurasi lama dipulihkan.'
fi

printf '[OK] Auditd dan koleksi perintah/proses aktif.\n'
printf 'Backup ossec.conf: %s\n' "${CONF}.${stamp}.bak"
printf 'Audit rule: %s\n' "$AUDIT_RULE"
if grep -A3 '<rootcheck>' "$CONF" | grep -Fq '<disabled>yes</disabled>'; then
    echo '[PERLU SETTING] Rootcheck dinonaktifkan pada Agent; lihat panduan PoC Linux.'
else
    echo '[CEK] Rootcheck tidak tampak dinonaktifkan; pastikan alert/scan nyata di Manager.'
fi
if grep -A3 '<wodle name="syscollector">' "$CONF" | grep -Fq '<disabled>yes</disabled>'; then
    echo '[PERLU SETTING] Syscollector dinonaktifkan; CVE tidak bisa diinvenarisasi.'
fi
