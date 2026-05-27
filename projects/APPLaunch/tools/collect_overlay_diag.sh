#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-pi.local}"
USER="${2:-pi}"
PASS="${3:-pi}"
OUT_DIR="${4:-overlay-diag-$(date +%Y%m%d-%H%M%S)}"

mkdir -p "$OUT_DIR"

if command -v sshpass >/dev/null 2>&1; then
  SSH_CMD=(sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${USER}@${HOST}")
else
  SSH_CMD=(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "${USER}@${HOST}")
fi

run_remote() {
  local name="$1"
  local cmd="$2"
  local out_file="$OUT_DIR/${name}.txt"
  {
    echo "# ${name}"
    echo "# host=${HOST} user=${USER}"
    echo "# cmd=${cmd}"
    echo
    "${SSH_CMD[@]}" "$cmd"
  } >"$out_file" 2>&1 || true
}

run_remote "00_basic" "date; uname -a; id; hostname"

run_remote "01_boot_config" "for f in /boot/firmware/config.txt /boot/config.txt; do if [ -f \"\$f\" ]; then echo \"=== \$f ===\"; grep -nE '^(dtoverlay|dtparam)' \"\$f\" || true; echo; fi; done"

run_remote "02_runtime_overlays" "if command -v dtoverlay >/dev/null 2>&1; then dtoverlay -l || true; else echo 'dtoverlay not found'; fi"

run_remote "03_spi_devices" "ls -l /sys/bus/spi/devices/ 2>/dev/null || true; echo; for d in /sys/bus/spi/devices/spi*; do [ -e \"\$d\" ] || continue; echo \"==== \$d ====\"; echo -n 'modalias: '; cat \"\$d/modalias\" 2>/dev/null || true; echo -n 'driver: '; readlink \"\$d/driver\" 2>/dev/null || echo 'no driver'; echo; done"

run_remote "04_spidev_nodes" "ls -l /dev/spidev* 2>/dev/null || true"

run_remote "05_live_spi0_dts" "if command -v dtc >/dev/null 2>&1; then dtc -I fs -O dts /proc/device-tree 2>/dev/null | awk '/spi@7e204000[[:space:]]*\\{/ {in_node=1; depth=0} in_node { print; depth += gsub(/\\{/, "{"); depth -= gsub(/\\}/, "}"); if (depth == 0) exit }' | sed -n '1,260p'; else echo 'dtc not found'; fi"

run_remote "06_overlay_spi_summary" "if ! command -v dtc >/dev/null 2>&1; then echo 'dtc not found'; exit 0; fi; overlays=\$(grep -hE '^[[:space:]]*dtoverlay=' /boot/firmware/config.txt /boot/config.txt 2>/dev/null | sed 's/^[[:space:]]*dtoverlay=//' | sed 's/[,:].*$//' | sort -u); for ov in \$overlays; do for base in /boot/firmware/overlays /boot/overlays; do p=\"\$base/\$ov.dtbo\"; [ -f \"\$p\" ] || continue; echo \"=== \$p ===\"; dtc -I dtb -O dts \"\$p\" 2>/dev/null | grep -nE 'fragment@|spi@7e204000|st7789|spidev@0|spidev@1|panel-mipi-dbi-spi|reg = <0x00>|reg = <0x01>|status = ' || true; echo; done; done"

run_remote "07_display_stack" "cat /proc/fb 2>/dev/null || true; echo; ls -l /dev/fb* /dev/dri/card* 2>/dev/null || true"

run_remote "08_kernel_modules" "lsmod | egrep -i 'spi|st7789|panel|drm|fbtft' || true"

run_remote "09_gpio_pinctrl" "if command -v pinctrl >/dev/null 2>&1; then for p in 5 7 8 9 10 11 22 23 25 26; do pinctrl get \$p || true; done; else echo 'pinctrl not found'; fi"

{
  echo "Overlay diagnostics collected."
  echo "Output directory: $OUT_DIR"
  echo
  echo "Files:"
  ls -1 "$OUT_DIR" | sed 's/^/- /'
} >"$OUT_DIR/README.txt"

printf 'Done. Report directory: %s\n' "$OUT_DIR"
