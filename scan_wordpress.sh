#!/bin/bash

# Thư mục cần quét
TARGET_DIR=${1:-.}
LOG_FILE="malware_scan_report_$(date +%F_%T).log"

echo "==== BẮT ĐẦU QUÉT MÃ ĐỘC TẠI: $TARGET_DIR ====" | tee -a "$LOG_FILE"
echo "Thời gian: $(date)" | tee -a "$LOG_FILE"
echo "=============================================" | tee -a "$LOG_FILE"

# Danh sách các mẫu mã độc thường gặp
PATTERNS=(
  "eval("
  "base64_decode("
  "gzinflate("
  "shell_exec("
  "exec("
  "passthru("
  "system("
  "shell_exec\\("
  "proc_close\\("
  "assert("
  "str_rot13("
  "preg_replace(.*\/e)"
  "php:\/\/input"
  "php:\/\/shell"
  "@file_get_contents"
  "GOTo "
  "stripos("
  "header("
  ".html"
  "(str_rot13|base64_decode|urldecode)"
  "tempnam\("
  "fwrite\("
  "include\(.*tempnam"
  "@call_user_func"
)

echo "[+] Đang quét các mẫu mã độc thường gặp..." | tee -a "$LOG_FILE"
for pattern in "${PATTERNS[@]}"; do
  echo "  -> Tìm: $pattern" | tee -a "$LOG_FILE"
  grep -Rni --include="*.php" -E "$pattern" "$TARGET_DIR" >> "$LOG_FILE"
done

# Kiểm tra quyền thực thi bất thường
echo "[+] Kiểm tra các file PHP có quyền thực thi bất thường..." | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name "*.php" -perm /111 >> "$LOG_FILE"

# File PHP bị sửa trong 7 ngày
echo "[+] File PHP bị thay đổi trong 7 ngày gần đây:" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name "*.php" -mtime -7 >> "$LOG_FILE"

# File PHP ẩn (.) đáng nghi
echo "[+] File PHP ẩn đáng ngờ:" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name ".*.php" >> "$LOG_FILE"

echo "=============================================" | tee -a "$LOG_FILE"
echo "✅ Quét hoàn tất. Xem kết quả tại: $LOG_FILE"
