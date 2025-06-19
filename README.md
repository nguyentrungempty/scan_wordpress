#!/bin/bash

# Thư mục chứa mã nguồn WordPress (mặc định là thư mục hiện tại)
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
  "assert("
  "str_rot13("
  "preg_replace(.*\/e)"
  "php:\/\/input"
  "php:\/\/shell"
)

# Quét các file nghi ngờ chứa mã độc
echo "[+] Đang quét mã độc tiềm ẩn..." | tee -a "$LOG_FILE"
for pattern in "${PATTERNS[@]}"; do
  echo "  -> Tìm kiếm mẫu: $pattern" | tee -a "$LOG_FILE"
  grep -Rni --include="*.php" --include="*.inc" --include="*.phtml" "$pattern" "$TARGET_DIR" >> "$LOG_FILE"
done

# Kiểm tra quyền thực thi bất thường
echo "[+] Kiểm tra các file PHP có quyền thực thi..." | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name "*.php" -perm /111 >> "$LOG_FILE"

# Tìm file bị thay đổi gần đây (7 ngày)
echo "[+] Kiểm tra file bị thay đổi gần đây (7 ngày):" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name "*.php" -mtime -7 >> "$LOG_FILE"

# Tìm file ẩn đáng nghi (bắt đầu bằng .)
echo "[+] Tìm file PHP ẩn:" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name ".*.php" >> "$LOG_FILE"

echo "=============================================" | tee -a "$LOG_FILE"
echo "✅ Quét hoàn tất. Kiểm tra file báo cáo: $LOG_FILE"
