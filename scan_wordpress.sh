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
  "assert("
  "str_rot13("
  "preg_replace(.*\/e)"
  "php:\/\/input"
  "php:\/\/shell"
  "@file_get_contents"
  "GOTo "
  "stripos("
  "header("
  "\\\\x[0-9a-fA-F]{2}"  # Mã hóa hexa đáng ngờ
  "(str_rot13|base64_decode|urldecode)"
  "tempnam\("
  "fwrite\("
  "include\(.*tempnam"
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

# Tìm domain gốc từ wp-config.php
REAL_DOMAIN=$(grep -E "WP_HOME|WP_SITEURL" "$TARGET_DIR/wp-config.php" 2>/dev/null \
  | sed -E "s/.*'(https?:\/\/)?([^'\/]+).*/\2/" \
  | head -n1)

# Nếu không có trong wp-config.php -> lấy từ database
if [ -z "$REAL_DOMAIN" ]; then
  DB_NAME=$(grep DB_NAME "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")
  DB_USER=$(grep DB_USER "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")
  DB_PASSWORD=$(grep DB_PASSWORD "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")
  DB_HOST=$(grep DB_HOST "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")

  REAL_DOMAIN=$(mysql -N -u"$DB_USER" -p"$DB_PASSWORD" -h"$DB_HOST" "$DB_NAME" \
    -e "SELECT option_value FROM wp_options WHERE option_name='siteurl' LIMIT 1;" \
    | sed -E "s#https?://([^/]+).*#\1#")
fi

if [ -z "$REAL_DOMAIN" ]; then
  echo "[!] Không tìm thấy domain gốc trong wp-config.php hoặc database. Bạn cần nhập thủ công." | tee -a "$LOG_FILE"
else
  echo "[+] Domain gốc phát hiện: $REAL_DOMAIN" | tee -a "$LOG_FILE"
fi


echo "=============================================" | tee -a "$LOG_FILE"
echo "✅ Quét hoàn tất. Xem kết quả tại: $LOG_FILE"
