#!/bin/bash

# ==============================
# Script quét mã độc cho WordPress
# ==============================

TARGET_DIR=${1:-.}
LOG_FILE="malware_scan_report_$(date +%F_%T).log"

echo "==== BẮT ĐẦU QUÉT MÃ ĐỘC TẠI: $TARGET_DIR ====" | tee -a "$LOG_FILE"
echo "Thời gian: $(date)" | tee -a "$LOG_FILE"
echo "=============================================" | tee -a "$LOG_FILE"

# ---------------------------------------------
# 1. Quét các mẫu mã độc phổ biến
# ---------------------------------------------
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
  "\\\\x[0-9a-fA-F]{2}"  # mã hóa hexa đáng ngờ
)

echo "[+] Đang quét các mẫu mã độc..." | tee -a "$LOG_FILE"
for pattern in "${PATTERNS[@]}"; do
  echo "  -> Tìm: $pattern" | tee -a "$LOG_FILE"
  grep -Rni --include="*.php" -E "$pattern" "$TARGET_DIR" >> "$LOG_FILE"
done

# ---------------------------------------------
# 2. Tìm domain gốc (REAL_DOMAIN)
# ---------------------------------------------
REAL_DOMAIN=$(grep -E "WP_HOME|WP_SITEURL" "$TARGET_DIR/wp-config.php" 2>/dev/null \
  | sed -E "s/.*'(https?:\/\/)?([^'\/]+).*/\2/" \
  | head -n1)

if [ -z "$REAL_DOMAIN" ]; then
  DB_NAME=$(grep DB_NAME "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")
  DB_USER=$(grep DB_USER "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")
  DB_PASSWORD=$(grep DB_PASSWORD "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")
  DB_HOST=$(grep DB_HOST "$TARGET_DIR/wp-config.php" | sed -E "s/.*'(.+)'.*/\1/")

  if [ -n "$DB_NAME" ] && [ -n "$DB_USER" ] && [ -n "$DB_PASSWORD" ]; then
    REAL_DOMAIN=$(mysql -N -u"$DB_USER" -p"$DB_PASSWORD" -h"$DB_HOST" "$DB_NAME" \
      -e "SELECT option_value FROM wp_options WHERE option_name='siteurl' LIMIT 1;" 2>/dev/null \
      | sed -E "s#https?://([^/]+).*#\1#")
  fi
fi

if [ -z "$REAL_DOMAIN" ]; then
  echo "[!] Không tìm thấy domain gốc trong wp-config.php hoặc database. Bạn cần nhập thủ công." | tee -a "$LOG_FILE"
else
  echo "[+] Domain gốc phát hiện: $REAL_DOMAIN" | tee -a "$LOG_FILE"
fi

# ---------------------------------------------
# 3. Quét tất cả URL/link chèn
# ---------------------------------------------
echo "[+] Đang quét các URL/link khả nghi..." | tee -a "$LOG_FILE"
grep -Rni --include="*.php" --include="*.js" --include="*.html" -E "http[s]?://[a-zA-Z0-9./?=_-]*" "$TARGET_DIR" >> "$LOG_FILE"

if [ -n "$REAL_DOMAIN" ]; then
  echo "[+] Danh sách domain khả nghi (không khớp $REAL_DOMAIN):" | tee -a "$LOG_FILE"
  grep -Rho --include="*.php" --include="*.js" --include="*.html" -E "http[s]?://[a-zA-Z0-9./?=_-]*" "$TARGET_DIR" \
    | sort -u \
    | grep -v "$REAL_DOMAIN" \
    | tee -a "$LOG_FILE"
fi

# ---------------------------------------------
# 4. Một số kiểm tra bổ sung
# ---------------------------------------------
echo "[+] Kiểm tra file PHP có quyền thực thi bất thường..." | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name "*.php" -perm /111 >> "$LOG_FILE"

echo "[+] File PHP bị thay đổi trong 7 ngày qua:" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name "*.php" -mtime -7 >> "$LOG_FILE"

echo "[+] File PHP ẩn đáng ngờ:" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name ".*.php" >> "$LOG_FILE"

# ---------------------------------------------
echo "=============================================" | tee -a "$LOG_FILE"
echo "✅ Quét hoàn tất. Xem kết quả tại: $LOG_FILE"
