#!/bin/bash
#
# Script quét mã độc cho WordPress
# Tự động nhận diện domain gốc, whitelist domain hợp pháp, báo cáo domain lạ
#

TARGET_DIR=${1:-.}
LOG_FILE="malware_scan_report_$(date +%F_%T).log"

echo "==== BẮT ĐẦU QUÉT MÃ ĐỘC TẠI: $TARGET_DIR ====" | tee -a "$LOG_FILE"
echo "Thời gian: $(date)" | tee -a "$LOG_FILE"
echo "=============================================" | tee -a "$LOG_FILE"

# ---------------------------------------------
# 1. Các mẫu code khả nghi (pattern)
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
  "stripos("
  "header("
  "iframe"
  "<script"
  "window.location"
  "document.write"
  "\\\\x[0-9a-fA-F]{2}"
)

echo "[+] Đang quét các mẫu mã độc..." | tee -a "$LOG_FILE"
for pattern in "${PATTERNS[@]}"; do
  echo "  -> Tìm: $pattern" | tee -a "$LOG_FILE"
  grep -Rni --include="*.php" --include="*.js" --include="*.html" --include=".htaccess" -E "$pattern" "$TARGET_DIR" >> "$LOG_FILE"
done

# ---------------------------------------------
# 2. Lấy domain gốc (REAL_DOMAIN)
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
# 3. Whitelist domain hợp pháp
# ---------------------------------------------
WHITELIST_DOMAINS=(
  # Core WordPress
  "wordpress.org"
  "api.wordpress.org"
  "downloads.wordpress.org"
  "s.w.org"
  "gravatar.com"
  "wp.com"
  "jetpack.com"

  # Google CDN
  "ajax.googleapis.com"
  "fonts.googleapis.com"
  "fonts.gstatic.com"
  "maps.googleapis.com"
  "maps.gstatic.com"

  # Cloudflare CDN
  "cdnjs.cloudflare.com"

  # JSDelivr
  "cdn.jsdelivr.net"

  # Bootstrap CDN
  "stackpath.bootstrapcdn.com"
  "maxcdn.bootstrapcdn.com"

  # jQuery CDN
  "code.jquery.com"

  # FontAwesome CDN
  "use.fontawesome.com"
  "kit.fontawesome.com"

  # Microsoft
  "ajax.aspnetcdn.com"
)

# ---------------------------------------------
# 4. Quét tất cả URL/link chèn
# ---------------------------------------------
echo "[+] Đang quét các URL/link khả nghi..." | tee -a "$LOG_FILE"

ALL_URLS=$(grep -Rho --include="*.php" --include="*.js" --include="*.html" --include=".htaccess" \
  -E "http[s]?://[a-zA-Z0-9./?=_-]*" "$TARGET_DIR" | sort -u)

if [ -n "$REAL_DOMAIN" ]; then
  echo "[+] Danh sách domain khả nghi (không khớp $REAL_DOMAIN và không nằm trong whitelist):" | tee -a "$LOG_FILE"
  echo "$ALL_URLS" | grep -v "$REAL_DOMAIN" | while read -r url; do
    safe=false
    for safe_domain in "${WHITELIST_DOMAINS[@]}"; do
      if echo "$url" | grep -q "$safe_domain"; then
        safe=true
        break
      fi
    done
    if [ "$safe" = false ]; then
      echo "$url" | tee -a "$LOG_FILE"
    fi
  done
else
  echo "[!] Không có domain gốc, chỉ hiển thị tất cả URL tìm thấy:" | tee -a "$LOG_FILE"
  echo "$ALL_URLS" | tee -a "$LOG_FILE"
fi

# ---------------------------------------------
# 5. Kiểm tra file bất thường
# ---------------------------------------------
echo "[+] Kiểm tra file PHP có quyền thực thi bất thường..." | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name "*.php" -perm /111 >> "$LOG_FILE"

echo "[+] File bị thay đổi trong 7 ngày qua:" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f \( -name "*.php" -o -name "*.html" -o -name ".htaccess" \) -mtime -7 >> "$LOG_FILE"

echo "[+] File ẩn đáng ngờ:" | tee -a "$LOG_FILE"
find "$TARGET_DIR" -type f -name ".*.php" -o -name ".*.html" -o -name ".htaccess" >> "$LOG_FILE"

# ---------------------------------------------
echo "=============================================" | tee -a "$LOG_FILE"
echo "✅ Quét hoàn tất. Xem kết quả tại: $LOG_FILE"
