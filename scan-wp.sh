#!/bin/bash
# Script quét mã độc WordPress cơ bản
# Usage: bash scan-wp.sh /path/to/wordpress

TARGET_DIR=$1

if [ -z "$TARGET_DIR" ]; then
  echo "❌ Vui lòng nhập đường dẫn đến thư mục WordPress"
  echo "Ví dụ: bash $0 /home/user/public_html"
  exit 1
fi

echo "🔍 Đang quét thư mục: $TARGET_DIR"
echo "---------------------------------"

# 1. Tìm hàm PHP nguy hiểm thường bị chèn
echo "👉 Kiểm tra hàm nguy hiểm..."
grep -R --line-number --color=always -E "base64_decode|eval\(|gzinflate|shell_exec|system\(|passthru\(|exec\(" $TARGET_DIR

# 2. Liệt kê file PHP thay đổi trong 7 ngày gần đây
echo -e "\n👉 File PHP thay đổi trong 7 ngày gần đây:"
find $TARGET_DIR -type f -name "*.php" -mtime -7 -print

# 3. Kiểm tra file .htaccess có dòng lạ
if [ -f "$TARGET_DIR/.htaccess" ]; then
  echo -e "\n👉 Nội dung .htaccess:"
  grep -n --color=always "Rewrite|Redirect|base64" $TARGET_DIR/.htaccess
fi

# 4. Đếm số file PHP để phát hiện bất thường
echo -e "\n👉 Tổng số file PHP trong site:"
find $TARGET_DIR -type f -name "*.php" | wc -l

echo -e "\n✅ Quét xong! Hãy xem lại các dòng màu để phát hiện file khả nghi."
