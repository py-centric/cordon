#!/usr/bin/env bash
set -euo pipefail

# Enforce PyCentric GL-01 <= 400-line module size cap across src/ and tests/.
max_lines=400
failed=0

while IFS= read -r -d '' file; do
    lines=$(wc -l < "$file")
    if (( lines > max_lines )); then
        echo "ERROR: $file has $lines lines (max $max_lines)" >&2
        failed=1
    fi
done < <(find src tests -type f -name '*.rs' -print0)

if (( failed != 0 )); then
    exit 1
fi

echo "check-file-size: OK (all Rust modules <= $max_lines lines)"
