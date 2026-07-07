#!/bin/bash
# Re-records docs/assets/demo.gif from a real `farsight scan` run.
#
# Requires: asciinema (pip install asciinema), agg (brew install agg / see
# https://github.com/asciinema/agg)
#
# Usage: ./scripts/record_demo.sh [target-domain]

set -euo pipefail

TARGET="${1:-example.com}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CAST_FILE="$(mktemp -t farsight_demo.XXXXXX).cast"
OUT_GIF="${SCRIPT_DIR}/../docs/assets/demo.gif"
TYPE_SCRIPT="$(mktemp -t farsight_demo_type.XXXXXX).sh"

cat > "$TYPE_SCRIPT" <<INNER
#!/bin/bash
CMD='farsight scan ${TARGET} -m org -m recon --verbose --force'
clear
printf '\033[1;32m\$ \033[0m'
for ((i = 0; i < \${#CMD}; i++)); do
  printf '%s' "\${CMD:\$i:1}"
  sleep 0.02
done
printf '\n'
sleep 0.3
eval "\$CMD"
sleep 2
INNER
chmod +x "$TYPE_SCRIPT"

asciinema rec "$CAST_FILE" --command "$TYPE_SCRIPT" --overwrite --quiet
agg --speed 1.0 --theme monokai --font-size 16 "$CAST_FILE" "$OUT_GIF"

rm -f "$TYPE_SCRIPT" "$CAST_FILE"
echo "Wrote $OUT_GIF"
