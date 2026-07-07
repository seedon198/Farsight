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

# Force a true-black background: agg's named themes (monokai, dracula, etc.)
# are all dark *gray*, not black. None of agg's built-in --theme values
# render pure #000000, so embed a custom theme directly in the cast
# header instead - agg picks up an embedded theme automatically when no
# --theme flag is passed.
python3 - "$CAST_FILE" <<'PYEOF'
import json, sys
path = sys.argv[1]
with open(path) as f:
    lines = f.readlines()
header = json.loads(lines[0])
header["theme"] = {
    "fg": "#e6e6e6",
    "bg": "#000000",
    "palette": "#000000:#dd3c69:#4ebf22:#d5971d:#268bd2:#9c36b6:#00a8c6:#e6e6e6:"
    "#666666:#f2777a:#a6e22e:#f4bf75:#5299d1:#c790e4:#66d9ef:#ffffff",
}
with open(path, "w") as f:
    f.write(json.dumps(header) + "\n")
    f.writelines(lines[1:])
PYEOF

agg --speed 1.0 --font-size 16 "$CAST_FILE" "$OUT_GIF"

rm -f "$TYPE_SCRIPT" "$CAST_FILE"
echo "Wrote $OUT_GIF"
