#!/bin/sh
# The embedder's model (server/src/embed.rs): bge-small-en-v1.5, int8 ONNX export, and its tokenizer, downloaded from
# Hugging Face at pinned revisions and checked against pinned SHA-256s. A file that doesn't match is deleted and the
# script fails, so nothing unpinned is ever kept. The image runs this at build time (Dockerfile); CI and local tests run
# it once to a cache outside the repo. Nothing downloads at run time.
#
#   scripts/fetch-model.sh [dir]     default: ${XDG_CACHE_HOME:-$HOME/.cache}/msp-console/models/bge-small-en-v1.5-int8
#
# The pins are also in server/src/embed.rs (FILES), and a test holds the two to each other. To change model, change
# both, and MODEL_KEY with them.
set -eu

dir="${1:-${XDG_CACHE_HOME:-$HOME/.cache}/msp-console/models/bge-small-en-v1.5-int8}"

# One pin a line: name|url (at a pinned revision)|sha256.
# model.onnx: Xenova's int8 export (onnx/model_quantized.onnx) of BAAI's model, revision ea104dac; its fp32 export there
# is byte for byte BAAI's own onnx/model.onnx. tokenizer.json: BAAI's own, revision 5c38ec7c.
pins() {
  cat <<'PINS'
model.onnx|https://huggingface.co/Xenova/bge-small-en-v1.5/resolve/ea104dacec62c0de699686887e3f920caeb4f3e3/onnx/model_quantized.onnx|6c9c6101a956d62dfb5e7190c538226c0c5bb9cb27b651234b6df063ee7dbfe4
tokenizer.json|https://huggingface.co/BAAI/bge-small-en-v1.5/resolve/5c38ec7c405ec4b44b94cc5a9bb96e735b38267a/tokenizer.json|d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66
PINS
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

mkdir -p "$dir"
pins | while IFS='|' read -r name url want; do
  if [ -f "$dir/$name" ] && [ "$(sha256 "$dir/$name")" = "$want" ]; then echo "$name: already there, $want"; continue; fi
  tmp="$dir/.$name.part"
  rm -f "$tmp"
  curl --fail --silent --show-error --location --proto '=https' --retry 3 --output "$tmp" "$url"
  got="$(sha256 "$tmp")"
  if [ "$got" != "$want" ]; then
    rm -f "$tmp"
    echo "$name: SHA-256 $got, expected $want: refused" >&2
    exit 1
  fi
  mv "$tmp" "$dir/$name"
  echo "$name: $want"
done
echo "model in $dir"
