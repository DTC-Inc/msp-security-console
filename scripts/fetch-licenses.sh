#!/bin/sh
# The licences and notices of what the image carries beyond the console's own code (THIRD_PARTY.md): ONNX Runtime,
# linked into the binary, with the notices of the third-party code inside it; the embedding model; and the tokenizer
# library. Each is downloaded at a pinned commit and checked against a pinned SHA-256. A file that doesn't match is
# deleted and the script fails, so the image build fails. The Dockerfile runs this into /licenses.
#
#   scripts/fetch-licenses.sh <dir>
#
# When ort moves to another ONNX Runtime release, pin that release's commit here (ort-sys's build/download/dist.tsv
# names the version it downloads: ms@1.31.0 today).
set -eu

dir="${1:?usage: scripts/fetch-licenses.sh <dir>}"

# One pin a line: path under <dir>|url (at a pinned commit)|sha256.
# onnxruntime: microsoft/onnxruntime tag v1.31.0 (commit 402979ac), the release ort-sys links.
# bge-small-en-v1.5: FlagOpen/FlagEmbedding's LICENSE (commit 897baa67), the licence the model card names (MIT).
# tokenizers: huggingface/tokenizers tag v0.22.2 (commit f383101a), the crate compiled in (Apache-2.0).
# kleidiai: ARM-software/kleidiai tag v1.30.0 (commit 74b1a12d), the version ONNX Runtime 1.31's cmake/deps.txt names;
#   pyke's arm64 archive links it (its kai_ symbols are in libonnxruntime.a), the x86_64 one doesn't use it.
pins() {
  cat <<'PINS'
onnxruntime/LICENSE|https://raw.githubusercontent.com/microsoft/onnxruntime/402979ac1bef89dcd55add41eaa7277c407599eb/LICENSE|2f07c72751aed99790b8a4869cf2311df85a860b22ded05fa22803587a48922c
onnxruntime/ThirdPartyNotices.txt|https://raw.githubusercontent.com/microsoft/onnxruntime/402979ac1bef89dcd55add41eaa7277c407599eb/ThirdPartyNotices.txt|143764b952fdb1a7c69ce653bfba74a7744d6a8a573bfb73e235fba356c83de3
bge-small-en-v1.5/LICENSE|https://raw.githubusercontent.com/FlagOpen/FlagEmbedding/897baa67c0ffddbfccf4e6776ff55310d67809d4/LICENSE|587a673933425dbc36ec61268d3b954051b2d3ef3c9b322ede357976055ffdd5
tokenizers/LICENSE|https://raw.githubusercontent.com/huggingface/tokenizers/f383101a26663708484cac0727792aad74f78234/LICENSE|c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4
kleidiai/LICENSE|https://raw.githubusercontent.com/ARM-software/kleidiai/74b1a12d3620c89dae4766de640e064952000f4d/LICENSES/Apache-2.0.txt|074e6e32c86a4c0ef8b3ed25b721ca23aca83df277cd88106ef7177c354615ff
PINS
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

pins | while IFS='|' read -r name url want; do
  mkdir -p "$(dirname "$dir/$name")"
  tmp="$dir/$name.part"
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
echo "licences in $dir"
