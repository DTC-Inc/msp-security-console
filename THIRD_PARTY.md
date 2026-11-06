# Third-party components shipped in the image

The console's own code is MIT OR Apache-2.0 (LICENSE-MIT, LICENSE-APACHE). The Rust crates linked into the binary are
listed, with each licence's text, in `/licenses/rust-crates.txt`, which the image build generates from
`server/Cargo.lock` with cargo-about 0.9.3; the build fails if any crate's licence isn't on the list in
`server/about.toml` (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0; a crate offering a choice,
such as MIT OR Apache-2.0, passes on any one of them). The JavaScript packages in the web app's bundle are listed, with
each licence's text, in `/licenses/web.txt`, which the image build generates from `bun.lock` with
`scripts/web-licenses.ts`; the build fails if any package's licence isn't on that script's list (the same as
`server/about.toml`'s, plus 0BSD), or if a package ships no licence file. This file covers the rest: the embedding
model, and ONNX Runtime, which is linked into the binary. In the image, under `/licenses` (each file fetched at a
pinned commit and checked against a pinned SHA-256 by `scripts/fetch-licenses.sh`; a mismatch fails the build):

| Path | What |
|---|---|
| `/licenses/THIRD_PARTY.md` | this file |
| `/licenses/onnxruntime/LICENSE` | ONNX Runtime's licence (MIT), microsoft/onnxruntime tag v1.31.0, the release ort-sys links |
| `/licenses/onnxruntime/ThirdPartyNotices.txt` | the notices of the third-party code inside ONNX Runtime, at the same tag |
| `/licenses/bge-small-en-v1.5/LICENSE` | the model's licence (MIT), FlagOpen/FlagEmbedding's, the one the model card names |
| `/licenses/tokenizers/LICENSE` | Hugging Face tokenizers' licence (Apache-2.0), tag v0.22.2, the crate compiled in |
| `/licenses/kleidiai/LICENSE` | Arm's KleidiAI (Apache-2.0), tag v1.30.0, the version ONNX Runtime 1.31 builds with |
| `/licenses/rust-crates.txt` | every Rust crate linked into `/msp-console` and its licence's text (cargo-about) |
| `/licenses/web.txt` | every JavaScript package in the web app's bundle (`/web`) and its licence's text (solid-js, @solidjs/router, seroval, seroval-plugins and csstype today, all MIT) |

`tokenizer.json` is part of the model and under the model's licence.

## bge-small-en-v1.5 (the embedding model)

- **What:** BAAI's `bge-small-en-v1.5`, a 384-dimension English sentence-embedding model (BERT, 33M parameters), as an
  int8 ONNX export. It turns NVD descriptions into vectors for similar-CVE search (`server/src/embed.rs`).
- **Licence:** MIT, as BAAI's model card declares (`license: mit`; "FlagEmbedding is licensed under the MIT License. The
  released models can be used for commercial purposes free of charge."). The licence text is FlagEmbedding's, below. The file shipped is
  Xenova's int8 export of BAAI's model; Xenova's card names no licence of its own, so the export inherits BAAI's MIT.
- **Files and pins** (`scripts/fetch-model.sh`, and `FILES` in `server/src/embed.rs`; the image build fails on a
  mismatch):

  | File | From | SHA-256 |
  |---|---|---|
  | `model.onnx` | `huggingface.co/Xenova/bge-small-en-v1.5`, revision `ea104dacec62c0de699686887e3f920caeb4f3e3`, `onnx/model_quantized.onnx` (34,014,426 bytes) | `6c9c6101a956d62dfb5e7190c538226c0c5bb9cb27b651234b6df063ee7dbfe4` |
  | `tokenizer.json` | `huggingface.co/BAAI/bge-small-en-v1.5`, revision `5c38ec7c405ec4b44b94cc5a9bb96e735b38267a` (711,396 bytes) | `d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66` |

- **Why this export:** BAAI publishes only an fp32 ONNX export (`onnx/model.onnx`, 133 MB). Xenova's repository, the one
  Transformers.js uses, carries BAAI's fp32 export byte for byte (SHA-256 `828e1496…40cf35` in both) and an int8 one
  made from it with per-channel dynamic quantisation of the weights (`quantize_config.json`: QInt8, per channel,
  reduced range). Qdrant's `bge-small-en-v1.5-onnx-Q`, the other widely used one, is an fp16 export optimised for GPUs,
  so not this. The int8 file is a quarter of the size. Measured on 30 made-up NVD-style descriptions
  (2026-11-05), the cosine between its vector and fp32's for the same text is at least 0.9938 (mean 0.9962), and the
  nearest neighbour is the same for 29 of 30, the 30th a tie. Speed wasn't the reason: with ONNX Runtime's
  graph optimisations on, the two were about as fast on an Apple M-series CPU; the console runs with them off, where
  int8 takes about 6 ms a description on two threads (server/src/embed.rs says why).
- **Copied from:** FlagEmbedding's LICENSE (github.com/FlagOpen/FlagEmbedding), the licence the model card names:

```
MIT License

Copyright (c) 2022 staoxiao

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## ONNX Runtime 1.31.0

- **What:** Microsoft's inference engine, linked statically into `/msp-console` by the `ort` crate (2.0.0-rc.15) from
  pyke's prebuilt archive for the platform (`cdn.pyke.io/0/pyke:ort-rs/ms@1.31.0/<target>.tar.lzma2`, CPU only, no
  execution providers). ort-sys's build script checks the archive against the SHA-256 in its own `dist.tsv`, and
  Cargo.lock pins ort-sys by checksum, so the build can't take a different archive.
- **Licence:** MIT (below). ONNX Runtime itself contains third-party code (among others protobuf, abseil, RE2, the ONNX
  project, cpuinfo, Eigen, flatbuffers), whose notices are ONNX Runtime's `ThirdPartyNotices.txt` for v1.31.0. pyke's
  archive holds only the library, so the image build fetches that file from the tag and ships it at
  `/licenses/onnxruntime/ThirdPartyNotices.txt`.
- **KleidiAI, on arm64:** pyke's arm64 archive (`aarch64-unknown-linux-gnu`, SHA-256 `380c1b63…4709`) links Arm's
  KleidiAI micro-kernels (its `kai_` symbols are in `libonnxruntime.a`; checked 2026-11-05), which ONNX Runtime 1.31
  builds at v1.30.0. Its notice is in ONNX Runtime's `ThirdPartyNotices.txt`, and its licence (Apache-2.0) is shipped
  at `/licenses/kleidiai/LICENSE` in both images; the x86_64 build doesn't use it.
- **Copied from:** ONNX Runtime's LICENSE at v1.31.0:

```
MIT License

Copyright (c) Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Debian's runtime libraries

The runtime image is `gcr.io/distroless/cc-debian13`: Debian 13's glibc, which is LGPL-2.1-or-later, and libgcc and
libstdc++, which are GPL with the GCC Runtime Library Exception. Their copyright files are in the image under
`/usr/share/doc/`.
