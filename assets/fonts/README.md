# Bundled fonts

These eight static faces are embedded in the binary; no system fonts or network access are required.
All three font families are licensed under SIL Open Font License 1.1 (OFL-1.1).
The corresponding licence texts are included beside the fonts.
This README records the source versions and SHA-256 checksums; there is no separate font manifest.
The fonts are embedded as unmodified static instances; no subsetting is applied.

| Family | Version / revision | Source | Licence |
| --- | --- | --- | --- |
| Inter | 4.1 | [Release archive](https://github.com/rsms/inter/releases/download/v4.1/Inter-4.1.zip), `extras/ttf/Inter-{Regular,Medium,Bold}.ttf` | [OFL-1.1](LICENSE-Inter.txt) |
| Noto Sans TC | noto-cjk revision `f8d157532fbf` | [Pinned source directory](https://github.com/notofonts/noto-cjk/tree/f8d157532fbf/Sans/SubsetOTF/TC), `NotoSansTC-{Regular,Medium,Bold}.otf` | [OFL-1.1](LICENSE-NotoSansTC.txt) |
| Maple Mono NL | v7.9 | [Release archive](https://github.com/subframe7536/maple-font/releases/download/v7.9/MapleMonoNL-TTF.zip), `MapleMonoNL-{Regular,Bold}.ttf` | [OFL-1.1](LICENSE-MapleMono.txt) |

## SHA-256

Verified using `shasum -a 256` against the checksums below on 2026-11-08; all eight match.

```text
288316099b1e0a47a4716d159098005eef7c0066921f34e3200393dbdb01947f  Inter-Bold.ttf
97ad806f526e41546d46365bb3a393145f75b7b1568913db74549ad8b8dba872  Inter-Medium.ttf
40d692fce188e4471e2b3cba937be967878f631ad3ebbbdcd587687c7ebe0c82  Inter-Regular.ttf
bc0878fd823d39c310afc1ad9906b9408376d3cfb52f4af03d6297ffe376a834  MapleMonoNL-Bold.ttf
30fe0df56b3aee42c012e6bbbabd60cc531e4ded91a6453eb8823dab0882976f  MapleMonoNL-Regular.ttf
55420b259eb119bf5f2a0aadba10cf9d736c12d64ab93e78546d69ef5f43558b  NotoSansTC-Bold.otf
bf206dca0975779bac71cb49a037a364156ca98a0c431b1b7d6b29fb8952ac7e  NotoSansTC-Medium.otf
5bab0cb3c1cf89dde07c4a95a4054b195afbcfe784d69d75c340780712237537  NotoSansTC-Regular.otf
```
