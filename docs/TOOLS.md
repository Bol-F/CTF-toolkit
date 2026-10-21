# Specialized tool compatibility

Core installation remains independent of legacy tools. `docker-compose.tools.yml` substitutes only the worker image, preserving no-network/read-only/nonroot/capability/PID/memory constraints. StegoVeritas has a separate Python environment. Build compilers stay in a separate stage. No tool or password dictionary is downloaded during analysis.

| Tool | Installation and adapter | License/source evidence |
| --- | --- | --- |
| zsteg | Core RubyGems 0.2.13; automatic deep checks or explicit analysis | MIT, [upstream](https://github.com/zed-0xff/zsteg) |
| steghide | Core Debian package; explicit supplied-password extraction into a fixed file | GPL-2.0-or-later, [upstream](https://steghide.sourceforge.net/) |
| StegSeek | Optional pinned v0.6 source build; supplied-list only, max 1,000 guesses, one thread; no seed sweep or bundled lists | GPL-2.0, [source/build instructions](https://github.com/RickdeJager/stegseek) |
| StegoVeritas | Optional 1.11 package/isolated venv; `-meta` only, no carving/external auto-extraction | MIT according to [published package metadata](https://pypi.org/project/stegoveritas/1.11/); [upstream](https://github.com/bannsec/stegoVeritas) |
| OutGuess | Optional Debian 1:0.4-2; detected-format suffix and fixed extraction output | BSD-4-Clause/BSD-3-Clause main code plus bundled IJG/additional source licenses; [Debian package](https://packages.debian.org/trixie/outguess), installed `/usr/share/doc/outguess/copyright` |
| OpenStego | Optional checksum-pinned official 0.8.6 archive; headless bounded Java RandomLSB extraction, explicit output filename overrides embedded names | GPL-2.0, [upstream](https://github.com/syvaidya/openstego), [license](https://www.openstego.com/about) |
| StegSnow | Optional Debian 20130616-8; whitespace extraction with supplied password | Apache-2.0; Debian packaging BSD-3-Clause; [package](https://packages.debian.org/trixie/stegsnow), installed copyright file |
| StegDetect | Unsupported/disabled even if an executable appears on PATH; no modern build is claimed | Archived/unmaintained [upstream](https://github.com/abeluck/stegdetect); BSD-style/bundled JPEG code |

The inventory is runtime evidence, not a promise: missing tools are unavailable, failed compatibility probes are reported, and adapters return actual execution statuses. Version probes sometimes require metadata fallbacks because older CLIs print only help. An installed executable is only considered a verified integration after a real fixture test; the test target contains supplied-password round trips for steghide, StegSeek, OutGuess, OpenStego and StegSnow, plus metadata-only StegoVeritas. Tests explicitly skip optional tools absent from the core image.

Upstream OpenStego/StegSeek release downloads are SHA-256 pinned in `config/install-specialized.py`. Debian packages and Python dependencies still need a build-time network connection. The optional image is larger and builds more slowly; rebuilding source edits reuses dependency stages. Preserve upstream notices and review the full installed license texts before redistributing images.

Test optional integration:

```sh
docker build --target tools-test -t stegolab-tools-tests .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,noexec,nosuid,size=512m stegolab-tools-tests
```
