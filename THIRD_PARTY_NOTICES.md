# Third-party software and image redistribution

StegoLab application code, documentation and authored CTF fixtures use the [MIT license](LICENSE). Analysis programs run as separate command-line processes; their licenses remain independent. The MIT license does not relicense the Docker image or its dependencies. No third-party executable is checked into this repository.

## Bundled analysis programs

This table describes the main upstream terms. The complete notices for the **installed version**, including bundled code and Debian patches, are authoritative. Debian packages retain `/usr/share/doc/<package>/copyright` and `/usr/share/common-licenses/`; these directories are deliberately not stripped. [Debian's copyright policy](https://www.debian.org/doc/debian-policy/ch-docs.html#copyright-information) describes those files.

| Component | Main license / material to retain | Installed notice or primary source |
| --- | --- | --- |
| ExifTool | Artistic or GPL-1.0-or-later; some files/additional material have their own terms | `/usr/share/doc/libimage-exiftool-perl/copyright`; [Debian source notices](https://sources.debian.org/src/libimage-exiftool-perl/) |
| Binwalk 2.x | MIT, with separately licensed signature/data material | `/usr/share/doc/python3-binwalk/copyright`; [upstream license](https://github.com/ReFirmLabs/binwalk/blob/v2.3.4/LICENSE) |
| GNU strings / binutils | GPL-3.0-or-later; library/data exceptions and other terms as packaged | `/usr/share/doc/binutils/copyright`; [GNU binutils](https://www.gnu.org/software/binutils/) |
| file / libmagic | BSD-style notices, with additional database/file notices | `/usr/share/doc/file/copyright`, `/usr/share/doc/libmagic1/copyright`; [upstream](https://www.darwinsys.com/file/) |
| pngcheck | Permissive custom MIT-like main utility; companion code can be GPL | `/usr/share/doc/pngcheck/copyright`; [source license](https://sources.debian.org/src/pngcheck/3.0.3-1/LICENSE/) |
| ImageMagick | ImageMagick license; bundled/delegate libraries retain their licenses | `/usr/share/doc/imagemagick/copyright` and corresponding library package notices; [upstream license](https://imagemagick.org/license/) |
| foremost | Public-domain US government portions and GPL-2.0-or-later portions | `/usr/share/doc/foremost/copyright`; [source notices](https://sources.debian.org/src/foremost/1.5.7-9.1/debian/copyright/) |
| Tesseract + English trained data | Apache-2.0 main projects, plus packaged notices | `/usr/share/doc/tesseract-ocr/copyright`, `/usr/share/doc/tesseract-ocr-eng/copyright`; [upstream](https://github.com/tesseract-ocr/tesseract/blob/main/LICENSE) |
| zbarimg / ZBar | LGPL-2.1-or-later main code and other packaged notices | `/usr/share/doc/zbar-tools/copyright`; [upstream](https://github.com/mchehab/zbar) |
| FFmpeg / ffprobe | LGPL-2.1-or-later or GPL depending on build options; Debian enables GPL components | `/usr/share/doc/ffmpeg/copyright`; [upstream explanation](https://ffmpeg.org/legal.html). Preserve exact build configuration and dependency sources when distributing binaries. |
| SoX | GPL command-line programs; LGPL/GPL library and optional format code | `/usr/share/doc/sox/copyright`; [upstream source README](https://sources.debian.org/src/sox/14.4.2%2Bgit20190427-3.5/README/) |
| pdfdetach / Poppler | GPL-2.0-or-later main code plus separately licensed files | `/usr/share/doc/poppler-utils/copyright`; [upstream](https://poppler.freedesktop.org/) |
| zsteg | MIT; Ruby dependencies retain their notices | Installed gem directories, recorded in `/usr/local/share/stegolab/ruby-source-paths.txt`; [upstream](https://github.com/zed-0xff/zsteg) |
| steghide | GPL-2.0-or-later | `/usr/share/doc/steghide/copyright`; [upstream](https://steghide.sourceforge.net/) |
| StegSeek (optional) | GPL-2.0, inherited steghide notices | `/usr/local/share/stegolab/StegSeek-COPYING`, checksum-pinned complete source archive in `upstream-sources/`; [v0.6 source](https://github.com/RickdeJager/stegseek/tree/v0.6) |
| StegoVeritas (optional) | MIT package; dependencies individually licensed | Optional Python notice inventory and installed `.dist-info` licenses; [package metadata](https://pypi.org/project/stegoveritas/1.11/) |
| OutGuess (optional) | BSD-4-Clause/BSD-3-Clause portions, IJG and additional bundled code | `/usr/share/doc/outguess/copyright`; [Debian package](https://packages.debian.org/trixie/outguess). Retain the attribution/advertising wording where applicable. |
| OpenStego (optional) | GPL-2.0 main code; bundled Java dependencies retain their notices | Complete official release archive and matching source archive in `upstream-sources/`, extracted source/LICENSE in `openstego-source/`; [upstream GPL text](https://github.com/syvaidya/openstego/blob/openstego-0.8.6/LICENSE) |
| StegSnow (optional) | Apache-2.0 main code; Debian packaging BSD-3-Clause | `/usr/share/doc/stegsnow/copyright`; [Debian package](https://packages.debian.org/trixie/stegsnow) |
| OpenJDK (optional) | GPL-2.0 with Classpath exception and bundled third-party notices | `/usr/share/doc/openjdk-21-jre-headless/copyright`, JDK legal directory; [OpenJDK legal](https://openjdk.org/legal/) |

StegDetect and xxd are not explicitly installed. A disabled inventory entry does not bundle their code. Python, Debian base-system packages, Ruby and native libraries have their own terms; the table is not a complete software bill of materials.

## Notices retained in images

`/usr/local/share/stegolab/` contains this file, the application license, exact Debian package/source-version inventory, Python package inventory and copied available Python license/NOTICE files, and Ruby version/source-path inventories. The optional image also inventories its isolated StegoVeritas environment and retains the OpenStego/StegSeek archives and source noted above. Python wheel notices and Ruby gem source remain installed as well. Inventory generation is offline and never contacts uploaded evidence.

## Source releases and binary images

The documented GitHub release is a **source release**: Dockerfiles resolve tools during the user's local build. CI does not push binary images. Running a local build is different from redistributing a prebuilt image.

Before distributing a container or binary, provide the complete corresponding source, patches and build scripts required by each copyleft component at the same download location, retain notices/attribution, and document modifications. A URL to upstream alone is not a substitute for those source obligations. Read [GPLv2 section 3](https://www.gnu.org/licenses/old-licenses/gpl-2.0.html#section3) and the full applicable licenses. Use the exact-version source collector in [the release guide](docs/RELEASING.md), audit non-Debian/native wheel and Java dependencies too, and publish the reviewed source bundle alongside the image. The collector is an aid, not an automated legal-compliance certification; do not publish an image if required source material is missing.
