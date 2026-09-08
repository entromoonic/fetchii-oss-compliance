<!-- fetchii-ffmpeg-record/v1 -->
# FFmpeg 8.0.1 — signed universal LGPL build

- Release identity: `ffmpeg-v8.0.1`
- Upstream FFmpeg version: `8.0`
- Input lock: `locks/8.0.1.json` (sha256: `54172d8772e3a9785ba60b32f4fa822a9bf62b8efa36b05613a9236fba9a7753`)
- Artifact: `ffmpeg_macos.tar.gz` (sha256: `7c3815fe61573b9f64421e0957bc366f423c1f7199065c2e11fcd979287b5944`)
- Apple notarization: `Accepted` (submission: `7da3095e-e6c9-4f69-90df-02570d297d16`)
- Signing certificate SHA-256: `30246a03a5922fe07647c2bfd150b3f10048dfaab2e9750979be74448326d27d`
- Signing Team ID: `MW9K57H8L4`

## Exact corresponding source

- `ffmpeg-source.tar.gz`: revision `8.0`, sha256 `cce1136d38c389e6baaa452d6babc384cb2d3a9406ebe48c36a48f3ee115d8df`, origin https://ffmpeg.org/releases/ffmpeg-8.0.tar.gz, release https://github.com/dynamicfire/fetchii-aria2-builder/releases/download/ffmpeg-v8.0.1/ffmpeg-source.tar.gz
- `libvpx-source.tar.gz`: revision `d168454ecd099805c675d4a98c66f4891373302a`, sha256 `e21bf360953189186ff7f93040be19baa5c0b99263a8bb4b14e8e9ef5348cc4b`, origin https://chromium.googlesource.com/webm/libvpx, release https://github.com/dynamicfire/fetchii-aria2-builder/releases/download/ffmpeg-v8.0.1/libvpx-source.tar.gz
- `opus-source.tar.gz`: revision `1.5.2`, sha256 `65c1d2f78b9f2fb20082c38cbe47c951ad5839345876e46941612ee87f9a7ce1`, origin https://downloads.xiph.org/releases/opus/opus-1.5.2.tar.gz, release https://github.com/dynamicfire/fetchii-aria2-builder/releases/download/ffmpeg-v8.0.1/opus-source.tar.gz
- `ogg-source.tar.gz`: revision `1.3.5`, sha256 `0eb4b4b9420a0f51db142ba3f9c64b333f826532dc0f48c6410ae51f4799b664`, origin https://downloads.xiph.org/releases/ogg/libogg-1.3.5.tar.gz, release https://github.com/dynamicfire/fetchii-aria2-builder/releases/download/ffmpeg-v8.0.1/ogg-source.tar.gz
- `vorbis-source.tar.gz`: revision `1.3.7`, sha256 `0e982409a9c3fc82ee06e08205b1355e5c6aa4c36bca58146ef399621b0ce5ab`, origin https://downloads.xiph.org/releases/vorbis/libvorbis-1.3.7.tar.gz, release https://github.com/dynamicfire/fetchii-aria2-builder/releases/download/ffmpeg-v8.0.1/vorbis-source.tar.gz
- `dav1d-source.tar.gz`: revision `b546257f770768b2c88258c533da38b91a06f737`, sha256 `9cf16eadc433a16361858da6afe537babc58d586b6bf1de7d1aee128e33d309b`, origin https://code.videolan.org/videolan/dav1d.git, release https://github.com/dynamicfire/fetchii-aria2-builder/releases/download/ffmpeg-v8.0.1/dav1d-source.tar.gz

Build flags: --enable-videotoolbox --enable-libvpx --enable-libopus --enable-libvorbis --enable-libdav1d --enable-static --disable-shared --disable-doc --disable-ffplay --disable-debug --disable-libxcb --disable-libxcb-shm --disable-libxcb-xfixes --disable-libxcb-shape --disable-xlib
