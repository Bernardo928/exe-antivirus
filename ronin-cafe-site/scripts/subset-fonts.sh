#!/usr/bin/env bash
# Gera fontes enxutas em src/fonts a partir do @fontsource-variable (requer: pip install fonttools brotli).
# Archivo: limita eixos ao que o site usa (wght 400-900, wdth 100-125). Ambas: só latin + pontuação usada.
set -euo pipefail
cd "$(dirname "$0")/.."
F=node_modules/@fontsource-variable
U="U+0020-007E,U+00A0-00FF,U+0152-0153,U+2013,U+2018-201E,U+2022,U+2026,U+20AC,U+2192"
fonttools varLib.instancer "$F/archivo/files/archivo-latin-wdth-normal.woff2" wght=400:900 wdth=100:125 -o /tmp/archivo-inst.ttf
pyftsubset /tmp/archivo-inst.ttf --unicodes="$U" --layout-features='kern,liga,calt,tnum' --flavor=woff2 --output-file=src/fonts/archivo-latin-wdth.woff2
fonttools varLib.instancer "$F/newsreader/files/newsreader-latin-wght-normal.woff2" wght=400:600 -o /tmp/newsreader-inst.ttf
pyftsubset /tmp/newsreader-inst.ttf --unicodes="$U" --layout-features='kern,liga,calt,onum,pnum' --flavor=woff2 --output-file=src/fonts/newsreader-latin-wght.woff2
fonttools varLib.instancer "$F/newsreader/files/newsreader-latin-wght-italic.woff2" wght=400:400 -o /tmp/newsreader-it.ttf
pyftsubset /tmp/newsreader-it.ttf --unicodes="$U" --layout-features='kern,liga' --flavor=woff2 --output-file=src/fonts/newsreader-latin-italic.woff2
rm -f /tmp/archivo-inst.ttf /tmp/newsreader-inst.ttf /tmp/newsreader-it.ttf
ls -la src/fonts
