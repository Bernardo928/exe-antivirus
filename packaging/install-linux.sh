#!/bin/sh
# Instala o EXE Antivirus para o usuário atual (atalho no menu de aplicativos).
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.local/opt/ExeAntivirus"
mkdir -p "$HOME/.local/opt" "$HOME/.local/share/applications" "$HOME/.local/bin"
if [ "$DIR" != "$DEST" ]; then
    rm -rf "$DEST"
    cp -r "$DIR" "$DEST"
fi
ln -sf "$DEST/ExeAntivirus" "$HOME/.local/bin/exe-antivirus"
cat > "$HOME/.local/share/applications/exe-antivirus.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=EXE Antivirus
Comment=Proteção contra vírus e malware
Exec=$DEST/ExeAntivirus
Icon=$DEST/icon.png
Terminal=false
Categories=System;Security;Utility;
EOF
echo "EXE Antivirus instalado em $DEST"
echo "Abra pelo menu de aplicativos ou execute: exe-antivirus"
