#!/bin/sh
# Render the deck to JPEGs for visual checks. Everything stays inside the project folder.
cd "$(dirname "$0")" && ROOT=$(cd .. && pwd)
mkdir -p render && rm -f render/*
"$ROOT/tools/lo/LibreOffice.app/Contents/MacOS/soffice" -env:UserInstallation=file://$ROOT/.cache/lo-profile --headless --convert-to pdf --outdir render Seven_Sins_Revisited_Presentation.pptx >/dev/null 2>&1
pdftoppm -jpeg -r 80 render/Seven_Sins_Revisited_Presentation.pdf render/slide
ls render | wc -l
