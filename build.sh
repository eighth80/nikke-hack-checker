#!/bin/sh
# 한국어판·일본어판 exe 를 한 번에 빌드합니다. (리눅스·맥·WSL·GitHub Actions)
# 필요: Go 1.24+
# res/rsrc_*.syso (아이콘·버전 정보·매니페스트) 는 미리 만들어 둔 것을 씁니다.
set -e
cd "$(dirname "$0")"
trap 'rm -f rsrc_windows_amd64.syso' EXIT
for L in ko ja; do
  cp "res/rsrc_$L.syso" rsrc_windows_amd64.syso
  GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
    -ldflags="-H windowsgui -X main.lang=$L" -o "nikke_check_$L.exe" .
  echo "built nikke_check_$L.exe"
done
