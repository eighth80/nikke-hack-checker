# 한국어판·일본어판 exe 를 한 번에 빌드합니다. (윈도우 PowerShell)
# 필요: Go 1.24+  https://go.dev/dl/
# 실행이 막히면: powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:GOOS = "windows"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
try {
  foreach ($L in "ko", "ja") {
    Copy-Item "res\rsrc_$L.syso" "rsrc_windows_amd64.syso" -Force
    go build -trimpath "-ldflags=-H windowsgui -X main.lang=$L" -o "nikke_check_$L.exe" .
    if ($LASTEXITCODE -ne 0) { throw "build failed: $L" }
    Write-Host "built nikke_check_$L.exe"
  }
  Get-FileHash nikke_check_ko.exe, nikke_check_ja.exe -Algorithm SHA256 | Format-Table Hash, Path -AutoSize
} finally {
  Remove-Item rsrc_windows_amd64.syso -ErrorAction SilentlyContinue
}
