$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$required = @('go.mod', 'OmniDeleter_icon_resource_amd64.syso', 'OmniDeleter.exe.manifest')
foreach ($name in $required) {
    $path = Join-Path $Root $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing required build input: $name"
    }
}

$env:GOOS = 'windows'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'

& go version
if ($LASTEXITCODE -ne 0) { throw 'go version failed' }

$fmtFiles = & gofmt -l *.go
if ($LASTEXITCODE -ne 0) { throw 'gofmt check failed' }
if ($fmtFiles) { throw "gofmt check failed; unformatted files: $($fmtFiles -join ', ')" }

& go test ./...
if ($LASTEXITCODE -ne 0) { throw 'go test failed' }

$outExe = Join-Path $Root 'OmniDeleter.exe'
& go build -trimpath -buildvcs=false -ldflags='-H=windowsgui' -o $outExe .
if ($LASTEXITCODE -ne 0) { throw 'Windows amd64 GUI build failed' }

# The .syso already embeds both the application icon and the RT_MANIFEST.
# mt.exe is used only as a post-build verification tool when Windows SDK tools
# are available; the build does not depend on a sidecar manifest at runtime.
$mt = Get-Command mt.exe -ErrorAction SilentlyContinue
if ($mt) {
    $verifyManifest = Join-Path $env:TEMP ("OmniDeleter-manifest-{0}.xml" -f $PID)
    try {
        & $mt.Source ("-inputresource:{0};#1" -f $outExe) ("-out:{0}" -f $verifyManifest)
        if ($LASTEXITCODE -ne 0) { throw 'mt.exe manifest extraction failed' }
        $expected = Get-FileHash -LiteralPath (Join-Path $Root 'OmniDeleter.exe.manifest') -Algorithm SHA256
        $actual = Get-FileHash -LiteralPath $verifyManifest -Algorithm SHA256
        if ($expected.Hash -ne $actual.Hash) {
            throw 'Embedded RT_MANIFEST does not match OmniDeleter.exe.manifest'
        }
        Write-Host 'Embedded RT_MANIFEST: verified'
    }
    finally {
        Remove-Item -LiteralPath $verifyManifest -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Warning 'mt.exe not found; build continues because the manifest is embedded in the amd64 .syso resource object.'
}

Write-Host 'Build complete: OmniDeleter.exe'
