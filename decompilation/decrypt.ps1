# Decrypt a SQUARE ENIX Software Token VDS file and extract the OTP seed.
#
# Usage:
#   .\decrypt.ps1 --input <VDS file> --android_id <16 hex> [--imei <15 digits>] [--serial <serial>] [--plaintext]
#
# Examples:
#   .\decrypt.ps1 --input VDS_dfms4142 --android_id 0123456789abcdef
#   .\decrypt.ps1 --input VDS_dfms --android_id 0123456789abcdef --imei 000000000000000 --serial FDR0000000
#
# Output: the raw decrypted string by default; with --plaintext, the parsed
# key = value records.

# Manual argument parsing so the `--name value` style works (PowerShell's native
# binder only recognises single-dash `-name`).
$Input = $null
$Android_id = $null
$Imei = $null
$Serial = $null
$Formatted = $false

for ($i = 0; $i -lt $args.Count; $i++) {
    $a = $args[$i]
    $n = ($a -replace '^-+', '').ToLowerInvariant()
    if ($n -eq 'plaintext') { $Formatted = $true; continue }
    if ($n -match '=') {
        $parts = $n -split '=', 2
        $n = $parts[0]
        $val = $parts[1]
    } else {
        $val = if (($i + 1) -lt $args.Count) { $args[++$i] } else { $null }
    }
    switch ($n) {
        'input'      { $Input      = $val }
        'android_id' { $Android_id = $val }
        'imei'       { $Imei       = $val }
        'serial'     { $Serial     = $val }
        default      { Write-Warning "Ignoring unknown argument '$a'" }
    }
}

if (-not $Input -or -not $Android_id) {
    Write-Host 'Usage:' -ForegroundColor Cyan
    Write-Host '  .\decrypt.ps1 --input <VDS file> --android_id <16 hex> [--imei <15 digits>] [--serial <serial>] [--plaintext]'
    Write-Host ''
    Write-Host 'Examples:'
    Write-Host '  .\decrypt.ps1 --input VDS_dfms4142 --android_id 0123456789abcdef'
    Write-Host '  .\decrypt.ps1 --input VDS_dfms --android_id 0123456789abcdef --imei 000000000000000 --serial FDR0000000'
    exit 1
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Load crypto helpers (HexToBytes, BytesToHex, AesCfb8, Pbkdf2Sha256)
. "$PSScriptRoot\aes.ps1"

# ---------------------------------------------------------------------------
# App constants (identical for every user - extracted from the APK / smali).
# You do NOT need to change these.
# ---------------------------------------------------------------------------
$whiteboxKey = '3EBDEF66F889366F390537E3F64F06CFAC2DCE407528A70CFD91A79FEA663EFCDB6CCDE2F43AF27113619C7F3107FC4B6DBDAE373AE120ECB52D5203599053D8'
$bHex        = '890292DA66A2C289E00D67D6AF776A6BF2B2CF9660F5BD6B70EA7513C26F04F719F141D661EED5C0D087F7C56CAA35EF68D510B32D7BE9CD6DCE6D1A308BD453'
$constant    = '5C0750B58F11EB60FCD92393FCDD23C131D8B36BA466318D68B1A34FAC6BB44A'
$v8salt      = '6902324DEB69F55805742B63A230B10BBA4129DFC28EEEB1E4A578EB808AB4D58810B598E5BE545BB5D12377F51FCF4AC8F5A2F0F15E932EAE45FABC14BBD257'
$cdefSalt    = 'F6B4198C5CCFFCF3A0F37E0884DEC77CB3443FFFA308DD46A6F6AF78FA77A6C58F99DA40819094EC90BCE8AA7150CF1A588F55A693CC86EE264FE9460A726709'
$macKey      = '9639D79604CC302034FC1EA000D7DC771568FC1E8663A1054A7D546D2578D7790584EC63B095FBEE7F721521BDC09DF941E0357B4D0804D58E1A817F3265C298'

# ---------------------------------------------------------------------------
# Normalise user inputs (strip anything that is not hex / digits).
# ---------------------------------------------------------------------------
$aid    = $Android_id -replace '[^0-9A-Fa-f]', ''
$imei   = $Imei       -replace '[^0-9]', ''
$serial = $Serial     -replace '\s', ''

if ($aid.Length -ne 16) { Write-Error "--android_id must be 16 hex characters (got '$aid')"; exit 1 }

# ---------------------------------------------------------------------------
# Read the file and detect the format from the first 4 characters.
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Input)) { Write-Error "Input file not found: $Input"; exit 1 }
$raw = ([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $Input))) -replace '\s', ''
if ($raw.Length -lt 4) { Write-Error 'File is too short to be a VDS file'; exit 1 }
$marker = $raw.Substring(0, 4)

# ---------------------------------------------------------------------------
# Device binding value. The v4 format upper-cases the android_id and appends a
# fixed constant; the v1 format lower-cases it and prepends the IMEI instead.
# ---------------------------------------------------------------------------
$sha = [System.Security.Cryptography.SHA256]::Create()
function Get-Binding([string]$format) {
    if ($format -eq '0004') {
        $s = $aid.ToUpperInvariant() + $whiteboxKey + $constant
    } else {
        if (-not $imei) { Write-Error "The '$format' format requires --imei"; exit 1 }
        if ($imei.Length -ne 15) { Write-Warning "--imei is $($imei.Length) digits (expected 15)" }
        $s = $aid.ToLowerInvariant() + $imei + $whiteboxKey
    }
    $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($s))
    return ([System.BitConverter]::ToString($h) -replace '-', '')
}

switch ($marker) {
    '0004' {
        $binding = Get-Binding '0004'
        $saltHex = $v8salt
        $iv = HexToBytes $raw.Substring(4, 32)
        $ct = HexToBytes $raw.Substring(36, $raw.Length - 100)
        $macHex = $raw.Substring($raw.Length - 64)
        Write-Host "Format detected: 0004 (v4 - IV + HMAC-SHA256)" -ForegroundColor Cyan
    }
    '0001' {
        $binding = Get-Binding '0001'
        $saltHex = $cdefSalt
        $iv = New-Object byte[] 16
        $ct = HexToBytes $raw.Substring(4)
        $macHex = $null
        Write-Host "Format detected: 0001 (v1 - no IV, no MAC)" -ForegroundColor Cyan
    }
    default {
        Write-Error "Unsupported format '$marker'. Only 0001 and 0004 are supported."
        exit 1
    }
}

# ---------------------------------------------------------------------------
# Derive the key and decrypt (AES-256-CFB8).
# ---------------------------------------------------------------------------
$password = [System.Text.Encoding]::ASCII.GetBytes($binding + $bHex)
$key = Pbkdf2Sha256 $password (HexToBytes $saltHex) 320 32
$plaintext = [System.Text.Encoding]::UTF8.GetString((AesCfb8 $key $iv $ct $true))

# ---------------------------------------------------------------------------
# If the android_id (or IMEI) is wrong, decryption yields binary garbage rather
# than the "instance0..." key/value records. Check for a known field first.
# ---------------------------------------------------------------------------
if (-not $plaintext.Contains('instance0')) {
    Write-Error 'Decryption produced garbage - the --android_id (or --imei for 0001) does not match this file.'
    exit 1
}

# ---------------------------------------------------------------------------
# Verify the MAC for v4 (proves the file was not corrupted).
# ---------------------------------------------------------------------------
if ($macHex) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = HexToBytes $macKey
    $body = HexToBytes $raw.Substring(0, $raw.Length - 64)
    $computed = ([System.BitConverter]::ToString($hmac.ComputeHash($body)) -replace '-', '')
    if ($computed -ne $macHex.ToUpperInvariant()) {
        Write-Error 'HMAC MISMATCH - the file appears to be corrupted.'
        exit 1
    }
    Write-Host 'HMAC check: OK (file integrity)' -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Parse the key/value/type records (chars 0xA8 = record separator, 0xA7 = field
# separator, third field = type: 0 string, 1 hex).
# ---------------------------------------------------------------------------
$records = @{}
$types = @{}
$order = New-Object System.Collections.Generic.List[string]
foreach ($rec in $plaintext.Split([char]0xA8)) {
    if ([string]::IsNullOrEmpty($rec)) { continue }
    $parts = $rec.Split([char]0xA7)
    if ($parts.Length -lt 2) { continue }
    $records[$parts[0]] = $parts[1]
    $types[$parts[0]] = if ($parts.Length -ge 3) { $parts[2] } else { '0' }
    $order.Add($parts[0])
}

# Optional serial sanity check (console only).
if ($serial) {
    $name = $records['instance0name']
    if ($name -and ($name -eq $serial -or $name.Contains($serial) -or $serial.Contains($name))) {
        Write-Host 'Serial check: OK (matches instance0name)' -ForegroundColor Green
    } else {
        Write-Warning "Serial '$serial' does not match instance0name '$name' - continuing anyway."
    }
}

# ---------------------------------------------------------------------------
# Extract the OTP seed (sv tag 0x02) and diversification key (dv tag 0x32)
# from the TLV blobs (shown on the console in both modes).
# ---------------------------------------------------------------------------
function ConvertTo-TlvMap([byte[]]$bytes, [int]$offset) {
    $map = @{}
    $i = $offset
    while (($i + 1) -lt $bytes.Length) {
        $tag = $bytes[$i]
        $len = $bytes[$i + 1]
        if (($i + 2 + $len) -gt $bytes.Length) { break }
        $val = New-Object byte[] $len
        [Array]::Copy($bytes, $i + 2, $val, 0, $len)
        $map[('{0:X2}' -f $tag)] = (BytesToHex $val)
        $i += 2 + $len
    }
    return $map
}

$seed = $null
$dv = $null
if ($records.ContainsKey('instance0sv')) {
    $svMap = ConvertTo-TlvMap (HexToBytes $records['instance0sv']) 4
    $seed = $svMap['02']
}
if ($records.ContainsKey('instance0dv')) {
    $dvMap = ConvertTo-TlvMap (HexToBytes $records['instance0dv']) 0
    $dv = $dvMap['32']
}

Write-Host ''
Write-Host '=== OTP secret ===' -ForegroundColor Cyan
Write-Host ("  seed (sv tag 0x02)             = {0}" -f $seed) -ForegroundColor Green
Write-Host ("  diversification (dv tag 0x32) = {0}" -f $dv) -ForegroundColor Green

# ---------------------------------------------------------------------------
# Output. Default: the raw decrypted string. --plaintext: the parsed key=value
# records (so it can be piped to a file).
# ---------------------------------------------------------------------------
if ($Formatted) {
    Write-Output '=== Decrypted records ==='
    foreach ($key in $order) {
        $kind = if ($types[$key] -eq '1') { '   (hex)' } else { '' }
        Write-Output ("{0,-28} = {1}{2}" -f $key, $records[$key], $kind)
    }
} else {
    Write-Output $plaintext
}
