# Re-encrypt a modified VDS plaintext back into the VDS format.
#
# Usage:
#   .\encrypt.ps1 --in <plaintext file> --android_id <16 hex> [--imei <15 digits>] [--serial <serial>] --out <VDS file>
#
# Examples:
#   .\encrypt.ps1 --in raw.txt --android_id 0123456789abcdef --out VDS_dfms4142
#   .\encrypt.ps1 --in raw.txt --android_id 0123456789abcdef --imei 000000000000000 --out VDS_dfms
#
# The input is the raw decrypted string produced by decrypt.ps1 (the default,
# non --plaintext output). The format (0001 vs 0004) is detected automatically
# from the "v" field inside the plaintext (v=5 -> 0004, v=3 -> 0001).

$In = $null
$Out = $null
$Android_id = $null
$Imei = $null
$Serial = $null

for ($i = 0; $i -lt $args.Count; $i++) {
    $a = $args[$i]
    $n = ($a -replace '^-+', '').ToLowerInvariant()
    if ($n -match '=') {
        $parts = $n -split '=', 2
        $n = $parts[0]
        $val = $parts[1]
    } else {
        $val = if (($i + 1) -lt $args.Count) { $args[++$i] } else { $null }
    }
    switch ($n) {
        'in'         { $In         = $val }
        'out'        { $Out        = $val }
        'android_id' { $Android_id = $val }
        'imei'       { $Imei       = $val }
        'serial'     { $Serial     = $val }
        default      { Write-Warning "Ignoring unknown argument '$a'" }
    }
}

if (-not $In -or -not $Out -or -not $Android_id) {
    Write-Host 'Usage:' -ForegroundColor Cyan
    Write-Host '  .\encrypt.ps1 --in <plaintext file> --android_id <16 hex> [--imei <15 digits>] [--serial <serial>] --out <VDS file>'
    exit 1
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Load crypto helpers (HexToBytes, BytesToHex, AesCfb8, Pbkdf2Sha256)
. "$PSScriptRoot\aes.ps1"

# ---------------------------------------------------------------------------
# App constants (identical for every user - extracted from the APK / smali).
# ---------------------------------------------------------------------------
$whiteboxKey = '3EBDEF66F889366F390537E3F64F06CFAC2DCE407528A70CFD91A79FEA663EFCDB6CCDE2F43AF27113619C7F3107FC4B6DBDAE373AE120ECB52D5203599053D8'
$bHex        = '890292DA66A2C289E00D67D6AF776A6BF2B2CF9660F5BD6B70EA7513C26F04F719F141D661EED5C0D087F7C56CAA35EF68D510B32D7BE9CD6DCE6D1A308BD453'
$constant    = '5C0750B58F11EB60FCD92393FCDD23C131D8B36BA466318D68B1A34FAC6BB44A'
$v8salt      = '6902324DEB69F55805742B63A230B10BBA4129DFC28EEEB1E4A578EB808AB4D58810B598E5BE545BB5D12377F51FCF4AC8F5A2F0F15E932EAE45FABC14BBD257'
$cdefSalt    = 'F6B4198C5CCFFCF3A0F37E0884DEC77CB3443FFFA308DD46A6F6AF78FA77A6C58F99DA40819094EC90BCE8AA7150CF1A588F55A693CC86EE264FE9460A726709'
$macKey      = '9639D79604CC302034FC1EA000D7DC771568FC1E8663A1054A7D546D2578D7790584EC63B095FBEE7F721521BDC09DF941E0357B4D0804D58E1A817F3265C298'

# Normalise inputs.
$aid    = $Android_id -replace '[^0-9A-Fa-f]', ''
$imei   = $Imei       -replace '[^0-9]', ''
$serial = $Serial     -replace '\s', ''

if ($aid.Length -ne 16) { Write-Error "--android_id must be 16 hex characters (got '$aid')"; exit 1 }

# ---------------------------------------------------------------------------
# Read the plaintext file.
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $In)) { Write-Error "Input file not found: $In"; exit 1 }
$content = ([System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $In))).TrimEnd()

# ---------------------------------------------------------------------------
# Parse the records. Accept either the raw decrypt output ("key<0xA7>value<0xA7>type"
# separated by 0xA8) or the formatted --plaintext output ("key = value").
# ---------------------------------------------------------------------------
$records = @{}
$types = @{}
$order = New-Object System.Collections.Generic.List[string]

if ($content.Contains([string][char]0xA7)) {
    # raw format
    foreach ($rec in $content.Split([char]0xA8)) {
        if ([string]::IsNullOrEmpty($rec)) { continue }
        $parts = $rec.Split([char]0xA7)
        if ($parts.Length -lt 2) { continue }
        $records[$parts[0]] = $parts[1]
        $types[$parts[0]] = if ($parts.Length -ge 3) { $parts[2] } else { '0' }
        $order.Add($parts[0])
    }
} else {
    # formatted format: "key = value" or "key = value (hex)"
    foreach ($line in ($content -split "\r?\n")) {
        if ($line -match '^([A-Za-z0-9_]+)\s*=\s*(.*)$') {
            $key = $Matches[1]
            $value = $Matches[2].Trim()
            if ($value -match '\s*\(hex\)\s*$') {
                $value = $value -replace '\s*\(hex\)\s*$', ''
                $type = '1'
            } else {
                $type = '0'
            }
            $records[$key] = $value
            $types[$key] = $type
            $order.Add($key)
        }
    }
}

if ($records.Count -eq 0) { Write-Error 'Could not parse any key/value records from the input.'; exit 1 }

# ---------------------------------------------------------------------------
# Detect the format from the "v" field: 5 -> 0004, 3 -> 0001.
# ---------------------------------------------------------------------------
$v = $records['v']
if ($v -eq '5') { $format = '0004' }
elseif ($v -eq '3') { $format = '0001' }
else { Write-Error "Cannot determine format from 'v' field (got '$v'). Expected 5 (0004) or 3 (0001)."; exit 1 }

Write-Host "Format detected: $format (from v=$v)" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Device binding value (same rules as decrypt.ps1).
# ---------------------------------------------------------------------------
$sha = [System.Security.Cryptography.SHA256]::Create()
if ($format -eq '0004') {
    $s = $aid.ToUpperInvariant() + $whiteboxKey + $constant
    $saltHex = $v8salt
} else {
    if (-not $imei) { Write-Error "The '$format' format requires --imei"; exit 1 }
    $s = $aid.ToLowerInvariant() + $imei + $whiteboxKey
    $saltHex = $cdefSalt
}
$binding = ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($s))) -replace '-', '')

# Optional serial sanity check.
if ($serial) {
    $name = $records['instance0name']
    if (-not $name -or -not ($name -eq $serial -or $name.Contains($serial) -or $serial.Contains($name))) {
        Write-Warning "Serial '$serial' does not match instance0name '$name' - continuing anyway."
    }
}

# ---------------------------------------------------------------------------
# Rebuild the raw plaintext string, then encrypt.
# ---------------------------------------------------------------------------
$sect = [string][char]0xA7
$parts = @()
foreach ($key in $order) {
    $parts += ($key + $sect + $records[$key] + $sect + $types[$key])
}
$plaintext = $parts -join [string][char]0xA8

$password = [System.Text.Encoding]::ASCII.GetBytes($binding + $bHex)
$key = Pbkdf2Sha256 $password (HexToBytes $saltHex) 320 32
$ptBytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)

if ($format -eq '0004') {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $iv = New-Object byte[] 16
    $rng.GetBytes($iv)
    $ct = AesCfb8 $key $iv $ptBytes $false
    $bodyHex = '0004' + (BytesToHex $iv) + (BytesToHex $ct)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = HexToBytes $macKey
    $macHex = BytesToHex ($hmac.ComputeHash((HexToBytes $bodyHex)))
    $output = $bodyHex + $macHex
} else {
    $iv = New-Object byte[] 16
    $ct = AesCfb8 $key $iv $ptBytes $false
    $output = '0001' + (BytesToHex $ct)
}

[System.IO.File]::WriteAllText($Out, $output, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Wrote encrypted VDS file to: $Out" -ForegroundColor Green
