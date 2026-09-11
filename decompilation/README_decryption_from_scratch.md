# Recovering your SQUARE ENIX Software Token (OneSpan DIGIPASS) — from scratch

This guide explains how to decrypt your own `VDS_dfms4142` file and recover the
OTP seed **without memory dumps or network captures**. Everything you need is in
the APK itself plus two device identifiers (android_id and IMEI).

---

## 1. What you need

| Item | Where to find it |
|------|------------------|
| `VDS_dfms4142` | App internal storage: `/data/data/com.square_enix_software_token/files/` (needs root, or a backup such as `adb backup`) |
| The APK | `com.square_enix_software_token.apk` |
| `android_id` | `adb shell settings get secure android_id` (16 hex chars, e.g. `0123456789abcdef`) |
| IMEI | `*#06#` on the device, or `adb shell service call iphonesubinfo` (15 digits, e.g. `000000000000000`) |
| Tools | `apktool`/`baksmali`, and either .NET (C#) or any language with AES-256 + PBKDF2 + SHA-256 |

The serial number (`FDR0000000`) is visible in plaintext in the app and is not
secret — it appears inside the decrypted data too.

---

## 2. The encryption chain (summary)

```
VDS_dfms4142 = "0004" + IV(16 bytes) + AES-256-CFB8(ciphertext) + HMAC-SHA256(32 bytes)

key      = PBKDF2-HMAC-SHA256(password, salt, iterations=320, dkLen=32)
salt     = whitebox("k" table, counter "7BC04A269DD85F007A7A66A1A4AA6F4D")
           = 6902324DEB69F55805742B63A230B10BBA4129DFC28EEEB1E4A578EB808AB4D5
             8810B598E5BE545BB5D12377F51FCF4AC8F5A2F0F15E932EAE45FABC14BBD257
MAC key  = whitebox("l" table, counter "ECE45D7D8E55D5306F88505B1604A58D")
password = deviceBindingValue + b()
```

where

```
deviceBindingValue = hex(SHA256( android_id.UPPERCASE + whiteboxKey + constant ))
whiteboxKey = whitebox("a" key tables, counter "BF3E6C7121ADF171581A5C4355A5EFC4")
b()         = whitebox("b" key tables, counter "D6904EC533C25FD34D276C7EF17C8332")
constant    = "5C0750B58F11EB60FCD92393FCDD23C131D8B36BA466318D68B1A34FAC6BB44A"
```

> Note the **case**: `android_id` is UPPERCASE in the `0004` binding (newer format).
> The older `0001` format instead uses `SHA256(android_id.LOWERCASE + IMEI + whiteboxKey)`.

---

## 3. Step by step

### 3.1 Decompile the APK
```
apktool d com.square_enix_software_token.apk
```
You need the smali of:
- `com/vasco/digipass/sdk/utils/utilities/b.smali`  (string deobfuscation key)
- `com/vasco/digipass/sdk/utils/utilities/c.smali`  (crypto dispatch: digest/cipher modes)
- the white-box AES table classes under `com/vasco/digipass/sdk/obfuscated/`
  (`ee.smali`-equivalent: `p,q,r,s,t,u,v` + `i,j,k,l,m,n,o` = 131120 bytes of tables)
- `com/vasco/digipass/sdk/utils/e/a.smali`  (VDS file logic, salts, markers)

### 3.2 Recover the string-deobfuscation key (AES-256-CTR)
The obfuscated strings are decrypted by `b.g(String)` using a **fixed** AES-256-CTR
key/IV assembled from static byte arrays `a..f` in `b.smali`'s `<clinit>`:

```
key = a||b||c||d = 25950767BD0202821DFBC71286A813A82B2CB404A27D171C11487B6381076476
iv  = e||f       = 2D916B88C324FBDC0192B4B855573582
```
Use this to decode the hard-coded markers/constants:
`"5DE67821"→"0004"`, `"5DE67824"→"0001"`, `"3B921B4A"→"VDS_"`,
`"25BB297657350D1EC715"→"HmacSHA256"`, `"AF7E"→"¨"`, `"AF71"→"§"`.

### 3.3 Port the white-box AES (the hard part)
The real AES key is **baked into lookup tables** in `obfuscated/ee.smali`
(~131 KB). This is a nibble/dual-rail table-based AES-128 (9 rounds) with
bit-sliced round keys. The crypto is dispatched by `utilities/c.smali`:

```
digest : 1=MD5, 2=SHA-1, 3=SHA-256, 4=SHA-256 (vds)
cipher alg: 1=DES, 2=3DES, 3=AES
cipher mode: 1=ECB, 2=CBC, 3=CFB8, 4=CTR/SIC
```

A **working C# port is included** in `decrypt_work/wb/Program.cs` (verified:
keystream PASS, MAC MATCH). Run it to compute the four white-box outputs:

```
whiteboxKey = 3EBDEF66F889366F390537E3F64F06CFAC2DCE407528A70CFD91A79FEA663EF
              CDB6CCDE2F43AF27113619C7F3107FC4B6DBDAE373AE120ECB52D5203599053D8
b()         = 890292DA66A2C289E00D67D6AF776A6BF2B2CF9660F5BD6B70EA7513C26F04F7
              19F141D661EED5C0D087F7C56CAA35EF68D510B32D7BE9CD6DCE6D1A308BD453
salt (k)    = 6902324DEB69F55805742B63A230B10BBA4129DFC28EEEB1E4A578EB808AB4D5
              8810B598E5BE545BB5D12377F51FCF4AC8F5A2F0F15E932EAE45FABC14BBD257
MAC key (l) = 9639D79604CC302034FC1EA000D7DC771568FC1E8663A1054A7D546D2578D779
              0584EC63B095FBEE7F721521BDC09DF941E0357B4D0804D58E1A817F3265C298
```

(These are constants of the app binary and are identical for every user — only the
`android_id` + IMEI in the device binding are per-device.)

### 3.4 Compute the device binding value
The constant `"5C0750B58F11EB60FCD92393FCDD23C131D8B36BA466318D68B1A34FAC6BB44A"`
is deobfuscated from static arrays in `c/a` (it is `b.g(hex(a||b||c||d))`). Then:

```
deviceBindingValue = hex( SHA256( android_id.toUpperCase() + whiteboxKey + constant ) )
```

### 3.5 Decrypt with `decrypt.ps1`
The simplest path is `decrypt_work/decrypt.ps1`. It **auto-detects the file format**
(`0001` vs `0004`) and applies the correct uppercase/lowercase + IMEI logic itself —
you only supply your identifiers.

```powershell
powershell -ExecutionPolicy Bypass -File .\decrypt.ps1 --input VDS_dfms4142 --android_id <your-android-id>
```

For an older `0001` file, add `--imei`:

```powershell
powershell -ExecutionPolicy Bypass -File .\decrypt.ps1 --input VDS_dfms --android_id <your-android-id> --imei <your-imei>
```

`--serial` is optional and only used as a sanity check against the decrypted
`instance0name`.

| Argument | What to pass |
|----------|--------------|
| `--input` | path to the `VDS_dfms4142` (v4) or `VDS_dfms` (v1) file |
| `--android_id` | the device android_id, 16 hex chars (case does not matter) |
| `--imei` | the device IMEI, 15 digits — only needed for `0001` |
| `--serial` | optional, e.g. `FDR1160370` |

Everything else is automatic:

- **`0004`** (newer): binding = `SHA256( android_id.UPPERCASE + whiteboxKey + constant )`,
  salt = `k[]`, IV read from the file, HMAC verified.
- **`0001`** (older): binding = `SHA256( android_id.LOWERCASE + IMEI + whiteboxKey )`,
  salt = `c||d||e||f`, zero IV, no MAC.

The app constants (whiteboxKey, `b()`, salts, MAC key, `constant`) are already
hardcoded in the script, so there is nothing else to edit.

The script prints the decrypted key/value records and then:

```
seed (sv tag 0x02)             = ...
diversification (dv tag 0x32) = ...
```

Under the hood it does exactly:

```
password = deviceBindingValue + b()          # ASCII, both uppercase hex
key      = PBKDF2-HMAC-SHA256(password, salt, 320, 32)

file  = "0004" + IV + ciphertext + MAC       # the hex text file
IV    = first 32 hex chars after "0004"
MAC   = last  64 hex chars
plain = AES-256-CFB8-decrypt(key, IV, ciphertext)
verify: HMAC-SHA256(key=MACkey, hexdecoded("0004"+IV+ciphertext)) == MAC
```

### 3.6 Extract the OTP seed
The plaintext is `key§value§type` records separated by `¨` (0xA8) and `§` (0xA7):

```
instance0sv = 3808006F...00112233445566778899AABBCCDDEEFF...   (hex)
instance0dv = 2D01072E...FFEEDDCCBBAA99887766554433221100...   (hex)
```

`instance0sv` is a TLV blob: tag `0x02` holds the **16-byte OTP seed**:

```
seed = 00112233445566778899AABBCCDDEEFF
```

`instance0dv` tag `0x32` holds the **16-byte diversification key**:

```
dv = FFEEDDCCBBAA99887766554433221100
```

The seed + diversification drive the DIGIPASS OTP algorithm (see
`OTP_algorithm_trace.md`).

---

## 4. Older `0001` files (pre-upgrade `VDS_dfms`)
If your file starts with `0001` (no IV, no MAC), the differences are:

```
salt     = c||d||e||f (from e/a.smali <clinit>)
           = F6B4198C5CCFFCF3A0F37E0884DEC77CB3443FFFA308DD46A6F6AF78FA77A6C5
             8F99DA40819094EC90BCE8AA7150CF1A588F55A693CC86EE264FE9460A726709
IV       = 16 zero bytes
binding  = hex( SHA256( android_id.LOWERCASE + IMEI + whiteboxKey ) )
           (= 0000000000000000000000000000000000000000000000000000000000000000
              for a sample device — differs per device)
password = binding + b()
```

---

## 5. Reference values (example device — for verifying a port)
```
android_id        = 0123456789abcdef
IMEI              = 000000000000000
whiteboxKey       = 3EBDEF66F889366F390537E3F64F06CFAC2DCE407528A70CFD91A79FEA663EF
                    CDB6CCDE2F43AF27113619C7F3107FC4B6DBDAE373AE120ECB52D5203599053D8
b()               = 890292DA66A2C289E00D67D6AF776A6BF2B2CF9660F5BD6B70EA7513C26F04F7
                    19F141D661EED5C0D087F7C56CAA35EF68D510B32D7BE9CD6DCE6D1A308BD453
constant          = 5C0750B58F11EB60FCD92393FCDD23C131D8B36BA466318D68B1A34FAC6BB44A
deviceBinding(0004)= 0000000000000000000000000000000000000000000000000000000000000000
deviceBinding(0001)= 0000000000000000000000000000000000000000000000000000000000000000
v4 salt (k)       = 6902324DEB69F55805742B63A230B10BBA4129DFC28EEEB1E4A578EB808AB4D5
                    8810B598E5BE545BB5D12377F51FCF4AC8F5A2F0F15E932EAE45FABC14BBD257
v1 salt (cdef)    = F6B4198C5CCFFCF3A0F37E0884DEC77CB3443FFFA308DD46A6F6AF78FA77A6C5
                    8F99DA40819094EC90BCE8AA7150CF1A588F55A693CC86EE264FE9460A726709
MAC key           = 9639D79604CC302034FC1EA000D7DC771568FC1E8663A1054A7D546D2578D779
                    0584EC63B095FBEE7F721521BDC09DF941E0357B4D0804D58E1A817F3265C298
OTP seed (tag 02) = 00112233445566778899AABBCCDDEEFF
diversification   = FFEEDDCCBBAA99887766554433221100   (v4)  /  11223344556677889900AABBCCDDEEFF (v1)
```
