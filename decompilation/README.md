# SQUARE ENIX Software Token — VDS_dfms4142 decryption notes
All findings verified against the smali in `apktool/com.square_enix_software_token/smali/`
and cross-checked against the memory dumps in `full/memory dumps/memdiff/`.

## 1. The key embedded in the APK (string deobfuscation)
`com.vasco.digipass.sdk.utils.utilities.b.g(String)` = AES-256-CTR (mode "SIC"/CTR)
with a FIXED key and IV assembled from static arrays a..f in `b.smali`:

  key (32 bytes) = a||b||c||d:
    25950767BD0202821DFBC71286A813A82B2CB404A27D171C11487B6381076476
  IV (16 bytes) = e||f:
    2D916B88C324FBDC0192B4B855573582

VERIFIED: decrypting "5DE67821" -> "0004", "3B921B4A" -> "VDS_",
"2CB82C676B142867975AF6A413E372" -> "AndroidKeyStore",
"25BB297657350D1EC715" -> "HmacSHA256".
This key is NOT the VDS file key; it deobfuscates the hardcoded strings/constants.

## 2. VDS_dfms4142 file format (version "0004")
    "0004" + IV(32 hex = 16 bytes) + AES-256-CFB8(ciphertext) + MAC(64 hex = 32 bytes)

Confirmed on the real file (1960 chars):
    marker "0004", IV 6E692466EA5061DA7F430C4B18A05739,
    ciphertext 1860 hex chars, MAC 3C167B9B...4DE6BA.

## 3. Key derivation for the VDS file
    key  = PBKDF2-HMAC-SHA256(password, salt, iterations=0x140=320, dkLen=32)
    data decrypted with AES-256-CFB8(key, IV)

    salt     = whitebox_decrypt(e/a.k[], "D60847D9882AF9C526DD62895C7CB230845B73C0B25821EE472ADEC263F78DFDCA2A0F43CFAE941FC56F986ED000FD619A3F3D485FC1B9354F83FA600051D985")
    MAC key  = whitebox_decrypt(e/a.l[], "8FEA624303F97DBC03ACF3C9680C9BE93B36954226569A2FDEA2381C30E904444E03723CAE2A6AC034B40891CDF204AF306F374526A4766629D127AA7D4F9A7A")

    password = deviceBindingValue + m.b()
       * m.b() = whitebox_decrypt(counter="D6904EC533C25FD34D276C7EF17C8332",
                     ct="5C8620132643D308EB11F562F604CEEF515CD0647E52E8D2852828C283BD9610621CA3ED0B66CD1751E6D6DE7F1C448B71225AFB0B3683F409517A0AC4F4B332")
       * deviceBindingValue = hex(SHA256( deviceIdSerial + whiteboxKey + constant ))
           - whiteboxKey = whitebox_decrypt(counter="BF3E6C7121ADF171581A5C4355A5EFC4",
                 ct="859DACCF10DBA553190C8ED2F0DEF5C04CA46DDF816109E4F3DE5650EF7DD9920599BF4077E869E4DA2942A3C40AE8F0E21DBFD5843767B353BCD9B7CB749592")
           - constant = "5C0750B58F11EB60FCD92393FCDD23C131D8B36BA466318D68B1A34FAC6BB44A"  (verified)
           - deviceIdSerial = Build.getSerial() / getDeviceId() (from OneSpan_DeviceBinding.xml)

## 4. The "white box" AES (the last missing piece)
`com.vasco.digipass.sdk.utils.utilities.c.c.a([B,[B)` is CTR/SIC mode where the
first 16-byte argument is the INITIAL COUNTER (IV). The real AES key is baked into
the ~131 KB of lookup tables in `obfuscated/ee.smali` (9-round table-based AES-128).
`d/g.a(keyHex, ctHex)` = whitebox-CTR(keyHex, ctHex).

Because this key is fixed and device-independent, the whitebox outputs above
(m.b(), salt, MAC key, whiteboxKey) are CONSTANTS. They can be obtained by:
  * porting the `ee`/`c/b`/`c/d` tables, or
  * running the app once (emulator) and logging `d/g.a` / the PBKDF2 inputs, or
  * locating them in a full memory dump (they are passed around as hex strings).

## 5. What's already in your memory dumps (plaintext VDS data)
The decrypted DIGIPASS instance record is visible in `memdiff/memdumpanalysis.txt`:
    instance0name = FDR0000000
    instance0rId  = user0000000
    instance0pwdFrmt = 1
    SQEXSA_OTP
TLV record: tag 0x02 (16 bytes) = 00112233445566778899aabbccddeeff   <- candidate seed
            tag 0x32 (16 bytes) = ffeeddccbbaa99887766554433221100
Observed 6-digit OTP outputs in memory: 000000, 000000, 000000, 000000, 000000.

## 6. Tools in this folder
  aes.ps1          - AES-CTR, AES-CFB8, PBKDF2-HMAC-SHA256 (all test-vector verified)
  test_crypto.ps1  - verification against NIST/RFC vectors
  test_deobfuscate.ps1 - string deobfuscation demo (b.g)
  decrypt_vds.ps1  - VDS decryptor (needs password + salt as inputs)
