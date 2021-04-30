# Note, as of 2021-04-27, Square now officially supports software authenticators!
https://na.finalfantasyxiv.com/lodestone/topics/detail/71188ef5daa1405a631a2bc2d79d54b08b69508a

(see https://square-enix-games.com/en_US/seaccount/otp/authenticator.html for details)

I may continue to work on this project as a hobby, but my main goal of getting it working with other password managers is now possible.

# Square-Enix-Software-Token-OTP

Findings when looking into the Square Enix Software Token: https://play.google.com/store/apps/details?id=com.square_enix_software_token

Ultimately, it's my goal to find out how the OTP codes are being generated, and then writing that functionality into BitWarden, similar to Steam (https://bitwarden.com/help/article/authenticator-keys/ / https://github.com/bitwarden/mobile/blob/master/src/Core/Services/TotpService.cs). As with the Steam service, I'm not too interested in how the key is generated, only where to find it and how to use it.

tl;dr: The Square Enix Software Token uses it's own proprietary method to generate OTP codes, and can't be added to existing apps like Google Authenticator. It uses Vasco (now OneSpan) DIGIPASS for Mobile (https://www.onespan.com/products/mobile-authentication / https://www.authstrong.com/DIGIPASS-Mobile-Enterprise-Security.asp), which is similar to RSA SecurID, and NOT the OTP standard.
It may be possible to reverse the process by which it generates OTP codes (like with the Steam OTP codes), but then we may as well use the app.

Process for adding the software OTP:
https://square-enix-games.com/en_GB/seaccount/otp

https://square-enix-games.com/en_GB/seaccount/otp/token.html

https://support.eu.square-enix.com/faqarticle.php?kid=78777&id=612&la=2

For the purposes of easy testing, I'm using Nox, so any device IDs or model names will be related to this.
    
Note: Square Enix will e-mail you a code to put into the app (this isn't one of the values in the network capture). This code only lasts for one hour, and a new one can only be generated once every 24 hours.

## Notes:
1. The token is stored in /data/data/com.square_enix_software_token/files/VDS_dfms4142
1. The token always starts with "0004", and has a length of 1960 characters.
    1. The 0004 repreesents the version number. Older versions start with 0001, and have 1586 characters. Loading an old version of this file in the new app converts it to the 0004 version above.
1. The token is in uppercase hex.
    1. The token in this file changes each time the "Show One-Time Password" button is pressed.
    1. Deleting this token when the app is closed means that the registration process needs to be restarted from the EULA stage.
    1. Deleting this token when the app is running causes a new file to be written when the button is pressed, as the data is already in memory.
    1. The initial value in the token is different and shorter on fresh installations (before the EULA is accepted) - 228 or 290 characters, same format with the preceeding "0004" and character range.
    1. There is a delay of a few seconds when pressing the button as a big calculation occurs (fan spins up).
1. The token may be generated using the libQRCronto.so library (need to test, this library could just be for unused QR code functionality).
    1. /data/app/com.square_enix_software_token-1/lib/arm/libQRCronto.so
        1. This may just be "com.square_enix_software_token" on some devices.
1. The OTP is valid for 30 seconds (old phone) or 60 seconds (Nox).
    1.  On older devices, only one code can be generated every 30 seconds, even if you go back and forth.
    1.  On newer devices, a new code is generated each time the "Show One-Time Password" button is clicked, and lasts for 60 seconds.
    1.  Note: This needs looking into. Sometimes going out and in of the token screen returns the same code, sometimes it changes. I think it's 30 seconds, synchronised to the server (it changed at xx:xx:58)
1. Possibly lses either sha256 (vdsSHA256Initial_hash_value) or sha512 (vdsSHA512Initial_hash_value) (from GHIDRA)
1. Related to VASCO DIGIPASS for Mobile (http://www.authstrong.com/DIGIPASS-Mobile.asp).
1. None of the strings below work as an OTP seed, because they contain illegal characters (e.g. "1").
1. Only the initial registration needs to be done online. Generating codes can be done offline.

I feel like the trick to understanding this will be in either understanding the "VDS_dfms4142" file (you can search for "dfms" in jadx-gui to get some starting points), or to find the method that's called when running the OTP generation button, and following the code from there. The latter is the best bet, and where I'll focus on next.
<br>
<br>

## New (or modified) Files:
Below are a list of files in `/data/data/com.square_enix_software_token/` that are changed or modified during each step. It appears that only the file VDS_dfms4142 changes, and none of the data in the network capture (nonce, xfad, etc) appears in any of these files.

### Fresh install:
```
/lib/libQRCronto.so (new) (/lib is symlinked to /data/app/com.square_enix_software_token-1/lib/x86, and the file isn't used)
```
### After launch:
```
/cache/WebView/Crashpad/settings.dat (new)
/cache/org.chromium.android_webview/Code Cache/js/index (new)
/cache/org.chromium.android_webview/Code Cache/js/index-dir/the-real-index (new)
/files/VDS_dfms4142 (new)
/shared_prefs/OneSpan_DeviceBinding.xml (new)
/shared_prefs/WebViewChromiumPrefs.xml (new)
/app_webview/variations_seed_new (new)
/app_webview/variations_stamp (new) (empty)
/app_webview/webview_data.lock (new) (empty)
/app_webview/metrics_guid (new)
/app_webview/Web Data (new)
/app_webview/Web Data-journal (new) (empty)
/app_webview/pref_store (new)
```
### After registration:
```
/files/VDS_dfms4142 (changed)
```
### After generating code:
```
/files/VDS_dfms4142 (changed)
```
### After generating code again:
```
/files/VDS_dfms4142 (changed)
```
<br>
<br>

## Network capture results:

Using Charles Proxy, we can see that the app makes the following **two**  requests (identifiable details replaced):

### First request
Code | Method | Host | Path | Fields | Duration | Size | Status
------------ | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------
200 | GET | https://secure.square-enix.com | /account/app/svc/activation1 | ?sqexid=username<br>&birthday=YYYYMMDD<br>&clinetInitialVector1=0123456789ABCDEF0123456789ABCDEF<br>&clientPublickey=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567<br>&lang=en-us | 920ms | 19.15 KB | Complete

#### Fields that stay the same between multiple activations
`sqexid` = Square Enix ID, the one you log on to https://secure.square-enix.com with.

`birthday` = The date of birth set in your Square Enix account, in YYYYMMDD format. This doesn't change.

`lang` = The language of the app. It looks like it supports de-de, en-gb, en-us, fr-fr, ja-jp (according to the date in the assets\eula folder, the flags in the images folder, and the xml in the xml folder.

`User-Agent:` = The user agent of the android device. 

#### Fields that change between multiple activations
`clinetInitialVector1` = 32 UPPERCASE hex characters. The Initialisation Vector for encryption. Note that the second request sends a field called `clinetInitialVector2`. Also note the spelling. It's clinet, not client. Fairly sure this is a typo, as `clientPublickey` is spelt correctly.

`clientPublickey` = 136 UPPERCASE hex characters. The Public Key for encryption.

Here's a handy picture of the fields required: https://pbs.twimg.com/media/EtaO3HnXcAEK8-T?format=jpg&name=large


#### RAW:

```
GET /account/app/svc/activation1?sqexid=username&birthday=YYYYMMDD&clinetInitialVector1=0123456789ABCDEF0123456789ABCDEF&clientPublickey=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567&lang=en-us HTTP/1.1
User-Agent: Dalvik/1.2.3 (Linux; U; Android 1.2.3; SM-G123A Build/ABC12D)
Host: secure.square-enix.com
Connection: Keep-Alive
Accept-Encoding: gzip
```

<br>

#### Response:

#### Fields that stay the same between multiple activations
Most fields are the same and not that interesting, but of note are:

`retcode` = Always 0. Possibly to indicate a successful log in.

`message` = Always blank.

`Expires:` = Always set to `Sat, 06 May 1995 12:00:00 GMT` for some reason.

#### Fields that change between multiple activations
`Set-Cookie: cis_sessid=` = 56 lowercase hex characters. Sets a cookie.

`serverTime` = Epoch timestamp on the server.

`xfad` = 544 UPPERCASE hex characters. An Encrypted Full Activation Data (XFAD) for online activation. (see https://trustbuilder.zendesk.com/hc/en-us/articles/360007137874-Digipass-Service or http://www.etruserve.com.tw/vasco/wp/wp-VACMAN%20Controller%20Integration%20White%20Paper%20v3%200.pdf)

`serverPublicKey` = 128 UPPERCASE hex characters. The Public Key for encryption.

`initialVector` = 32 UPPERCASE hex characters. The Initialisation Vector for encryption.

`nonces` = 32 UPPERCASE hex characters. Nonce value for Encryption. 

#### RAW:

```
HTTP/1.1 200 OK
Date: <redacted>
Server: Apache
Strict-Transport-Security: max-age=600; includeSubDomains
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Expires: Sat, 06 May 1995 12:00:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html;charset=UTF-8
Content-Length: 970
Set-Cookie: cis_sessid=0123456789abcdef0123456789abcdef0123456789abcdef01234567; Path=/; Secure; HttpOnly; SameSite=None
P3P: CP='UNI CUR OUR'
Keep-Alive: timeout=3, max=100
Connection: keep-alive

<?xml version="1.0" encoding="UTF-8"?> 
<DP4Mobile
    retCode="0"
    message=""
    serverTime="1600000000" >
    
    <Activation
        xfad="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        serverPublicKey="0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
        initialVector="0123456789ABCDEF0123456789ABCDEF"
        nonces="0123456789ABCDEF0123456789ABCDEF"/>
</DP4Mobile>
```

<br>
<br>

### Second request

Code | Method | Host | Path | Fields | Duration | Size | Status
------------ | ------------- | ------------- | ------------- | ------------- | ------------- | ------------- | -------------
200 | POST | https://secure.square-enix.com | /account/app/svc/activation2 | serialNumber=XYZ1234567<br>&derivationCode=0123456789012345<br>&clientNonce=0123456789ABCDEF0123456789ABCDEF<br>&clinetInitialVector2=0123456789ABCDEF0123456789ABCDEF<br>&deviceId=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF<br>&lang=en-us | 360 ms | 696 bytes | Complete

#### Fields that stay the same between multiple activations
`serialNumber` = A 10 UPPERCASE alphanumeric serial number of your device. In Nox, the first three characters were letters, and the remaining seven were letters. Also required when deregistering the OTP device, so take note. Not related to the device name of the device. Not sure where this value is generated.

`deviceId` = 64 UPPERCASE hex characters. I suspect similar to serialNumber in determining uniqueness.

`lang` = The language of the app. It looks like it supports de-de, en-gb, en-us, fr-fr, ja-jp (according to the date in the assets\eula folder, the flags in the images folder, and the xml in the xml folder.

#### Fields that change between multiple activations
`derivationCode` = A 16 digit number. Not sure of it's use, but probably involved in the SSL handshake.

`clientNonce` = 32 UPPERCASE hex characters. Nonce value for Encryption.

`clinetInitialVector2` = 32 UPPERCASE hex characters. The Initialisation Vector for encryption. Note that the second request sends a field called `clinetInitialVector2`. Also note the spelling. It's clinet, not client. Fairly sure this is a typo, as `clientNonce` and `clientPublickey` are spelt correctly.

#### RAW:
```
POST /account/app/svc/activation2 HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Accept: */*
User-Agent: Dalvik/1.2.3 (Linux; U; Android 1.2.3; SM-G123A Build/ABC12D)
Host: secure.square-enix.com
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: 239

serialNumber=XYZ1234567&derivationCode=0123456789012345&clientNonce=0123456789ABCDEF0123456789ABCDEF&clinetInitialVector2=0123456789ABCDEF0123456789ABCDEF&deviceId=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF&lang=en-us
```

#### Response:

#### Fields that stay the same between multiple activations
Most fields are the same and not that interesting, but of note are:

`Expires:` = Always set to `Sat, 06 May 1995 12:00:00 GMT` for some reason.

#### Fields that change between multiple activations
`Set-Cookie: cis_sessid=` = 56 lowercase hex characters. Sets a cookie.

`serverTime` = Epoch timestamp on the server.

#### RAW:
```
HTTP/1.1 200 OK
Date: <redacted>
Server: Apache
Strict-Transport-Security: max-age=600; includeSubDomains
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Expires: Sat, 06 May 1995 12:00:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html;charset=UTF-8
Set-Cookie: cis_sessid=0123456789abcdef0123456789abcdef0123456789abcdef01234567; Path=/; Secure; HttpOnly; SameSite=None
P3P: CP='UNI CUR OUR'
Keep-Alive: timeout=3, max=99
Transfer-Encoding: chunked
Connection: keep-alive

<?xml version="1.0" encoding="UTF-8"?> 
    <DP4Mobile retCode="0" message="Software Token Registration Complete" serverTime="1600000000">
</DP4Mobile>
```

Todo: <add guide, including installing the CA cert> (https://stackoverflow.com/a/51485753)


### Synchronise
There's an option in the app to Synchronise the time.

#### Request (RAW):
```
GET /account/app/svc/synchronization HTTP/1.1
User-Agent: Dalvik/1.2.3 (Linux; U; Android 1.2.3; SM-G123A Build/ABC12D)
Host: secure.square-enix.com
Connection: Keep-Alive
Accept-Encoding: gzip
```


#### Response (RAW):
```
HTTP/1.1 200 OK
Date: <redacted>
Server: Apache
Strict-Transport-Security: max-age=600; includeSubDomains
X-XSS-Protection: 1; mode=block
X-Frame-Options: SAMEORIGIN
Expires: Sat, 06 May 1995 12:00:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Pragma: no-cache
Content-Type: text/html;charset=UTF-8
Content-Length: 78
Set-Cookie: cis_sessid=0123456789abcdef0123456789abcdef0123456789abcdef01234567; Path=/; Secure; HttpOnly; SameSite=None
P3P: CP='UNI CUR OUR'
Keep-Alive: timeout=3, max=100
Connection: keep-alive

<?xml version="1.0" encoding="UTF-8"?> 
<DP4Mobile serverTime="1600000000" />
```

<br>

## Reverse engineering the apk:

Using ByteCode Viewer (https://github.com/Konloch/bytecode-viewer) I could see a few interesting, but disappointing things about the apk.
1. It uses heavy obfuscation (`import com.vasco.digipass.sdk.utils.utilities.obfuscated`) and lots of Strings / BigIntegers which I'm sure are used to generate useful data (like the login URL).
1. It uses the zxing library in libQRCronto.so (https://github.com/zxing/zxing). This is normally used with QR codes, but that's not the case with the Square Enix app.
1. Searching for the few error strings shows that it uses The Bouncy Castle Crypto Package For Java (https://github.com/bcgit/bc-java) for encryption.

#### Useful classes:
**a/a/a/b/b/a.class**
```
319:throw new IllegalArgumentException("Key length not 128/192/256 bits.");
...
448:throw new IllegalStateException("AES engine not initialised");
```

**a/a/a/b/d/a.class**

List of hash functions
```
   static {
      h.put("GOST3411", a.a.a.d.c.a(32));
      h.put("MD2", a.a.a.d.c.a(16));
      h.put("MD4", a.a.a.d.c.a(64));
      h.put("MD5", a.a.a.d.c.a(64));
      h.put("RIPEMD128", a.a.a.d.c.a(64));
      h.put("RIPEMD160", a.a.a.d.c.a(64));
      h.put("SHA-1", a.a.a.d.c.a(64));
      h.put("SHA-224", a.a.a.d.c.a(64));
      h.put("SHA-256", a.a.a.d.c.a(64));
      h.put("SHA-384", a.a.a.d.c.a(128));
      h.put("SHA-512", a.a.a.d.c.a(128));
      h.put("Tiger", a.a.a.d.c.a(64));
      h.put("Whirlpool", a.a.a.d.c.a(64));
   }
```

**a/a/a/b/h/a.class**

Another list of hash functions
```

   static {
      e.put("RIPEMD128", cr.c);
      e.put("RIPEMD160", cr.b);
      e.put("RIPEMD256", cr.d);
      e.put("SHA-1", cw.j);
      e.put("SHA-224", cf.f);
      e.put("SHA-256", cf.c);
      e.put("SHA-384", cf.d);
      e.put("SHA-512", cf.e);
      e.put("SHA-512/224", cf.g);
      e.put("SHA-512/256", cf.h);
      e.put("SHA3-224", cf.i);
      e.put("SHA3-256", cf.j);
      e.put("SHA3-384", cf.k);
      e.put("SHA3-512", cf.l);
      e.put("MD2", cj.H);
      e.put("MD4", cj.I);
      e.put("MD5", cj.J);
   }
...
   private byte[] b(byte[] var1) {
      return (new cu(this.b, var1)).getEncoded("DER");
   }

```

**a/a/a/b/c.class**

Reference to PGP/OpenPGP
```
   public c(b var1) {
      this.d = var1;
      this.a = new byte[var1.b()];
      boolean var2 = false;
      this.b = 0;
      String var3 = var1.a();
      int var4 = var3.indexOf(47) + 1;
      boolean var5;
      if (var4 > 0 && var3.startsWith("PGP", var4)) {
         var5 = true;
      } else {
         var5 = false;
      }

      this.f = var5;
      if (!this.f && !(var1 instanceof q)) {
         var5 = var2;
         if (var4 > 0) {
            var5 = var2;
            if (var3.startsWith("OpenPGP", var4)) {
               var5 = true;
            }
         }

         this.e = var5;
      } else {
         this.e = true;
      }

   }
```


<br>

#### Proc dump
The process closes whenever it's minimised, so you need to run an adb shell to get the info. Regardless, there's nothing obvious in the /proc/<pid> folder for this application

<br>

#### Memory dump

I've dumped the memory using GameGuardian (https://gameguardian.net/download), and tried using https://github.com/makomk/aeskeyfind to find the (AES?) keys, but nothing appears. I'm not even able to see the OTP value in live memory. The memory is where the de-obfuscated code would live, so it'd be worthwhile investigating this area more.


In memory, there's a value called instance0rId§<username> (or "i�n�s�t�a�n�c�e�0�r�I�d�§that (where x is the username)) (for me, at 0x000AFA30). Most strings (though not all) are obfuscated in memory by the addition of a hex 00 character (�) between each character. Using a hex editor (e.g. HxD), copying the text, then removing all instances of this character, and then running the Linux command `strings` on it shows some very interesting information, such as the Square Enix URL (previously completely obfuscated), the username, and the device ID. It also shows a list of cipher suites, error messages, and some long strings that may/may not be the OTP secret. The OTP code itself still isn't present 

<br>

When searching for my DeviceID (which is referred to as `instance0name`), I get the following (plus some long data strings I've removed, possibly the encrypted key):

```
instance0initialized§true
instance0tds§LATER
instance0pwdFrmt§1
instance0biometricUsed§false
eula§true
instance0rId§<sqexid>
v§5
ts§0
instance0fingerprintVersion§6
instance0name§<deviceId>
AlgorithmParameters.1.2.840.113549.1.12.1.3
AlgorithmParameters.1.2.840.113549.1.12.1.4
```

Of note here is: `AlgorithmParameters.1.2.840.113549.1.12.1.3` and `AlgorithmParameters.1.2.840.113549.1.12.1.4`, which appears to be `pbeWithSHAAnd3-KeyTripleDES-CBC1` and `pbeWithSHAAnd2-KeyTripleDES-CBC` (from https://github.com/caesay/Asn1Editor/blob/master/Asn1Editor/OID.txt)
```
1.2.840.113549.1.12.1.3, pbeWithSHAAnd3-KeyTripleDES-CBC
1.2.840.113549.1.12.1.4, pbeWithSHAAnd2-KeyTripleDES-CBC
```

This thread looks like it has an example to decrypt the data: https://stackoverflow.com/questions/34261024/encrypted-private-key-in-java-java-security-invalidkeyexception

Another result from the search shows mention of `SHA-512/224`. From (https://webcache.googleusercontent.com/search?q=cache:GqZxQ_jbc5MJ:sbsit.sa/dpf-removal-fu9hj/password-generator-algorithm-examples.html),  `SHA-2 is a set of 6 hashing algorithm (SHA-256, SHA-512, SHA-224, SHA-384, SHA-512/224, SHA-512/256)`, so we might need to specify this when creating the otp link. E.g. otpauth://totp/websiteName?secret=ABC123&algorithm=SHA512

In order to test whether we have the right key/algorithm, I've put all of the best looking codes into bash-totp (https://github.com/jakwings/bash-totp), so I can generate them all at once and compare it to the real answer.

Here's a list of interesting strings from the memory dump. The Square Enix URL is found here (it's obfuscated in the code), and there are some interesting error messages. I've removed most of the garbage text and some strings that look unique to my account (e.g. account name, device name, WiFi IP address).
<details>
  <summary>Interesting strings</summary>

```
  MP
 !"#$&'*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQSTUVWXYZ[\]^_`abcdefghlmnopqrstuvwxyz{|}~
% Square Enix ID (for which the registration password was acquired)h
/data/media/0
/data/misc/user/0
/mnt/shell/emulated/0
/storage/emulated/0
0123456789ABCDEF8
1.0p
1.2.840.113549.1.1.1
1.2.840.113549.1.1.10
1.2.840.113549.1.1.11
1.2.840.113549.1.1.12
1.2.840.113549.1.1.13
1.2.840.113549.1.1.14
1.2.840.113549.1.1.15
1.2.840.113549.1.1.16
1.2.840.113549.1.1.2
1.2.840.113549.1.1.3
1.2.840.113549.1.1.4
1.2.840.113549.1.1.5
1.2.840.113549.1.1.6
1.2.840.113549.1.1.7
1.2.840.113549.1.1.8
1.2.840.113549.1.1.9
1.2.840.113549.1.12.1
1.2.840.113549.1.12.1.1
1.2.840.113549.1.12.1.2
1.2.840.113549.1.12.1.3
1.2.840.113549.1.12.1.4
1.2.840.113549.1.12.1.5
1.2.840.113549.1.12.10.1
1.2.840.113549.1.12.10.1.1
1.2.840.113549.1.12.10.1.2
1.2.840.113549.1.12.10.1.3
1.2.840.113549.1.12.10.1.4
1.2.840.113549.1.12.10.1.5
1.2.840.113549.1.12.10.1.6
1.2.840.113549.1.3.1
1.2.840.113549.1.5.1
1.2.840.113549.1.5.10
1.2.840.113549.1.5.11
1.2.840.113549.1.5.12
1.2.840.113549.1.5.13
1.2.840.113549.1.5.3
1.2.840.113549.1.5.4
1.2.840.113549.1.5.6
1.2.840.113549.1.9.1
1.2.840.113549.1.9.13
1.2.840.113549.1.9.14
1.2.840.113549.1.9.15
1.2.840.113549.1.9.15.1
1.2.840.113549.1.9.15.2
1.2.840.113549.1.9.15.3
1.2.840.113549.1.9.16
1.2.840.113549.1.9.16.1.2
1.2.840.113549.1.9.16.1.23
1.2.840.113549.1.9.16.1.31
1.2.840.113549.1.9.16.1.4
1.2.840.113549.1.9.16.1.9
1.2.840.113549.1.9.16.2.1
1.2.840.113549.1.9.16.2.10
1.2.840.113549.1.9.16.2.11
1.2.840.113549.1.9.16.2.12
1.2.840.113549.1.9.16.2.14
1.2.840.113549.1.9.16.2.15
1.2.840.113549.1.9.16.2.16
1.2.840.113549.1.9.16.2.17
1.2.840.113549.1.9.16.2.18
1.2.840.113549.1.9.16.2.19
1.2.840.113549.1.9.16.2.20
1.2.840.113549.1.9.16.2.21
1.2.840.113549.1.9.16.2.22
1.2.840.113549.1.9.16.2.23
1.2.840.113549.1.9.16.2.24
1.2.840.113549.1.9.16.2.25
1.2.840.113549.1.9.16.2.26
1.2.840.113549.1.9.16.2.27
1.2.840.113549.1.9.16.2.37
1.2.840.113549.1.9.16.2.38
1.2.840.113549.1.9.16.2.4
1.2.840.113549.1.9.16.2.40
1.2.840.113549.1.9.16.2.43
1.2.840.113549.1.9.16.2.47
1.2.840.113549.1.9.16.2.5
1.2.840.113549.1.9.16.2.54
1.2.840.113549.1.9.16.2.7
1.2.840.113549.1.9.16.3
1.2.840.113549.1.9.16.3.10
1.2.840.113549.1.9.16.3.14
1.2.840.113549.1.9.16.3.5
1.2.840.113549.1.9.16.3.9
1.2.840.113549.1.9.16.6.1
1.2.840.113549.1.9.16.6.2
1.2.840.113549.1.9.16.6.3
1.2.840.113549.1.9.16.6.4
1.2.840.113549.1.9.16.6.5
1.2.840.113549.1.9.16.6.6
1.2.840.113549.1.9.2
1.2.840.113549.1.9.20
1.2.840.113549.1.9.21
1.2.840.113549.1.9.22
1.2.840.113549.1.9.22.2
1.2.840.113549.1.9.23
1.2.840.113549.1.9.23.1
1.2.840.113549.1.9.3
1.2.840.113549.1.9.4
1.2.840.113549.1.9.5
1.2.840.113549.1.9.52
1.2.840.113549.1.9.6
1.2.840.113549.1.9.7
1.2.840.113549.1.9.8
1.2.840.113549.1.9.9
1.2.840.113549.2.10
1.2.840.113549.2.11(
1.2.840.113549.2.2
1.2.840.113549.2.4
1.2.840.113549.2.5
1.2.840.113549.2.7
1.2.840.113549.2.8
1.2.840.113549.2.9
1.2.840.113549.3.2
1.2.840.113549.3.4
1.2.840.113549.3.7
1.3.36.3.2.1
1.3.36.3.2.2
1.3.36.3.2.3
1.3.36.3.3.1
1.3.36.3.3.1.2
1.3.36.3.3.1.3
1.3.36.3.3.1.4
1.3.36.3.3.2
1.3.36.3.3.2.1
1.3.36.3.3.2.2
1.3.36.3.3.2.8
1.3.36.3.3.2.8.1.1
1.3.36.3.3.2.8.1.1.1
1.3.36.3.3.2.8.1.1.10
1.3.36.3.3.2.8.1.1.11
1.3.36.3.3.2.8.1.1.12
1.3.36.3.3.2.8.1.1.13
1.3.36.3.3.2.8.1.1.14
1.3.36.3.3.2.8.1.1.2
1.3.36.3.3.2.8.1.1.3
1.3.36.3.3.2.8.1.1.4
1.3.36.3.3.2.8.1.1.5
1.3.36.3.3.2.8.1.1.6
1.3.36.3.3.2.8.1.1.7
1.3.36.3.3.2.8.1.1.8
1.3.36.3.3.2.8.1.1.9
1.3.36.3.3.2.8.18
1.3.6.1.5.5.7.1
1.3.6.1.5.5.7.48
1.3.6.1.5.5.7.48.1
1.3.6.1.5.5.7.48.2
2.16.840.1.101.3.4.1
2.16.840.1.101.3.4.1.1
2.16.840.1.101.3.4.1.2
2.16.840.1.101.3.4.1.21
2.16.840.1.101.3.4.1.22
2.16.840.1.101.3.4.1.23
2.16.840.1.101.3.4.1.24
2.16.840.1.101.3.4.1.25
2.16.840.1.101.3.4.1.26
2.16.840.1.101.3.4.1.27
2.16.840.1.101.3.4.1.28
2.16.840.1.101.3.4.1.3
2.16.840.1.101.3.4.1.4
2.16.840.1.101.3.4.1.41
2.16.840.1.101.3.4.1.42
2.16.840.1.101.3.4.1.43
2.16.840.1.101.3.4.1.44
2.16.840.1.101.3.4.1.45
2.16.840.1.101.3.4.1.46
2.16.840.1.101.3.4.1.47
2.16.840.1.101.3.4.1.48
2.16.840.1.101.3.4.1.5
2.16.840.1.101.3.4.1.6
2.16.840.1.101.3.4.1.7
2.16.840.1.101.3.4.1.8
2.16.840.1.101.3.4.2
2.16.840.1.101.3.4.2.1
2.16.840.1.101.3.4.2.10
2.16.840.1.101.3.4.2.11
2.16.840.1.101.3.4.2.12
2.16.840.1.101.3.4.2.13
2.16.840.1.101.3.4.2.14
2.16.840.1.101.3.4.2.15
2.16.840.1.101.3.4.2.16
2.16.840.1.101.3.4.2.2
2.16.840.1.101.3.4.2.3
2.16.840.1.101.3.4.2.4
2.16.840.1.101.3.4.2.5
2.16.840.1.101.3.4.2.6
2.16.840.1.101.3.4.2.7
2.16.840.1.101.3.4.2.8
2.16.840.1.101.3.4.2.9
2.16.840.1.101.3.4.3
2.16.840.1.101.3.4.3.1
2.16.840.1.101.3.4.3.10
2.16.840.1.101.3.4.3.11
2.16.840.1.101.3.4.3.12
2.16.840.1.101.3.4.3.13
2.16.840.1.101.3.4.3.14
2.16.840.1.101.3.4.3.15
2.16.840.1.101.3.4.3.16
2.16.840.1.101.3.4.3.2
2.16.840.1.101.3.4.3.3
2.16.840.1.101.3.4.3.4
2.16.840.1.101.3.4.3.5
2.16.840.1.101.3.4.3.6
2.16.840.1.101.3.4.3.7
2.16.840.1.101.3.4.3.8
2.16.840.1.101.3.4.3.9
acquireExistingProvider
acquireProvider@
alarm
animation-list
applyCompatConfiguration
applyConfigCompatMainThread
applyConfigurationToResources
AsyncTask #4
AsyncTask #5P
attachp
AutoLaunchSerialNumberNotFound
Binder_1
Binder_2
Binder_6
Checking update, please wait...
Cipher.1.2.840.113549.1.12.1.1
Cipher.1.2.840.113549.1.12.1.2
Cipher.1.2.840.113549.1.12.1.3
Cipher.1.2.840.113549.1.12.1.4
Cipher.1.2.840.113549.1.12.1.5
Cipher.1.2.840.113549.1.12.1.6
Cipher.1.2.840.113549.1.5.10
Cipher.1.2.840.113549.1.5.11
Cipher.1.2.840.113549.1.5.3
Cipher.1.2.840.113549.1.5.6
Cipher.2.16.840.1.101.3.4.1.25
Cipher.2.16.840.1.101.3.4.1.26
Cipher.2.16.840.1.101.3.4.1.45
Cipher.2.16.840.1.101.3.4.1.46
Cipher.2.16.840.1.101.3.4.1.5
Cipher.2.16.840.1.101.3.4.1.6
Cipher.2.16.840.1.101.3.4.2
Cipher.2.16.840.1.101.3.4.22
Cipher.2.16.840.1.101.3.4.42
Cipher.AES/CBC/PKCS5PADDING
Cipher.AES/CBC/PKCS7PADDING
Cipher.AES/ECB/PKCS5PADDING
Cipher.AES/ECB/PKCS7PADDING
Cipher.DESEDE/CBC/NOPADDING
Cipher.DESEDE/CBC/PKCS5PADDING
Cipher.DESEDE/CBC/PKCS7PADDING
Cipher.DESEDE/CFB/NOPADDING
Cipher.DESEDE/ECB/NOPADDING
Cipher.DESEDE/ECB/PKCS5PADDING
Cipher.DESEDE/ECB/PKCS7PADDING
Cipher.DESEDE/OFB/NOPADDING
Cipher.PBEWITHSHA1AND128BITRC4
Cipher.PBEWITHSHA1AND40BITRC4
Cipher.PBEWITHSHA1ANDDESEDE
Cipher.PBEWITHSHAAND128BITRC4
Cipher.PBEWITHSHAAND40BITRC4
Cipher.PBEWITHSHAANDTWOFISH-CBC
Cipher.RSA/ECB/PKCS1PADDING
Cipher.RSA/NONE/PKCS1PADDING
cleanUpPendingRemoveWindows0
CLG5
collectComponentCallbacks
com.teslacoilsw.launcher
completeRemoveProvider
conf/static.properties
Configuration file corrupted
CouldNotInitializeServerTimeX
createBaseContextForActivity
createThumbnailBitmap
currentActivityThread
currentApplication8
currentPackageName8
currentProcessName
debug_view_attributes
deliverNewIntents
deliverResults
doGcIfNeeded
dream2ltexx
dumpGraphicsInfo
dumpMemInfoTable8
edmno
ensureJitEnabled
FFFFFF
finishInstrumentation
freeTextLayoutCachesIfNeeded
getActivity8
getApplication
getApplicationThread
getHandler 
getInstrumentation
getIntCoreSetting
getIntentBeingBroadcastx0
getPackageInfo
getPackageInfoNoCheckH
getPackageManager
getProcessName@
getProfileFilePath
getSystemContext8
getTopLevelResources
handleBindApplication
handleBindService
handleCancelVisibleBehind
handleConfigurationChanged
handleCreateBackupAgent
handleCreateService
handleDestroyActivity
handleDestroyBackupAgent
handleDispatchPackageBroadcast
handleDumpActivity
handleDumpHeap8
handleDumpProvider
handleDumpService
handleEnterAnimationComplete
handleInstallProvider6
handleLaunchActivity
handleLowMemory8
handleNewIntent
handlePauseActivity
handleProfilerControl
handleReceiver8
handleRelaunchActivity
handleResumeActivity
handleSendResult
handleServiceArgs
handleSetCoreSettings
handleSleeping
handleStopActivity
handleStopService8
handleTrimMemory8
handleUnbindService
handleUnstableProviderDiedx0
handleWindowVisibility
https://secure.square-enix.com/account/app/svc/activation1?sqexid=%_RegistrationIdentifier_%&birthday=%_AuthorizationCode_%&clinetInitialVector1=%_InitialVector_%&clientPublickey=%_PublicKey_%&lang=en-us(
ImageButton
images/background.png
incProviderRefLocked
installContentProviders
installProvider
installSystemApplicationInfo
installSystemProvidersx0
isProfiling8
KeyAgreement.ECDH
KeyFactory.1.2.840.10040.4.1
KeyFactory.1.2.840.10045.2.1
KeyFactory.1.2.840.113549.1.1.1
KeyFactory.1.2.840.113549.1.1.7X
KeyFactory.1.2.840.113549.1.3.1
KeyFactory.DH
KeyFactory.DSA
KeyFactory.EC
KeyFactory.RSA
KeyGenerator.1.2.840.113549.2.7
KeyGenerator.1.2.840.113549.2.8
KeyGenerator.1.2.840.113549.2.9
KeyGenerator.1.2.840.113549.3.4
KeyGenerator.1.3.6.1.5.5.8.1.1
KeyGenerator.1.3.6.1.5.5.8.1.2
KeyPairGenerator.DH
KeyPairGenerator.DSA
KeyPairGenerator.EC
KeyPairGenerator.RSA
Launching view: 
linearInterpolator8
long_press_timeout
MessageDigest.1.3.14.3.2.26
MessageDigest.MD5
MessageDigest.SHA
MessageDigest.SHA1
MessageDigest.SHA-1
MessageDigest.SHA224
MessageDigest.SHA-224
MessageDigest.SHA256
MessageDigest.SHA-256
MessageDigest.SHA384
MessageDigest.SHA-384
MessageDigest.SHA512
MessageDigest.SHA-512
onNewActivityOptions
org.bouncycastle.pkcs1.strict
p B0
p Cipher.1.2.840.113549.1.9.16.3.6
p Cipher.PBEWITHSHAAND40BITRC2-CBC
p E%
p handleRequestAssistContextExtras
p handleUnstableProviderDiedLocked
p installProviderAuthoritiesLocked
p KeyFactory.1.3.133.16.840.63.0.2
p KeyGenerator.1.2.840.113549.2.10
p KeyGenerator.1.2.840.113549.2.11
p MessageDigest.1.2.840.113549.2.5
P MP
p registerOnActivityPausedListener0
p res/layout/activity_digipass.xml
p Signature.2.16.840.1.101.3.4.3.1
p Signature.2.16.840.1.101.3.4.3.2
p v>
p You must enter a local password.
p	dream2lte
p	getLooperp
p	H9
p!Cipher.PBEWITHSHA1AND40BITRC2-CBC
p!Cipher.PBEWITHSHAAND128BITRC2-CBC
p!Cipher.PBEWITHSHAAND3KEYTRIPLEDES
p!KeyGenerator.1.3.6.1.4.1.3029.1.2
p!org.bouncycastle.pkcs1.not_strict
p!PasswordCharactersNotAlphanumeric
p!Signature.OID.1.2.840.10045.4.3.1X
p!Signature.OID.1.2.840.10045.4.3.2
p!Signature.OID.1.2.840.10045.4.3.3X
p!Signature.OID.1.2.840.10045.4.3.4
p!Signature.SHA224WITHRSAENCRYPTION
p!Signature.SHA256WITHRSAENCRYPTION
p!Signature.SHA384WITHRSAENCRYPTION
p!Signature.SHA512WITHRSAENCRYPTION
p"Cipher.1.3.6.1.4.1.22554.1.1.2.1.2
p"Cipher.PBEWITHSHA1AND128BITRC2-CBC
p"handleActivityConfigurationChanged
p"OptionalApplicationUpdateAvailable
p"Signature.OID.1.2.840.113549.1.1.4
p"Signature.OID.1.2.840.113549.1.1.5
p"splashscreenBackgroundColor=FFFFFF
p"Token derivation is not supported.
p"unregisterOnActivityPausedListener
p#callCallActivityOnSaveInstanceState
p#Cipher.1.3.6.1.4.1.22554.1.1.2.1.22p
p#Cipher.1.3.6.1.4.1.22554.1.1.2.1.42
p#handleTranslucentConversionComplete
p#KeyGenerator.2.16.840.1.101.3.4.2.1
P#pE
p#Signature.OID.1.2.840.113549.1.1.11
p#Signature.OID.1.2.840.113549.1.1.12
p#Signature.OID.1.2.840.113549.1.1.13
p#Signature.OID.1.2.840.113549.1.1.14
p$Cipher.1.3.6.1.4.1.22554.1.2.1.2.1.2
p$Cipher.PBEWITHSHAAND128BITAES-CBC-BC`E
p$Cipher.PBEWITHSHAAND192BITAES-CBC-BC
p$Cipher.PBEWITHSHAAND256BITAES-CBC-BC
p$handleUpdatePackageCompatibilityInfo
p$MessageDigest.2.16.840.1.101.3.4.2.1
p$MessageDigest.2.16.840.1.101.3.4.2.2
p$MessageDigest.2.16.840.1.101.3.4.2.3
p$MessageDigest.2.16.840.1.101.3.4.2.4
P$pE
p$Signature.OID.2.16.840.1.101.3.4.3.1
p$Signature.OID.2.16.840.1.101.3.4.3.2
p%Cipher.1.3.6.1.4.1.22554.1.2.1.2.1.22
p%Cipher.1.3.6.1.4.1.22554.1.2.1.2.1.42
p%Cipher.PBEWITHSHA1AND128BITAES-CBC-BC
p%Cipher.PBEWITHSHA1AND192BITAES-CBC-BC
p%Cipher.PBEWITHSHA1AND256BITAES-CBC-BC
p&Cipher.PBEWITHSHA-1AND128BITAES-CBC-BC
p&Cipher.PBEWITHSHA-1AND192BITAES-CBC-BC
p&Cipher.PBEWITHSHA-1AND256BITAES-CBC-BC
p&Cipher.PBEWITHSHAAND2-KEYTRIPLEDES-CBC
p&Cipher.PBEWITHSHAAND3-KEYTRIPLEDES-CBC
p&handleOnBackgroundVisibleBehindChanged
p(Cipher.PBEWITHSHA-256AND128BITAES-CBC-BC
p(Cipher.PBEWITHSHA-256AND192BITAES-CBC-BC
p(Cipher.PBEWITHSHA-256AND256BITAES-CBC-BC
p)/data/data/com.square_enix_software_token
p)/data/data/com.square_enix_software_token`E
p)/data/misc/user/0/cacerts-added
p)/data/misc/user/0/cacerts-removed`E
p)AlgorithmParameters.1.2.840.10040.4.1
p)AlgorithmParameters.1.2.840.113549.3.7
p)AlgorithmParameters.1.3.14.3.2.27
p)AlgorithmParameters.1.3.14.3.2.7
p)AlgorithmParameters.1.3.6.1.4.1.3029.1.2
p)AlgorithmParameters.2.16.840.1.101.3.4.2
p)AlgorithmParameters.2.16.840.1.101.3.4.22
p)AlgorithmParameters.2.16.840.1.101.3.4.42
p)AlgorithmParameters.BLOWFISH
p)AlgorithmParameters.DIFFIEHELLMAN
p)AlgorithmParameters.PBEWITHSHA1ANDRC2
p)AlgorithmParameters.PBEWITHSHA1ANDRC2-CBC
p)AlgorithmParameters.PBEWITHSHAAND40BITRC4
p)AlgorithmParameters.PBEWITHSHAANDRC2
p)AlgorithmParameters.PBEWITHSHAANDRC4
p)AlgorithmParameters.PBEWITHSHAANDTWOFISH
p)AlgorithmParameters.PKCS12PBE
p)Cipher.PBEWITHMD5AND128BITAES-CBC-OPENSSL
p)Cipher.PBEWITHMD5AND192BITAES-CBC-OPENSSL
p)Cipher.PBEWITHMD5AND256BITAES-CBC-OPENSSL
p)KeyPairGenerator.1.2.840.10040.4.1
p)KeyPairGenerator.1.2.840.10045.2.1
p)KeyPairGenerator.1.2.840.113549.1.1.1
p)KeyPairGenerator.1.2.840.113549.1.1.7
p)KeyPairGenerator.1.2.840.113549.1.3.1
p)KeyPairGenerator.1.3.133.16.840.63.0.2
p)KeyPairGenerator.1.3.14.3.2.27
p)KeyPairGenerator.DIFFIEHELLMAN
P)pE
p)SecretKeyFactory.1.2.840.113549.1.12.1.1
p)SecretKeyFactory.1.2.840.113549.1.12.1.2
p)SecretKeyFactory.1.2.840.113549.1.12.1.3
p)SecretKeyFactory.1.2.840.113549.1.12.1.4
p)SecretKeyFactory.1.2.840.113549.1.12.1.5
p)SecretKeyFactory.1.2.840.113549.1.12.1.6
p)SecretKeyFactory.1.2.840.113549.1.5.10
p)SecretKeyFactory.1.2.840.113549.1.5.11
p)SecretKeyFactory.1.2.840.113549.1.5.3
p)SecretKeyFactory.1.2.840.113549.1.5.6
p)SecretKeyFactory.1.3.14.3.2.26
p)SecretKeyFactory.PBEWITHHMACSHA
p)SecretKeyFactory.PBEWITHHMACSHA1
p)SecretKeyFactory.PBEWITHMD5ANDDES
p)SecretKeyFactory.PBEWITHMD5ANDDES-CBC
p)SecretKeyFactory.PBEWITHMD5ANDRC2
p)SecretKeyFactory.PBEWITHMD5ANDRC2-CBC
p)SecretKeyFactory.PBEWITHSHA1ANDDES
p)SecretKeyFactory.PBEWITHSHA1ANDDES-CBC
p)SecretKeyFactory.PBEWITHSHA1ANDRC2
p)SecretKeyFactory.PBEWITHSHA1ANDRC2-CBC
p)SecretKeyFactory.PBEWITHSHAAND128BITRC4
p)SecretKeyFactory.PBEWITHSHAAND40BITRC4
p)SecretKeyFactory.PBEWITHSHAANDTWOFISH-CBC
p)SecretKeyFactory.PBKDF2WITHHMACSHA1
p*AlgorithmParameterGenerator.1.3.14.3.2.27
p*AlgorithmParameterGenerator.DH
p*AlgorithmParameterGenerator.DIFFIEHELLMAN
p*AlgorithmParameterGenerator.DSA
p*AlgorithmParameters.2.16.840.1.101.3.4.1.2
p*AlgorithmParameters.2.16.840.1.101.3.4.1.6
p*AlgorithmParameters.PBEWITHSHAAND128BITRC4
p*org.bouncycastle.asn1.allow_unsafe_integer
p*SecretKeyFactory.PBEWITHSHAAND40BITRC2-CBC
p*SecretKeyFactory.PBKDF2WITHHMACSHA1AND8BIT
p*SecretKeyFactory.PBKDF2WITHHMACSHA1ANDUTF8
p,AlgorithmParameters.PBEWITHSHAANDDES2KEY-CBC
p,AlgorithmParameters.PBEWITHSHAANDDES3KEY-CBC
p,AlgorithmParameters.PBEWITHSHAANDTWOFISH-CBC(
p,SecretKeyFactory.1.3.6.1.4.1.22554.1.1.2.1.2(
p,Signature.1.3.14.3.2.26WITH1.2.840.10040.4.1
p,Signature.1.3.14.3.2.26WITH1.2.840.10040.4.3
p,Signature.1.3.14.3.2.26WITH1.2.840.10045.2.1(
p./data/app/com.square_enix_software_token-1/lib
p./data/app/com.square_enix_software_token-1/lib(
p.AlgorithmParameters.PBEWITHSHAAND128BITRC2-CBC(
p.AlgorithmParameters.PBEWITHSHAAND3KEYTRIPLEDES
P.pE
p.SecretKeyFactory.PBEWITHSHAAND128BITAES-CBC-BC
p.SecretKeyFactory.PBEWITHSHAAND192BITAES-CBC-BC(
p.SecretKeyFactory.PBEWITHSHAAND256BITAES-CBC-BC
p/		
p//data/data/com.square_enix_software_token/files
p/AlgorithmParameters.1.3.6.1.4.1.22554.1.1.2.1.2
p/AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES
p/AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES
p/SecretKeyFactory.PBEWITHSHA1AND128BITAES-CBC-BC
p/SecretKeyFactory.PBEWITHSHA1AND192BITAES-CBC-BC
p/SecretKeyFactory.PBEWITHSHA1AND256BITAES-CBC-BC
p/Signature.1.3.14.3.2.26WITH1.2.840.113549.1.1.1
p/Signature.1.3.14.3.2.26WITH1.2.840.113549.1.1.5
p:Required only if your application provider sent it to you.(
p:The network response does not include the activation data.
p:The serial number has an invalid length (it should be 10).
p?/data/data/com.square_enix_software_token/cache
p?/data/data/com.square_enix_software_token/shared_prefs
p@Dalvik/1.2.3 (Linux; U; Android 1.2.3; SM-G123A Build/ABC12D)
p~/data/data/com.square_enix_software_token/shared_prefs/com.vasco.digipass.mobile.android.views.activities.DigipassActivity.xml
p+AlgorithmParameters.1.2.840.113549.1.12.1.1
p+AlgorithmParameters.1.2.840.113549.1.12.1.2
p+AlgorithmParameters.1.2.840.113549.1.12.1.3
p+AlgorithmParameters.1.2.840.113549.1.12.1.4(
p+AlgorithmParameters.1.2.840.113549.1.12.1.5
p+AlgorithmParameters.1.2.840.113549.1.12.1.6
p+AlgorithmParameters.2.16.840.1.101.3.4.1.22
p+AlgorithmParameters.2.16.840.1.101.3.4.1.26(
p+AlgorithmParameters.2.16.840.1.101.3.4.1.42
p+AlgorithmParameters.2.16.840.1.101.3.4.1.46
p0AlgorithmParameters.1.3.6.1.4.1.22554.1.1.2.1.22
p0AlgorithmParameters.1.3.6.1.4.1.22554.1.1.2.1.42
p0SecretKeyFactory.PBEWITHSHA-1AND128BITAES-CBC-BC
p0SecretKeyFactory.PBEWITHSHA-1AND192BITAES-CBC-BC
p0SecretKeyFactory.PBEWITHSHA-1AND256BITAES-CBC-BC
p1AlgorithmParameters.1.3.6.1.4.1.22554.1.2.1.2.1.2
p1AlgorithmParameters.PBEWITHSHAAND128BITAES-CBC-BC
p1AlgorithmParameters.PBEWITHSHAAND192BITAES-CBC-BC
p1AlgorithmParameters.PBEWITHSHAAND256BITAES-CBC-BC
p2/data/app/com.square_enix_software_token-1/lib/x86(
p2AlgorithmParameters.1.3.6.1.4.1.22554.1.2.1.2.1.22
p2AlgorithmParameters.1.3.6.1.4.1.22554.1.2.1.2.1.42
p2AlgorithmParameters.PBEWITHSHA1AND128BITAES-CBC-BC
p2AlgorithmParameters.PBEWITHSHA1AND192BITAES-CBC-BC
p2AlgorithmParameters.PBEWITHSHA1AND256BITAES-CBC-BC
p3/data/app/com.square_enix_software_token-1/base.apkHT
p3AlgorithmParameters.PBEWITHSHA-1AND128BITAES-CBC-BC
p3AlgorithmParameters.PBEWITHSHA-1AND192BITAES-CBC-BC
p3AlgorithmParameters.PBEWITHSHA-1AND256BITAES-CBC-BC
p3AlgorithmParameters.PBEWITHSHAAND2-KEYTRIPLEDES-CBC
p3AlgorithmParameters.PBEWITHSHAAND3-KEYTRIPLEDES-CBC
p3BiometricFingerprintRecognitionAuthenticationFailed
p3res/drawable-mdpi-v4/progressbar_indeterminate1.png
p3res/drawable-mdpi-v4/progressbar_indeterminate2.png
p3res/drawable-mdpi-v4/progressbar_indeterminate3.png
p3SecretKeyFactory.PBEWITHMD5AND128BITAES-CBC-OPENSSL
p3SecretKeyFactory.PBEWITHMD5AND192BITAES-CBC-OPENSSL
p3SecretKeyFactory.PBEWITHMD5AND256BITAES-CBC-OPENSSL
p3xmlSigningErrorMessage=Configuration file corrupted
p4AlgorithmParameters.PBEWITHSHA256AND128BITAES-CBC-BC
p4AlgorithmParameters.PBEWITHSHA256AND192BITAES-CBC-BC
p4AlgorithmParameters.PBEWITHSHA256AND256BITAES-CBC-BC
p4An internal error occurred with code: %_ErrorCode_%.
p4dream2ltexx-user 1.2.3 ABC12D 500000000 release-keys
p4MultiDeviceActivationCryptoApplicationIndexIncorrect
p4MultiDeviceInstanceActivationMessageLicenseIncorrect
p4MultiDeviceLicenseActivationMessageSignatureNotValid
p4res/drawable-mdpi-v4/scrollbar_handle_vertical.9.png
p4Signature.1.2.840.113549.2.5WITH1.2.840.113549.1.1.1
p5AlgorithmParameters.PBEWITHSHA-256AND128BITAES-CBC-BC
p5AlgorithmParameters.PBEWITHSHA-256AND192BITAES-CBC-BC
p5AlgorithmParameters.PBEWITHSHA-256AND256BITAES-CBC-BC
p5MultiDeviceInstanceActivationMessageDeviceIdIncorrect
p5MultiDeviceInstanceActivationMessageSignatureNotValid
p5Signature.2.16.840.1.101.3.4.2.1WITH1.2.840.10045.2.1
p5Signature.2.16.840.1.101.3.4.2.2WITH1.2.840.10045.2.1
p5Signature.2.16.840.1.101.3.4.2.3WITH1.2.840.10045.2.1
p5Signature.2.16.840.1.101.3.4.2.4WITH1.2.840.10045.2.1
p5The activation response does not include a challenge.(
p6res/drawable-mdpi-v4/scrollbar_handle_horizontal.9.png
p6The maximal length for the challenge is %_MaxLength_%.
p6The minimal length for the challenge is %_MinLength_%.
p8An error occured during Root Detection with error code: (
p8Signature.2.16.840.1.101.3.4.2.1WITH1.2.840.113549.1.1.1
p8Signature.2.16.840.1.101.3.4.2.2WITH1.2.840.113549.1.1.1
p8Signature.2.16.840.1.101.3.4.2.3WITH1.2.840.113549.1.1.1
p8Signature.2.16.840.1.101.3.4.2.4WITH1.2.840.113549.1.1.1
p8The application has been locked. It must be reactivated.
p8This activation message cannot be used with this device.
p9BiometricFingerprintRecognitionFallbackDescriptionMessage
p9Signature.2.16.840.1.101.3.4.2.1WITH1.2.840.113549.1.1.11
p9Signature.2.16.840.1.101.3.4.2.4WITH1.2.840.113549.1.1.11
p9The confirmation password does not match to the password.
package
p-AlgorithmParameters.PBEWITHSHAAND40BITRC2-CBC(
PasswordCharactersNotNumeric
pbcom.square_enix_software_token/com.vasco.digipass.mobile.android.views.activities.DigipassActivity
p'Cipher.PBEWITHSHA1AND2-KEYTRIPLEDES-CBC
p'Cipher.PBEWITHSHA1AND3-KEYTRIPLEDES-CBC
p'Cipher.PBEWITHSHA256AND128BITAES-CBC-BC
p'Cipher.PBEWITHSHA256AND192BITAES-CBC-BC
p'Cipher.PBEWITHSHA256AND256BITAES-CBC-BC
pCPlease authenticate using face recognition to protect your DIGIPASS
peekPackageInfo
performDestroyActivity
performNewIntents
performPauseActivity(
performRestartActivity
performResumeActivity
performStopActivity(
performUserLeavingActivity
pFsamsung/dream2ltexx/dream2lte:1.2.3/ABC12D/500000000:user/release-keys
pHThis image is not a relevant image to finalize your DIGIPASS activation.
pHYour device is jailbroken or rooted. The application cannot be executed.h
pIThe crypto application used for the multi-device activation is not valid.
pIThis message is not a relevant message to start your DIGIPASS activation.
pJPlease authenticate using fingerprint recognition to protect your DIGIPASS
pmaq:pending:com.square_enix_software_token/com.vasco.digipass.mobile.android.views.activities.DigipassActivity
pMThe location service is turned off. Please check your settings to turn it on.
pOcom.samsung.android.fingerprint.FingerprintManager$FingerprintClientSpecBuilder
ppThis function requires Internet connectivity. You must connect to a Wi-Fi or cellular data network to access it.
ProgressBar8
p-SecretKeyFactory.1.3.6.1.4.1.22554.1.1.2.1.22
pSYou need to be connected to the internet to continue. Please connect and try again.
ptaq:native-pre-ime:com.square_enix_software_token/com.vasco.digipass.mobile.android.views.activities.DigipassActivity
puaq:native-post-ime:com.square_enix_software_token/com.vasco.digipass.mobile.android.views.activities.DigipassActivity
pVSQUARE ENIX Software Token Ver.1.6.3
pVThe check for security updates have failed. Please make sure you have internet access.
pXThe settings of your application have been modified. You must re-activate your DIGIPASS.
RelativeLayout
releaseProvider8
requestRelaunchActivity
res/layout/screen_simple.xml
res/layout/splash_screen.xml
resolveActivityInfo(
ResultResponse
samsungexynos8890
SANS_SERIF-Bold.otf
SANS_SERIF-Bold.ttf
scheduleContextCleanup
scheduleGcIdler8
se.infra
sendActivityResult8
serialNumber=%_SerialNumber_%&derivationCode=%_DerivationCode_%&clientNonce=%_Nonce_%&clinetInitialVector2=%_InitialVector_%&deviceId=%_DeviceIdentifier_%&lang=en-us(
Settings button
SHA-512/224
SHA-512/256
Signal Catcher8
Signature.1.2.840.10040.4.1
Signature.1.2.840.10040.4.3
Signature.1.2.840.10045.4.1
Signature.1.2.840.10045.4.3.1
Signature.1.2.840.10045.4.3.2
Signature.1.2.840.10045.4.3.3
Signature.1.2.840.10045.4.3.4
Signature.1.2.840.113549.1.1.11
Signature.1.2.840.113549.1.1.12
Signature.1.2.840.113549.1.1.13
Signature.1.2.840.113549.1.1.14X
Signature.1.2.840.113549.1.1.4
Signature.1.2.840.113549.1.1.5
Signature.MD5WITHRSAENCRYPTION
Signature.OID.1.3.14.3.2.29X
Signature.SHA1WITHRSAENCRYPTION
SM-G123A
splashscreenBackgroundColorX
splashscreenImage=welcome.png
SQUARE ENIX CO., LTD. All Rights Reserved.
SSLContext.DEFAULT
SSLContext.SSL
SSLContext.SSLV3
SSLContext.TLS
SSLContext.TLSV1.1
SSLContext.TLSV1.2
SSLContext.TLSV18
startActivityNow`"
StaticVectorIncorrectFormat
StaticVectorIncorrectLength
The local password is weak.
The password must be numerical.
This application requires access to the camera to perform this action. Please enable the camera permission in the Settings menu of your device.
time_12_24
TokenDerivationNotSupported
universal8890
unscheduleGcIdler
welcome.png
window
1.2.840.113549.1.12.1.6
1.2.840.113549.1.9.22.1
AES/CBC8
AES/SIC@
default
en-US
p:com.vasco.digipass.mobile.android.core.DPMobileApplication
p2/data/app/com.square_enix_software_token-1/lib/x86
pCcom.vasco.digipass.mobile.android.views.activities.DigipassActivity
pEThe local password is too short. The minimal length is %_MinLength_%.
pH/data/data/com.square_enix_software_token/files/VDS_dfms4142
pJThe validation of the password failed. Tries remaining: %_RemainingTries_%
samsung
AES/SIC8
instance0fingerprintVersion
instance0name
p*/data/app/com.square_enix_software_token-1
pVThe Square Enix ID, date of birth, and registration password you entered do not match.
p3/data/app/com.square_enix_software_token-1/base.apk
eula
false
instance0biometricUsed
instance0initialized
instance0pwdFrmt
instance0rId
instance0tds
LATER
AES/SIC
```
</details>

#### logcat

The logcat logs don't show anything useful. The output doesn't change when generating the OTP. This should be used once some print statements are added to the code, helped by using jadx-gui.

Helpful Nox commands for adb (drops you into a root shell):
```
cd "C:\Program Files (x86)\Nox\bin"
nox_adb.exe connect 127.0.0.1:62001
nox_adb.exe -s 127.0.0.1:62001 shell
```

<br>

##  Next steps

#### Debug the app

For the next part of the investigation, I've added debug flags to every line (hoping to catch something), but I'm unable to run the smali code on the android emulator. Not sure what I'm doing wrong, buit I think it needs to know what the main method/Module is, and I'm not sure.

I've also tried running the app in Android Studio (after setting the Debug flag to true by decompiling it with APK Easy Tool first, and removing libQRCronto.so (which isn't used)). Steps for this are here: https://stackoverflow.com/questions/2409923/what-do-i-have-to-add-to-the-manifest-to-debug-an-android-application-on-an-actu
libQRCronto.so


If Android Studio doesn't work, then I'll try using Frida to trace function calls:
https://frida.re/docs/android/

I may also try to use GHIDA again (though I couldn't understand assembly).

It's been strongly recommended to look at the decompiled smali code instead of using a compiler to Java, because you have to fix Java classes and libraries yourself, and with the obfuscated code it becomes too much.

<br>

#### Check older versions

Previous versions are available here: https://apkpure.com/square-enix-software-token/com.square_enix_software_token

Searching for libQRCronto.so shows other apps using the same framework, so that could be interesting to compare against. Only one app still seems to be using this framework, the others (at least from the screenshots) appear to have moved to something else.

https://play.google.com/store/apps/details?id=com.eTokenBCR

It may also be useful to look for older versions of the app. The one in the example usage screenshots on the Square Enix website show a version back to 2013 (see: https://cache.secure.square-enix.com/account/content/images/gb/otp/manual_serial.png?ver=09202127021722)

Note: While is says Software Token n version 4.0.7 on the screenshot, the latets version is 1.6.3. On The latest version though, it shows a different field (System Version) as 4.17.1.

## Links:

https://report.ostorlab.co/scan/43403/share/yqlfhqmfmm.xjqttfdqbbdicreirgupeqcbrzcwqbquneejcahockfksmqaouizmudmdflqaxne - APK scan

https://www.bignox.com/ - Download Nox

https://portswigger.net/burp/communitydownload - Download BurpSuite

http://bowneconsultingcontent.com/liz/Attack/proj/A31bburpwin.htm - Setting up Nox and Burp

https://gist.github.com/Log1x/12d330ef7685d6fbc611d1d57efb5c29 - De-bloating Nox, but set root to true

https://forum.xda-developers.com/showthread.php?t=1523691 - MiXplorer - for copying files within Nox

https://www.apkmirror.com/apk/teslacoil-software/nova-launcher/ - Nova Launcher apk

https://secure.square-enix.com/account/app/svc/otpTop - Square Enix OTP page

## Notable mentions:
Very little comes up online when trying to look into this, so I've collected all of the useful links below:

https://github.com/winauth/winauth/issues/639 - Mentions that it can't be done

https://github.com/winauth/winauth/issues/621#issuecomment-413174476 - Mentions the Software token

https://github.com/KeeTrayTOTP/KeeTrayTOTP/issues/3#issuecomment-328408221 - Mentions the Square authenticator
