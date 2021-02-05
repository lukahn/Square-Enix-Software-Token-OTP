# Square-Enix-Software-Token-OTP
Findings when looking into the Square Enix Software Token.

tl;dr: The Square Enix Software Token uses it's own proprietary method to generate OTP codes, and can't be added to existing apps like Google Authenticator. It uses Vasco (now OneSpan) DIGIPASS for Mobile (https://www.onespan.com/products/mobile-authentication / https://www.authstrong.com/DIGIPASS-Mobile-Enterprise-Security.asp), which is similar to RSA SecurID, and NOT the OTP standard.
It may be possible to reverse the process by which it generates OTP codes (like with the Steam OTP codes), but then we may as well use the app.

Process for adding the software OTP:
<add steps>

## Notes:
1. The token is stored in /data/data/com.square_enix_software_token/files/VDS_dfms4142
1. The token always starts with "0004", but has a length of 1960 characters.
1. The token is in uppercase hex.
1. The token is generated using the libQRCronto.so library.
    1. /data/app/com.square_enix_software_token-1/lib/arm/libQRCronto.so
        1. This may just be "com.square_enix_software_token" on some devices.
1. The OTP is valid for 30 seconds (old phone) or 60 seconds (Nox).
    1.  On older devices, only one code can be generated every 30 seconds, even if you go back and forth.
    1.  On newer devices, a new code is generated each time the "Show One-Time Password" button is clicked, and lasts for 60 seconds.
1. Uses either sha256 (vdsSHA256Initial_hash_value) or sha512 (vdsSHA512Initial_hash_value).
1. Related to VASCO DIGIPASS for Mobile (http://www.authstrong.com/DIGIPASS-Mobile.asp).
1. None of the strings below work as an OTP seed, because they contain illegal characters (e.g. "1").
1. Only the initial registration needs to be done online. Generating codes can be done offline.

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

serialNumber=XYZ1234567&derivationCode=0123456789012345&clientNonce=0123456789ABCDEF0123456789ABCDEF&clinetInitialVector2=4D47BBCD86751458E6552FD8AE46E5E8&deviceId=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF&lang=en-us
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

##  Next steps

For the next part of the investigation, I'll try running the app in Android Studio (after setting the Debug flag to true by decompiling it with APK Easy Tool first). Steps for this are here: https://stackoverflow.com/questions/2409923/what-do-i-have-to-add-to-the-manifest-to-debug-an-android-application-on-an-actu

If Android Studio doesn't work, then I'll try using Frida to trace function calls:
https://frida.re/docs/android/

I may also try to use GHIDA again (though I couldn't understand assembly).

It's been strongly recommended to look at the decompiled smali code instead of using a compiler to Java, because you have to fix Java classes and libraries yourself, and with the obfuscated code it becomes too much.

<br>

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
