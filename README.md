# Square-Enix-Software-Token-OTP
Findings when looking into the Square Enix Software Token.

tl;dr: The Square Enix Software Token uses it's own proprietary method to generate OTP codes, and can't be added to existing apps like Google Authenticator. It uses Vasco (Now OneSpan) DIGIPASS for Mobile (https://www.onespan.com/products/mobile-authentication / https://www.authstrong.com/DIGIPASS-Mobile-Enterprise-Security.asp), which is similar to RSA SecurID, and NOT the OTP standard.
It may be possible to reverse the process by which it generates OTP codes (like with the Steam OTP codes), but then we may as well use the app.

Process for adding the software OTP:
<add steps>

Notes:
1. The token is stored in /data/data/com.square_enix_software_token/files/VDS_dfms4142
2. The token always starts with "0004", but has a length of 1960 characters
3. The token is in uppercase hex
4. The token is generated using the libQRCronto.so library
4.1. /data/app/com.square_enix_software_token-1/lib/arm/libQRCronto.so
4.1.1 This may just be "com.square_enix_software_token" on some devices.
5. The OTP is valid for 30 seconds (old phone) or 60 seconds (Nox)
5.1. On newer devices, a new code is generated each time the "Show One-Time Password" button is clicked, and lasts for 60 seconds.
5.2. On older devices, only one code can be generated every 30 seconds, even if you go back and forth.
6. Uses either sha256 (vdsSHA256Initial_hash_value) or sha512 (vdsSHA512Initial_hash_value)
7. Related to VASCO DIGIPASS for Mobile (http://www.authstrong.com/DIGIPASS-Mobile.asp)
8. None of the strings below work as a OTP seed, because they contain illegal characters (e.g. "1")
9. Only the initial registration needs to be done online. Generating codes can be done offline.

Network capture results:
<add guide, including installing the CA cert> (https://stackoverflow.com/a/51485753)
<insert burp results>

Reverse engineering the apk:
<add steps from http://www.javadecompilers.com/apk >

Reverse engineering libQRCronto.so:
<add Ghidra results>

Links:
https://www.bignox.com/ - Download Nox
https://portswigger.net/burp/communitydownload - Download BurpSuite
http://bowneconsultingcontent.com/liz/Attack/proj/A31bburpwin.htm - Setting up Nox and Burp
https://gist.github.com/Log1x/12d330ef7685d6fbc611d1d57efb5c29 - De-bloating Nox, but set root to true
https://forum.xda-developers.com/showthread.php?t=1523691 - MiXplorer - for copying files within Nox
https://www.apkmirror.com/apk/teslacoil-software/nova-launcher/ - Nova Launcher apk

https://secure.square-enix.com/account/app/svc/otpTop - Square Enix OTP page

Notable mentions:
Very little comes up online when trying to look into this, so I've collected all of the useful links below:
https://github.com/winauth/winauth/issues/639 - Mentions that it can't be done
https://github.com/winauth/winauth/issues/621#issuecomment-413174476 - Mentions the Software token
https://github.com/KeeTrayTOTP/KeeTrayTOTP/issues/3#issuecomment-328408221 - Mentions the Square authenticator
