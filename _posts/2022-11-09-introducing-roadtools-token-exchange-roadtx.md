---
layout: single
classes: wide
title:  "Introducing ROADtools Token eXchange (roadtx) - Automating Azure AD authentication, Primary Refresh Token (ab)use and device registration"
date:   2022-11-09 12:08:57 +0100
---
Ever since the initial release of [ROADrecon](https://dirkjanm.io/introducing-roadtools-and-roadrecon-azure-ad-exploration-framework/) and the ROADtools framework I have been adding new features to it, especially on the authentication side. As a result, it supports many forms of authentication, such as using [Primary Refresh Tokens](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/) (PRTs), PRT cookies, and regular access/refresh tokens. The authentication modules are all part of the shared library roadlib, and can be used in other tools by importing the library. Even though you can request tokens for any Azure AD connected resource and with many client IDs, the only tool exposing this authentication part was ROADrecon. It always felt unnatural and illogical to tell people that you can use a recon tool to request tokens for many other purposes. So I decided to start writing a new tool, which resolves around requesting and using Azure AD tokens. As I was working on this, I started adding proof of concepts I wrote during my Azure AD devices research into the tool, adding support for registering devices and requesting Primary Refresh Tokens using device credentials. I also added various modules for injecting PRTs into browser sessions with Selenium, and for automating authentication with MFA. The result is a comprehensive tool called ROADtools Token eXchange, or simply roadtx. Currently it has the following capabilities:

* Register and join devices to Azure AD.
* Request Primary Refresh Tokens from user credentials or other valid tokens.
* Use Primary Refresh Tokens in a similar way as the Web Account Manager (WAM) in Windows does.
* Perform several different Oauth2 token redemption flows.
* Perform interactive logins based on Browser SSO by injecting the Primary Refresh Token into the authentication flow.
* Add SSO capabilities to Chrome via the Windows 10 accounts plugin and a custom browsercore implementation.
* Automate sign-ins, MFA and token requesting to various resources in Azure AD by using Selenium.
* Possibility to load credentials and MFA TOTP seeds from a KeePass database to use in (semi-)automated flows.

In this blog I will describe the tools features and show some demonstrations of the cool stuff you can do with it. You can also skip directly to [GitHub](https://github.com/dirkjanm/ROADtools) or read the [Wiki](https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)) for details on each command.

# roadtx structure
roadtx is structured as a wrapper tool around features implemented in roadlib. With the release of roadtx, a new class has been added to roadlib with all device authentication logic, containing functions that register/join devices and can request or use Primary Refresh Tokens in the same way that Windows uses them. In roadtx itself, there is a class with helper functions for [Selenium](https://www.selenium.dev/)-based authentication and support for intercepting browser requests to add SSO features to the browser window.

The main function of roadtx itself is about 400 lines of code to construct an (I hope) straightforward collection of commands with their parameters. It also has about 300 lines of code to deal with the commands and call library functions with the data needed. The actual device logic being in roadlib means that it is possible to re-use it in other tools or to make light standalone tools without needing all the roadtx specific dependencies.

I've also tried to make it intuitive and straightforward to use roadtx, reducing the command line arguments needed to perform specific actions. For example, `roadtx device` will register a device with randomized defaults, and functions dealing with Primary Refresh Tokens will by default load the PRT from a `roadtx.prt` file, so you don't have to specify it every time you use a function.

# Using roadtx
## Devices and Primary Refresh Tokens
Most of the modules of roadtx are designed around Primary Refresh Tokens and device identities. To obtain a PRT, we must first register a device in Azure AD. Registering a device requires an access token to the device registration service resource. The access token must be a token without a device claim, so you cannot use single sign-on or an existing PRT to request one. There are a few ways to obtain such a token with roadtx, where some methods support MFA and others do not. MFA could be required to register a device, depending on tenant settings. If it is not, you can request a token for the device registration service (specified here through the _devicereg_ alias) with only a username and password:

```
roadtx gettokens -u myuser@mytenant.com -p password -r devicereg
```

If MFA is required, you can use the device authentication flow to request the tokens from a browser window somewhere:

```
roadtx gettokens --device-auth -r devicereg
```

Alternatively, we can already skip ahead a bit to the functionalities shown later in this blog, and use a Selenium based window for MFA, while autofilling the username + password:

```
roadtx interactiveauth -u myuser@mytenant.com -p password -r devicereg
```

Any of the commands above with save an access token to the `.roadtools_auth` file. The device registration command will automatically load it from this file. You can customize what you want for device properties with various commandline parameters to the `roadtx device` module:

![device command](/assets/img/roadtx/roadtx_device.png)

We register an Azure AD joined device with the name "blogdevice":

```
roadtx device -n blogdevice
Saving private key to blogdevice.key
Registering device
Device ID: 5f138d8b-6416-448d-89ef-9b279c419943
Saved device certificate to blogdevice.pem
```

We get two pieces of data that identify our device. The first is the device certificate saved in `blogdevice.pem`, which is issued by Azure AD and identifies our device. The second part is the `blogdevice.key` file, which contains the private key of the certificate and is also used as transport key. Now that we have the device certificate, we can do operations that require a device identity. The most useful one is requesting a Primary Refresh Token, since that will enable us to add Single Sign On capabilities to our (interactive or automated) token requests.

### Requesting a Primary Refresh Token
A primary refresh token is most often requested with a username and password. When you log in to an Azure AD joined or hybrid joined workstation with your username and password, Windows immediately requests a PRT from Azure AD. I've talked about the technicalities behind this flow at my Troopers and Romhack [talks](/talks/) in the past, so if you're interested in the technicalities have a read through those slides. To request a PRT with roadtx, run the `roadtx prt` command, specify the device cert/key and the username + password to use, and you get a PRT:

```
roadtx prt -u myuser@mytenant.com -p password --key-pem blogdevice.key --cert-pem blogdevice.pem
```

The command will give us a PRT (in the form of an encrypted token), and a session key that we need to use the PRT. The PRT is by default saved to `roadtx.prt`, where it can be picked up by other roadtx modules.

A PRT is by default valid for 90 days, but we can renew it at any time to extend the validity for another 90 days with the `renew` action:

```
roadtx prt -a renew
Renewing PRT
Saved PRT to roadtx.prt
```

Note that the PRT we requested here is only based on a password, so any authentication that requires MFA will fail even if we use the PRT. We can also upgrade or "enrich" the PRT with an MFA claim, this is shown in the next section on Selenium based authentication.

### Using Primary Refresh Tokens on the command line
Once we have a PRT, we can use it to sign in to resources that accept Azure AD authentication. You can do this either with the `roadtx gettokens` command, and specify the PRT and session key on the command line, or use the `roadtx prtauth` command. The difference between the two is that the `gettokens` command implements authentication that is based on how Chrome does Single Sign On in the browser. This method is slightly hacky and if it fails won't give you any feedback.

The `prtauth` module instead emulates the Web Account Manager (WAM) that Windows uses if you request access tokens from an app or native process. The WAM acts like a token broker, and requests tokens on behalf of other clients. It uses a combination of signed requests and encrypted responses to prevent exposing the tokens in transit, all done using the PRT session key. roadtx implements these flows and is able to perform the same authentication. In practice, you can use this module with any client that is either marked as public or has a redirect URL for a native app. By default, the `roadtx prtauth` module with use the Azure AD PowerShell Module client ID and the Azure AD graph as resource, but you can specify any other client ID or resource URL either by its full part or as an alias (listable with `roadtx listaliases`):

```
roadtx prtauth
Tokens were written to .roadtools_auth
```

Example using the Azure CLI as client ID and requesting tokens for the Azure Resource Manager:

```
roadtx prtauth -c azcli -r azrm     
Tokens were written to .roadtools_auth
```

There's also other options you can use to specify other resources or the correct redirect URL for the app you are using:

![prtauth command](/assets/img/roadtx/roadtx_device.png)

# Selenium based Azure AD authentication
Command line based token requests and usage are nice, but often you will encounter some flow that either requires a browser window to do Multi Factor Authentication, or you simply want to use your PRT in an interactive way to browse things like the Azure Portal or just read your mail using a stolen PRT. roadtx supports this in various ways, via methods based on [Selenium](https://selenium.dev). For Selenium based methods to work you first need to download the [gecko driver](https://github.com/mozilla/geckodriver/releases) since roadtx uses Selenium and the gecko driver to control the browser window (based on Firefox). You should either put the geckodriver in your PATH, in the directory you run the roadtx commands from, or any other location if you want to specify the path manually each time.

The principle of Selenium based operations in roadtx is simple: it launches a browser window, tries to autofill any credentials that you supplied to the command, and let you fill in the rest by hand. If you have your accounts set up correctly, it will do the authentication fully automatically. I use this frequently for research purposes where dealing with multiple identities, need to get tokens for different resources, and/or am testing with MFA enabled. It can also be used to automatically inject PRTs into the authentication flow and to use them to browse sites with automatic authentication.

## Interactive authentication
In the simplest form, roadtx will launch a browser for you, request a token for the indicated service, fill in any credentials you specified, and obtain tokens. Example:

```
roadtx interactiveauth -u myuser@mytenant.com -p password
```

If MFA is required, you can enter that and obtain a token with MFA claim. If not, it will capture the output and save the requested tokens. You can specify the client ID you want to use with `-c` and the resource to authenticate to with `-r`. Here's a short demo:

<video width="100%" controls>
  <source src="/assets/video/selenium_autofill.mp4" type="video/mp4">
  <source src="/assets/video/selenium_autofill.webm" type="video/webm">
</video> 

## KeePass credentials based authentication
If you're dealing with many different accounts during research, copy/pasting credentials and entering MFA information becomes quite tedious. roadtx supports sourcing credentials and TOTP based MFA information from a kdbx file (KeePass file) or KeePass XML export. To use this, use the `roadtx keepassauth` command. It accepts a KeePass file with the `-kp` parameter or if you leave this parameter out it tries to load `roadtx.kdbx` from the current directory. The password of the KeePass file can be specified with `-kpp` or via the `KPPASS` environment variable. The only required parameter is the username, which it will look up in the KeePass file. It will autofill the password and also the OTP code if "Mobile app OTP" is enabled as an MFA method on the account. This requires the TOTP seed to be stored in the `otp` additional parameter of the identity in the KeePass file. For instructions on how to set this up and some caveats of using KeePass files, see the [roadtx wiki](https://github.com/dirkjanm/ROADtools/wiki/ROADtools-Token-eXchange-(roadtx)).

Here is another demo of authentication to the Microsoft Graph using an account that requires MFA, the credentials and OTP are automatically loaded from the KeePass file:

<video width="100%" controls>
  <source src="/assets/video/selenium_kpautofill.mp4" type="video/mp4">
  <source src="/assets/video/selenium_kpautofill.webm" type="video/webm">
</video> 

Aside from requesting tokens directly, you can also use this as an interactive browser window with auto authentication. To do this, specify a URL manually that will redirect you to the Microsoft sign-in page. For example, using `-url https://myaccount.microsoft.com` will open a browser, authenticate you, and go to the "My account" page. You can use `--keep-open` to keep the browser window open after authentication, which makes it possible to browse to other pages from an authenticated perspective. Example:

```
roadtx keepassauth -url https://myaccount.microsoft.com --keep-open -u myuser@mytenant.com -kp accounts.kdbx -kpp keepassfilepassword
```

## Primary Refresh Token authentication in browser
A more interesting scenario is using a Primary Refresh Token that you either registered yourself or that you [stole from a legitimate endpoint](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/) during a red team to create an interactive browser experience. Lets assume that we dumped a PRT and session key using Mimikatz from an endpoint (this is only possible if it doesn't use a Trusted Platform Module). We can use this PRT on the command line, or we can automatically inject that into our Selenium browser session. roadtx does this by proxying the browser traffic through itself and injecting a PRT cookie at various points during authentication. On the victim endpoint, we can use Mimikatz to dump the PRT and session key, with the following commands:

```
privilege::debug
sekurlsa::cloudap
```

Mimikatz gives us the PRT and encrypted session key (the _KeyValue_ of the _ProofOfPossesionKey_ field), which we can decrypt from a `SYSTEM` context.

```
token::elevate
dpapi::cloudapkd /keyvalue:cryptedkey /unprotect
```

The `cloudapkd` function will give us the clear session key (if not stored in TPM), and a derived key. We will need the clear key for roadtx:

![dumping PRT with mimikatzz](/assets/img/roadtx/mimikatz_dump.png)

To make our life easier, we renew the PRT first, which will save it in `roadtx.prt`:

```
roadtx prt -a renew --prt <PRT From mimikatz> --prt-sessionkey <clear key from mimikatz>
```

Now we can request tokens using the interactive browser with `roadtx browserprtauth`. If we use the `roadtx describe` command, we see the access token includes an MFA claim because the PRT I used in this case also had an MFA claim.

```
roadtx browserprtauth
roadtx describe < .roadtools_auth
```

![MFA claim from the PRT](/assets/img/roadtx/roadtx_describe.png)

Similar to the previous command, we can also use this for interactive browsing in the Selenium window:

<video width="100%" controls>
  <source src="/assets/video/selenium_prtauth.mp4" type="video/mp4">
  <source src="/assets/video/selenium_prtauth.webm" type="video/webm">
</video> 

## Primary Refresh Token usage with other accounts
An interesting use case for stolen Primary Refresh Tokens is that you can also use them for other accounts to add device claims to the authentication. For example, if there is a conditional access policy that requires a compliant or hybrid joined corporate device to access specific resources, the device claim originates from the primary refresh token used during authentication. This claim can also be used for other users. So if I have a stolen PRT from a compliant device for user `tpmtest@iminyour.cloud`, I can use this PRT with the credentials of `newlowpriv@iminyour.cloud` to sign in and pass the compliancy test.

In this example we still have the stolen PRT from `tpmtest@iminyour.cloud` used in the example above saved as `roadtx.prt`. I can use this PRT together with the credentials of `newlowpriv` that are stored in my KeePass file to sign in to Microsoft Teams and access data there with the `roadtx browserprtinject` command.

```
roadtx browserprtinject -u newlowpriv@iminyour.cloud -r msgraph -c msteams
```

The issued access token will contain the `deviceid` claim, which is the device from which we stole the PRT. Since this device is Intune managed and compliant, it passes the compliancy requirement:

![MFA claim from the PRT](/assets/img/roadtx/logs_compliant.png)


## Adding MFA claims to an existing PRT
Moving back from the PRTs that we stole and back to the PRT we registered earlier using a username + password combination. If we want to have a PRT with MFA claim, we have to use an interactive session that will request a special refresh token from Azure AD for "enriching" our PRT. The command for this is `roadtx prtenrich`, which like the previous commands accepts an identity in a KeePass file to autofill the MFA information, or you can do this by hand.

```
roadtx prtenrich -u newlowpriv@iminyour.cloud
Got refresh token. Can be used to request prt with roadtx prt -r <refreshtoken>
```

The result is a special refresh token that we can use to request a new PRT. For this we go back to the `roadtx prt` module:

```
roadtx prt -r <refreshtoken> -c blogdevice.pem -k blogdevice.key
```

The new PRT is written to disk and when we use it to request tokens we see the MFA claim:

![New PRT with MFA capabilities](/assets/img/roadtx/roadtx_prtmfa.png)

We can use this PRT to obtain tokens for resources that require MFA using any of the above methods.

# Single sign on in Windows using Chrome and a custom browsercore
In my [first blog on PRTs](https://dirkjanm.io/abusing-azure-ad-sso-with-the-primary-refresh-token/) I described the process that Chrome uses to do Single Sign On in Windows. It uses the `browsercore.exe` helper program to request PRT cookies to sign in automatically. For roadtx I wrote a small utility called `browsercore.py`, which can be used as a replacement for `browsercore.exe`. By doing so, you can use a Primary Refresh Token from roadtx (or one that you stole elsewhere) to automatically authenticate in your Chrome browser on your attacker controlled host. You don't need to have a Selenium window, but can use the PRT directly just as if you were on the victims machine in a legitimate browser.

The custom SSO requires a few steps to set up:

* You should put the `browsercore.py` and `manifest.json` [files](https://github.com/dirkjanm/ROADtools/tree/master/browsercore) in some location on disk, for example in `C:\browsercore\`.
* Install roadtx and place a `roadtx.prt` file in the same directory.
* Modify `HKEY_CURRENT_USER\Software\Google\Chrome\NativeMessagingHosts\com.microsoft.browsercore` to point to `C:\browsercore\manifest.json`.
* Test whether everything works using `bctest.py`
* Clear any existing cookies in Chrome for `login.microsoftonline.com`

Full install instructions are on the [ROADtools wiki](https://github.com/dirkjanm/ROADtools/wiki/Setting-up-BrowserCore.py). After setup, Chrome should use the PRT automatically during sign in. The first time it may need a hint for the username to work properly.

With this setup you can browse any Azure AD connected resource with SSO and the claims from the PRT, including device status and cached MFA information. 

# Other utilities
There are a few other utilities in roadtx, mostly to make my own research easier:

* `roadtx decrypt` can decrypt encrypted responses given a PRT session key or a device transport key
* `roadtx getotp` can calculate an OTP code from a seed or from the otp property stored in a KeePass file (if you need to do MFA for that user)
* `roadtx codeauth` can perform the OAuth2 code redemption flow for public and confidential clients.
* `roadtx listaliases` lists all the aliases that are supported for resources and clients. If you need any other aliases that you use frequently feel free to open an issue or send me a message.

# Tool download, future work and credits
As always the tools are available and open source on [GitHub](https://github.com/dirkjanm/ROADtools) and on pypi with `pip install roadtx`. This toolkit was developed during my research of the past years and I will keep adding new stuff to it as that research progresses. Many of the commands currently only work in managed environments (so not in federated), simply because I have not had the time yet to set up a lab with federation.

Thanks to [DrAzureAD](https://twitter.com/DrAzureAD) for developing [AADInternals](https://aadinternals.com/aadinternals/), which inspired the initial device registration development and was a helpful resource on several implementation details. Also a shoutout to [TokenTactics](https://github.com/rvrsh3ll/TokenTactics) which implements many token request/refresh related flows in Powershell.