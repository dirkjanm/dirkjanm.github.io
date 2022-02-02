---
layout: single
classes: wide
title:  "NTLM relaying to AD CS - On certificates, printers and a little hippo"
date:   2021-07-28 19:08:57 +0200
---
I did not expect NTLM relaying to be a big topic again in the summer of 2021, but among printing nightmares and bad ACLs on registry hives, there has been quite some discussion around this topic. Since there seems to be some confusion out there on the how and the why, and new attack vectors coming up fast now, I figured I'd write a short post with some more details and background. Hardly anything here is my own research, so I don't take credit for any of this, but since these issues are "by design" and will likely not see a patch or significant change soon, they are quite relevant. That's why I decided to write some Python tools around it and explain the process in this post. The tools are available on my [GitHub](https://github.com/dirkjanm/PKINITtools).

## Background - the state of NTLM relaying
I've written quite some times about NTLM relaying ever since I started contributing to ntlmrelayx in 2017. Despite NTLM relaying mitigations that were introduced ever since the first NTLM relay attacks that were introduced around 2001, the past few years have seen many exploits, but hardly any new mitigations to make this horrible protocol more secure. Even the scheduled change to [enforce LDAP signing and channel binding](https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a) by default, which was supposed to be deployed in 2020, ultimately did not ship, likely due to many third-party products not being compatible with this. This meant that in the default state with fully up-to-date systems, it was possible to:

* Relay NTLM authentication occurring over HTTP to LDAP, resulting in [computer account takeover](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
* Relay authentication over SMB to HTTP endpoints, but not to LDAP because of a signing requirements [mismatch](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/). Since no research was published on high-value default HTTP endpoints, this prevented exploitation of ways to get authenticated SMB connections via the infamous [Printer Bug](https://github.com/leechristensen/SpoolSample/).

This all changed when [Lee Christensen](https://twitter.com/tifkin_) and [Will Schroeder](https://twitter.com/harmj0y) published their whitepaper on [abusing Active Directory Certificate Services](https://posts.specterops.io/certified-pre-owned-d95910965cd2). In this whitepaper they describe an attack called ESC8, which involves NTLM relaying to the HTTP interface part of the certificate service, which issues certificates. Because this interface accepts NTLM authentication without support for signing, it is possible to:

1. Request an authenticated back-connect with the Printer Bug over MS-RPRN, as long as the spool service is running on the victim system.
2. Receive this authentication and relay this to the certificate services web interface.
3. Request a certificate on behalf of the victim system.
4. Use the issued certificate to impersonate the victim system.
5. Either use the privileges of the victim system directly (for example in the case of a Domain Controller), or use Kerberos features to request a service ticket with administrative access to the host itself or request the NT hash for the system account which allows you to create a silver ticket.

The printer bug has already been known for quite a while and has been a component in many attacks. Disabling the printer spooler service has been a common recommendation ever since, and has recently been brought to light again with the PrintNightmare exploit, which also relied on the spooler service being active. It was kind of a given that other methods must exist for coercing authentication via RPC methods, and I expect some are also keeping these methods private. Following the AD CS release, [Lionel Gilles](https://twitter.com/topotam77) released a new proof-of-concept way to exploit this last week called [PetitPotam](https://github.com/topotam/PetitPotam). Unlike the printer bug, which uses MS-RPRN and requires authentication, this attack is an alternative method that does not rely on the printer spooler service being active, and does not require authentication when attacking a Domain Controller. This makes it an even more valuable attack alternative, as there is no official way as of now to disable this authenticated callback and there is no indication of a fix in sight.

## Exploring AD CS relaying
After Will and Lee published their whitepaper, I was curious whether I could reproduce their attack on relaying to the certificate services web interface. ntlmrelayx is plugin based and quite modular, so the only thing that would likely be required is changing the [http attack](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/ntlmrelayx/attacks/httpattack.py) method to post the right data. After ensuring the web enrolment service is installed in my lab, I went to have a look at the source code of the service. This source is stored in `C:\Windows\system32\CertSrv\en-US` on the server where the AD CS service is installed (in my case and in many others this will probably be the Domain Controller). I imagine the last folder may be different if you installed your system in a different language. Since the pages are written in classic ASP, it is not that hard to read the source code. The copyright mentions 1998 - 1999, which is always a great sign if you're looking for things with a less than ideal security configuration.

When visiting the AD CS web interface at `http://dc-hostname/certsrv/`, we can authenticate using NTLM and a machine account. An easy way to obtain a machine account is with impacket's `addcomputer.py`, which can be used as any authenticated user to add a new computer account by default (note that we're only doing this to understand the attack in the lab, this is not required for the final attack). We can then use NTLM to authenticate to the AD CS web service (it's easier to do this from a non-domain joined computer or from a browser that doesn't perform Single Sign On). In this case I'm using Chrome, which can perform NTLM auth by using the `computername$@domain.fqdn` syntax in the credential prompt. This lets us authenticate as a computer account to the web service. Upon following the certificate request process, we get the following error message: "No certificate templates could be found. You do not have permission to request a certificate from this CA, or an error occurred while accessing the Active Directory.". At first I thought this indicated a problem with my setup, because computer certificate templates are available by default. After some debugging and reading the source I found the reason in `certsgcl.inc`:

![Machine certificates are not selected by the web UI](/assets/img/adcs/cert_machine.png){: .align-center} 

As we can see in the highlighted section, whenever the "choice" of certificate templates is rendered in the web page, the server does not actually query for machine templates. The reasoning behind this is probably that machines are not quite supposed to use the guided way of requesting certificates, so it doesn't make sense to render them. Does this mean that we can't request machine certificates via this interface? Not quite, as the page where the final request is submitted does not actually perform this check but simply submits the request to the CA, so we could use any certificate template here. I've patched the file and added the constant to also search for machine templates, and the template appears in the UI:

![Patched web UI to show computer template](/assets/img/adcs/patchedreq.png){: .align-center} 

Now we can submit a basic request. The only requirement is that we selected the correct template (Computer) and use the hostname of our newly created computer as Common Name. Note that this must match the `dNSHostname` attribute of the computer object, so make sure you run `addcomputer.py` with the `-method LDAPS` option otherwise this won't be the case for our test account. We can create this with openssl, and then submit the request. We see that is immediately issued to us, because the default Computer template does not require approval.

![Openssl request](/assets/img/adcs/manualcertreq.png){: .align-center} 

![Cert issued](/assets/img/adcs/issued.png){: .align-center} 

Requesting this with the dev tools open will show us the POST request, which goes to `certfnsh.asp`. 

![Cert issued](/assets/img/adcs/certpost.png){: .align-center} 

With this information we can build our custom AD CS relay attack. The template for the [http attack](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/ntlmrelayx/attacks/httpattack.py) in ntlmrelayx begins with an authenticated session. Building on this we can create a private key and certificate on the fly, and submit this request to the CA. After submitting the request, we get the certificate that was issued to us and use it to authenticate.

The template that can be used depends on the account that is relayed. For a member server or workstation, the template would be "Computer". For Domain Controllers this template gives an error because a DC is not a regular server and is not a member of "Domain Computers". So if you're relaying a DC then the template should be "DomainController" to match.

I did not initially want to publish the exploit code because Will and Lee also held off publishing theirs, but of course several people managed to reproduce the same attack pattern as above based on the whitepaper. A [pull request](https://github.com/SecureAuthCorp/impacket/pull/1101) for impacket soon appeared by user ExAndroidDev, which implements more or less the same code. If you're curious about my implementation, I included a proof-of-concept version of the [http attack](https://github.com/dirkjanm/PKINITtools/blob/master/ntlmrelayx/httpattack.py) file in the PKINITtools repository. If you want to play with this template you'll have to change the template and the domain manually before copying it to the correct impacket directory and running ntlmrelayx. Below is an example of the attack running:

![Running petitpotam](/assets/img/adcs/petitpotam.png){: .align-center} 

![Obtaining a certificate](/assets/img/adcs/adcsrelay.png){: .align-center} 

Note that this is **fully unauthenticated** (a feature of PetitPotam when used against DC's) and instantly escalates to Domain Controller privileges.

## Abusing the obtained certificate - diving into PKINIT
To actually use these certificates for Kerberos with PKINIT, we can use either [Rubeus](https://github.com/GhostPack/Rubeus/) or [kekeo](https://github.com/gentilkiwi/kekeo). Both of these tools have the downside that they only work on Windows. Originally I wanted to see if I could also port the PKINIT functionality to impacket, because if I could manage to get a regular TGT from the initial PKINIT operation this would allow us to use it with the other impacket tools such as secretdump and smbclient without any additional changes. I went down the rabbit hole of implementing the PKINIT ASN1 structures in impacket, but soon found out that the PKINIT specification itself uses structures from a multitude of different RFCs for it's cryptographic operations. I did some more searching for projects that already used PKINIT in Python and found that [AzureADJoinedMachinePTC](https://github.com/morRubin/AzureADJoinedMachinePTC) has an impacket based implementation, and that SkelSec's [minikerberos](https://github.com/skelsec/minikerberos) has a custom implementation as well. Both these implementations are written for Azure AD joined devices to use SMB and authenticate with certificates. This differs from our goal because Azure AD uses user-to-user (U2U) Kerberos without a central KDC. The PKINIT process is embedded in NegoEx over SMB. For using certificates in Active Directory, we don't need the U2U implementation or the NegoEx parts. But most of the code for PKINIT was already there so I decided to built forth on that rather than reinvent the wheel. The minikerberos project was the implementation of choice because AzureADJoinedMachinePTC does not actually implement the required signing operations in Python, but uses Windows API's for that, which prevents it on working on other operating systems.

I will save you the rant about ASN1 and about the many hours it took me to figure out that Active Directory for some reason does not consider Diffie-Hellman parameters generated by the `cryptography` library strong enough (without documentation I could find about the requirements or about why this is), so I had to borrow some known-safe primes instead. The end result of this is a simple command line tool that can take a certificate and private key, either in PFX or in PEM format, and request a TGT using PKINIT.

![Request TGT using PKINIT](/assets/img/adcs/gettgtpkinit.png){: .align-center} 

### Obtaining the NT hash of the impersonated computer account
One of the features described in the [whitepaper](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) from Will and Lee is the ability to obtain the original NT hash for an account by using the certificate. This is described as "THEFT5" in the whitepaper. The reason behind this is that when certificate authentication is used and a TGT is obtained, there has to be some way for the account performing the authentication to fall back to NTLM authentication if Kerberos is not supported. For that reason, the KDC will supply the NT hash of the account in the PAC that is added to the TGT (if you're not sure what a PAC is or what is in there, I recommend you read [my blog on forest trusts](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/)).

There is some interesting process involved in this. Whenever PKINIT authentication is used, the KDC adds the NT hash in an encrypted format to the PAC. This is encrypted with the same key as that is negotiated between the KDC and the client for encrypting the session key for the TGT. This key is negotiated with Diffie-Hellman key exchange or is encrypted using the public key of the certificate, depending on the implementation. The result of this is a key called the "AS reply key" in the [documentation in MS-PAC](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/cc919d0c-f2eb-4f21-b487-080c486d85fe). The PAC is contained inside the TGT, which is encrypted with one of the Kerberos keys of the `krbtgt` account. This makes it impossible for our client to actually read the PAC.

The way to read the PAC and to access the NT Hash is done via the Kerberos user to user (U2U) extensions. This extension [introduces](https://datatracker.ietf.org/doc/html/draft-ietf-cat-user2user-02) an option called `ENC-TKT-IN-SKEY`, which encrypts the resulting service ticket using the session key from a supplied TGT rather than with the key of the target service/user. This session key is in our possession (we need it to use our TGT), so we can use this to decrypt the service ticket, containing the PAC. The whole process is as follows:

1. Request a TGT using PKINIT and note down the AS reply key (the `gettgtpkinit.py` tool prints the key for you as you can see in the screenshot above).
2. Request a service ticket to ourself, while supplying the `ENC-TKT-IN-SKEY` option and adding the TGT that was issued to us to the "additional tickets" section of the `TGS-REQ`
3. The KDC will copy over the PAC, with the encrypted NT hash, to the ticket that is issued, and will encrypt this ticket with the session key of our TGT (which is known to us)
4. Using the session key we can decrypt the ticket, extract the PAC, and parse + decrypt the NT hash using the AS reply key

The proof-of-concept for this, which is mostly based on `getPac.py` from impacket and on reading the kekeo source code is called `getnthash.py`. Here's a demo:

![Obtaining the NT hash for the computer account](/assets/img/adcs/getnthash.png){: .align-center} 

#### Abuse
With the NT hash in our possession (which is the NT hash of the computer account that we originally relayed), we can perform attacks as that account using any tool that supports hashes for machine authentication. Alternatively, to get access to the original host we could use the hash as RC4 Kerberos key to create a silver ticket, which can contain any user claim and will be accepted by the host. 

### Using S4U2Self to obtain access to the relayed machine
There is another approach to obtain access to the machine we originally relayed. Aside from using the NT hash for a silver ticket, we can also use the TGT from earlier directly. This can be done via S4U2Self. If you're not familiar with this, the S4U2Self extension makes it possible for a Kerberos service to request a ticket on behalf of anyone towards itself, as long as the service has an SPN registered. This is also (ab)used in many delegation scenario's, and was documented as attack by [Elad Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html#solving-a-sensitive-problem). The relevant bit is that because we have a TGT for the system we want to attack, we can request a legitimate service ticket for any user that is accepted by the original system (since it's encrypted with it's own service key). I once again wrote a small command line tool for this based on some minikerberos example, which is called `gets4uticket.py`. You should supply the ccache containing the TGT and an SPN that belongs to the system for which the TGT was issued. Then we can ask for a ticket for any user, in this case the "Administrator" user. 

![Obtaining a ticket via S4U2self](/assets/img/adcs/gets4uticket.png){: .align-center} 

This ticket does indeed have Administrative access on my domain controller, as demonstrated by the ability to list the contents of the `c$` drive:

![Administrative rights](/assets/img/adcs/smbclient_admin.png){: .align-center} 

## Other abuse avenues of PetitPotam
PetitPotam also makes it possible to cause a backconnect over WebDAV, provided the webdav service is running. The advantage of WebDAV is that authentication happens over HTTP, which can be relayed to LDAP in the default configuration. This makes it possible to perform attacks based on Resource Based Constrained Delegation, similar to previous [blogs](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/) on [this](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) [topic](https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a). [Maximus](https://twitter.com/gladiatx0r/) recently wrote a nicely summarized [Gist](https://gist.github.com/gladiatx0r/1ffe59031d42c08603a3bde0ff678feb) on this which contains the required steps and ways to get the WebDAV service running.

# Defenses
There has already been written a lot about defenses on this topic, and there are extensive guidelines on mitigating relaying to AD CS in Lee and Will's [whitepaper](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf). There is also the [official Microsoft recommendation](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429). Personally I'd like to summarize the possible defenses as follows:

* Mitigate NTLM relaying attacks as much as possible by enforcing security features on sensitive services, such as LDAP signing + channel binding on the DCs and HTTPS + enhanced protection on IIS based services.
* Prevent services from authenticating to arbitrary workstations by disallowing traffic initiated from servers to workstations. An allowlist of required connections could be used if server to workstation traffic is required for some services.
* Disable known vulnerable services as much as possible (Spooler Service).
* Work on phasing out NTLM entirely.

# Credits / Thanks / Tools
As stated before, not much of this is my original work, and all credits go to the people referenced already in this post. The tools/adaptions shown in this blog are available on my GitHub under [PKINITtools](https://github.com/dirkjanm/PKINITtools).
