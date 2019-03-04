---
layout: single
classes: wide
title:  "The worst of both worlds: Combining NTLM Relaying and Kerberos delegation"
date:   2019-03-04 19:08:57 +0100
---
After my in-depth post last month about [unconstrained delegation](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/), this post will discuss a different type of Kerberos delegation: resource-based constrained delegation. The content in this post is based on [Elad Shamir's Kerberos research](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) and combined with my own NTLM research to present an attack that can get **code execution as SYSTEM** on any Windows computer in Active Directory **without any credentials**, if you are in the same network segment. This is another example of insecure Active Directory default abuse, and not any kind of new exploit.

# Attack TL;DR
If an attacker is on the local network, either physically (via a drop device) or via an infected workstation, it is possible to perform a DNS takeover using [mitm6](https://github.com/fox-it/mitm6), provided IPv6 is not already in use in the network. When this attack is performed, it is also possible to make computer accounts and users authenticate to us over HTTP by spoofing the `WPAD` location and requesting authentication to use our rogue proxy. This attack is described in detail in [my blog post on this subject](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/) from last year.

We can relay this NTLM authentication to LDAP (unless mitigations are applied) with ntlmrelayx and authenticate as the victim computer account. Computer accounts can modify some of their own properties via LDAP, which includes the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. This attribute controls which users can authenticate to the computer **as almost any account in AD** via impersonation using Kerberos. This concept is called Resource-Based constrained delegation, and is described in detail by [Elad Shamir](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) and [harmj0y](https://posts.specterops.io/another-word-on-delegation-10bdbe3cd94a). Because of this, when we relay the computer account, we can modify the account in Active Directory and give ourselves permission to impersonate users on that computer. We can then connect to the computer with a high-privilege user and execute code, dump hashes, etc.
The beauty of this attack is that it works by default and does not require any AD credentials to perform.

# No credentials, no problem
If you've already read the blog of Elad, you may have noticed that control over a computer account (or any other account with a Service Principal Name) is required to perform the S4U2Proxy attack. By default, any user in Active Directory can create up to 10 computer accounts. Interesting enough, this is not limited to user accounts, but can be done by existing computer accounts as well! If we can get any user or computer to connect to our NTLM relay, we can create a computer account with ntlmrelayx:

![create computer account](/assets/img/kerberos/computer-create.png){: .align-center}

It is required here to relay to LDAP over TLS because creating accounts is not allowed over an unencrypted connection.
These computer account credentials can be used for all kinds of things in AD, such as querying domain information or even running BloodHound:

![running bloodhound](/assets/img/kerberos/computer-bloodhound.png){: .align-center}

# Relaying and configuring delegation
Let's run the full attack. First we start `mitm6` to take over the DNS on our target, in this case `ICORP-W10` (a fully patched default Windows 10 installation), I'm limiting the attack to just this host here:
```
sudo mitm6 -hw icorp-w10 -d internal.corp --ignore-nofqnd
```
Now it might take a while before the host requests an IPv6 address via DHCPv6, or starts requesting a `WPAD` configuration. Your best chances are when the victim reboots or re-plugs their network cable, so if you're on a long term assignment, early mornings are probably the best time to perform this attack. In either case you'll have to be patient (or just attack more hosts, but that's also less quiet). 
In the meantime, we also start ntlmrelayx using the `--delegate-access` argument to enable the delegation attack and with the `-wh attacker-wpad` argument to enable `WPAD` spoofing and authentication requests:
```
ntlmrelayx.py -t ldaps://icorp-dc.internal.corp -wh attacker-wpad --delegate-access
```
After a while `mitm6` should show our victim connecting to us as DNS server for the WPAD host we set:

![wpad and mitm6](/assets/img/kerberos/mitm6-wpad.png){: .align-center}

And we see ntlmrelayx receiving the connection, creating a new computer account and granting it delegation rights to the victim computer:

![ntlmrelayx adding delegation](/assets/img/kerberos/ntlmrelayx-delegation.png){: .align-center}

Next we can use `getST.py` from [impacket](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getST.py), which will do all the S4U2Self an S4U2Proxy magic for us. You will need the latest version of [impacket from git](https://github.com/SecureAuthCorp/impacket) to include resource based delegation support. In this example we will be impersonating the user `admin`, which is a member of the `Domain Admins` group and thus has administrative access on `ICORP-W10`:

![getting a service ticket for the admin user](/assets/img/kerberos/admin-st.png){: .align-center}

We obtained a Kerberos Service Ticket now for the user `admin`, which is valid for `cifs/icorp-w10.internal.corp`. This only lets us impersonate this user to this specific host, not to other hosts in the network. With this ticket we can do whatever we want on the target host, for example dumping hashes with secretsdump:

![dumping hashes with secretsdump](/assets/img/kerberos/secretsdump-kerberos.png){: .align-center}

The attacker now has full control over the victim workstation.

# Other abuse avenues
This blog highlights the use of mitm6 and WPAD to perform the relay attack entirely without credentials. Any connection over HTTP to a host that is considered part of the `Intranet Zone` by Windows can be used in an identical matter (provided automatic intranet detection is enabled). Elad's original blog described using WebDAV to exploit this on hosts. Another attack avenue is (again) [PrivExchange](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/), which makes Exchange authenticate as SYSTEM unless the latest patches are installed.

# Tools
The updated version of ntlmrelayx is available in a branch on [my fork of impacket](https://github.com/dirkjanm/impacket/tree/rbdelrelay). I'll update the post once this branch gets merged into the main repository.

# Mitigations
As this attack consists of several components, there are several mitigations that apply to it.
### Mitigating mitm6
mitm6 abuses the fact that Windows queries for an IPv6 address even in IPv4-only environments. If you don't use IPv6 internally, the safest way to prevent mitm6 is to block DHCPv6 traffic and incoming router advertisements in Windows Firewall via Group Policy. Disabling IPv6 entirely may have unwanted side effects. Setting the following predefined rules to Block instead of Allow prevents the attack from working:
- *(Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)*
- *(Inbound) Core Networking - Router Advertisement (ICMPv6-In)*
- *(Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)*

### Mitigating WPAD abuse
If WPAD is not in use internally, disable it via Group Policy and by disabling the `WinHttpAutoProxySvc` service. Further mitigation and detection measures are discussed [in the original mitm6 blog](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/).

### Mitigating relaying to LDAP
Relaying to LDAP and LDAPS can only be mitigated by enabling both LDAP signing and [LDAP channel binding](https://support.microsoft.com/en-us/help/4034879/how-to-add-the-ldapenforcechannelbinding-registry-entry).

### Mitigating resource based delegation abuse
This is hard to mitigate as it is a legitimate Kerberos concept. The attack surface can be reduced by adding Administrative users to the `Protected Users` group or marking them as `Account is sensitive and cannot be delegated`, which will prevent any impersonation of that user via delegation. Further mitigations and detection methods are [available here](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html).

## Credits
- [@Elad_Shamir](https://twitter.com/elad_shamir) and [@3xocyte](https://twitter.com/3xocyte) for the original research and relay POC
- [@agsolino](https://twitter.com/agsolino/) for building and maintaining impacket and implementing all the cool Kerberos stuff
- [@gentilkiwi](https://twitter.com/gentilkiwi) for Kekeo and [@harmj0y](https://twitter.com/harmj0y) for Rubeus and their Kerberos research