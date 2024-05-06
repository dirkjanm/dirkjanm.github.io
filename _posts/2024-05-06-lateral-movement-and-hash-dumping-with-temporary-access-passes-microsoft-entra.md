---
layout: single
classes: wide
title:  "Lateral movement and on-prem NT hash dumping with Microsoft Entra Temporary Access Passes"
date:   2024-05-06 15:00:57 +0200
---

Temporary Access Passes are a method for Microsoft Entra ID (formerly Azure AD) administrators to configure a temporary password for user accounts, which will also satisfy Multi Factor Authentication controls. They can be a useful tool in setting up passwordless authentication methods such as FIDO keys and Windows Hello. In this blog, we take a closer look at the options attackers have to abuse Temporary Access Passes for lateral movement, showing how they can be used for passwordless persistence and even to recover on-premises Active Directory passwords in certain hybrid configurations.

Temporary access passes are not enabled by default. However, many tenants that primarily use passwordless forms of authentication have them enabled to allow users to configure passwordless authentication methods for the first time, or for account recovery in the case these users need to reset their authentication methods. For attackers, Temporary Access Passes (TAPs) also provide interesting options, since these temporary passwords exist next to the users regular password, which means configuring a TAP on an account is not a destructive action like resetting the account password. The abuse of TAPs by itself is not new, there are already some great blogs that explore this concept, such as [this blog](https://posts.specterops.io/id-tap-that-pass-8f79fff839ac) by [Daniel Heinsen from SpecterOps](https://twitter.com/hotnops).

After I read Daniel's blog a while ago, I started playing with these TAPs to see if I could also utilize them with ROADtools to request tokens and what the limitations on those tokens would be. Since TAPs can be used to configure passwordless authentication methods, it shouldn't be a surprise that we can also use them to configure Windows Hello for Business keys on accounts, which was added to ROADtools after my Windows Hello talks [last year](/talks/). I'll describe the steps for this below. What I found more interesting during my research, is that TAPs can be used for lateral movement in hybrid environments as well, where the use of a TAP in Entra would allow the attacker to authenticate in the on-premises Active Directory. It would even allow the attacker to recover the NT hash of the victim account, which might be used to recover the plain text password of the victim account. The hybrid lateral movement part is only applicable if Cloud Kerberos Trust is used, which gives Entra ID the ability to issue Kerberos tickets for on-prem identities.

## Configuring TAPs
Temporary Access Passes can be configured by admins, provided that the feature is enabled and the admin has sufficient rights to do so. The requirements and methods are quite clearly laid out in the [TAP documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass#create-a-temporary-access-pass) from Microsoft. We can also do it over the Microsoft Graph Rest API, however that would require that we have a token with the `UserAuthenticationMethod.ReadWrite.All` delegated permissions. Unfortunately for us, there aren't any built-in Microsoft apps that I'm aware of that have this kind of access, so our best bet is to use the Azure/Entra portal or to borrow a token from that portal and use that with PowerShell or the [REST API](https://learn.microsoft.com/en-us/graph/api/authentication-post-temporaryaccesspassmethods?view=graph-rest-1.0&tabs=http#request). In this case we'll stick to the Azure Portal to configure the temporary access pass.

![Configuring a TAP](/assets/img/tap/tap_configure.png)

Temporary Access Passes act as alternative credentials for the user, which means that we can use them while the legitimate user is not interrupted, which is a big advantage over destructive actions like password resets, which will invalidate the users current sessions and likely cause some complaints. Since the TAP also counts as MFA, we don't need to worry about them receiving notifications or text messages from MFA prompts either. Now that we have a TAP, lets see what we can do to convert this into persistent access.

## Abusing the TAP for lateral movement
The TAP itself is only valid during the configured lifetime. While we can influence this when creating the TAP, a longer validity might also be suspicious, because the TAP automatically becomes the preferred authentication method during its lifetime. To minimize the chance of the legitimate user being prompted for the TAP, we can make its lifetime as short as possible, or allow it to only be used once. 

### Configuring Windows Hello for Business keys with a TAP
To configure Windows Hello for Business, we need to have some special tokens. This process is very similar to the flow from [my last blog](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/) where we used the special permissions of the Microsoft Authentication Broker to request a token that we can upgrade to a PRT. This flow is also similar to how Windows upgrades Primary Refresh Tokens to include an MFA claim after obtaining them with only a password. In this flow we don't use the authentication method directly in the PRT request, but we use a special refresh token that acts as an intermediary.

Windows Hello provisioning also requires us to have a device in the tenant. Lucky for us, registering or joining devices is enables in almost all tenants, so if we do not have access to an existing device we can register or join one as part of the flow. We could technically abuse an existing device here, but that would complicate the process, especially if there is a TPM involved.

The first step is to authenticate using the TAP, using the `prtenrich` command from [roadtx](https://github.com/dirkjanm/ROADtools). This command also works without an existing PRT if we use the `--no-prt` flag, which allows us to use a TAP for authentication.

```
roadtx prtenrich -u hybrid@hybrid.iminyour.cloud --no-prt
```

This will prompt us for the TAP (which is now the preferred authentication method), and give us a refresh token. If we do not yet have a device certificate/key, we can also use this refresh token to register a device.

```
roadtx gettokens --refresh-token <token> -c broker -r drs
```

We can join or register a device with the `device` module:

```
roadtx device -n blogtest2 -a register
```

And with our newly registered device we can get a PRT:

```
roadtx prt -r <refreshtoken> -c blogtest2.pem -k blogtest2.key
```

The output of these commands should look somehwat like this:

![Request a PRT](/assets/img/tap/get_device_prt.png){: .align-center}

Unfortunately for us, this PRT is only going to be valid for as long as the TAP itself. It does not say so in the expiry time, but it will get refused after the TAP expiry:

![PRT expires with the TAP](/assets/img/tap/tap_expired_prt.png){: .align-center}

If we want to have actual persistence, we need to provision some additional credentials on the account. In this case, we could set up a Windows Hello key for the account, which we can then use after the TAP expires. The process to do this is very similar as in my [last blog](https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/). We use the `prtenrich` command again to get an access token for Windows Hello provisioning, then we register the actual hello key.

```
roadtx prtenrich --ngcmfa-drs-auth
roadtx winhello -k hybriduser.key
```

The `prtenrich` command should automatically proceed if we did the TAP authentication within the last 10 minutes. If not, we can just use the TAP again to comply with MFA requirements (provided the TAP was valid for multiple uses). The `winhello` command provisions the key for our user. If we want, we can use it to get a new PRT, that is valid for longer and also counts as MFA:

```
roadtx prt -hk hybriduser.key -c blogtest2.pem -k blogtest2.key -u hybrid@hybrid.iminyour.cloud
```

We can use this PRT with the usual `prtauth` and `browserprtauth` to either get tokens or to browse the web as our victim.

### Obtaining NT hashes of the victim via a TAP
So far, we didn't see anything unexpected. After all, a TAP is a legitimate way to configure passwordless credentials, such as Windows Hello keys or FIDO keys (we wouldn't even need to use custom tools to register a FIDO key, a browser would be sufficient). But if we take a step back and look at the PRT that we received after using the TAP, we see something unexpected:

![PRT with TGT](/assets/img/tap/prt_tgt.png){: .align-center}

Our PRT came with a Kerberos TGT for the on-premises Active Directory that our victim is part of. This is made possible by the Cloud Kerberos Trust feature, so it only works if that has been configured in the Entra tenant and the on-prem AD. However, it is meant to make on-premises authentication possible with Windows Hello for business keys and FIDO keys, not necessarily with TAPs. The issue here is that while a TAP is by definition temporary, the TGT that we receive here is valid for 10 hours, which most likely exceeds the validity of the TAP itself. Further more, since Cloud Kerberos trust enables recovering legacy credentials (meaning NT hashes), we can obtain the NT hash of our victim, provided that we have line-of-sight to an on-premises AD Domain Controller. The NT hash can be used to request TGTs even after the TAP expired or our access in the cloud was revoked. If the original password of the user is relatively weak, we might also be able to recover the plain text password by brute forcing the NT hash with tools such as hashcat.

So to recap, provided we have the following:

* TAPs enabled in the tenant
* Sufficient access to provision TAPs on our victims
* Cloud Kerberos trust enabled
* Line of sight to the on-premises AD

We could obtain the NT hash for anyone we can provision a TAP for, without requiring to configure persistence on their account, and all with a single device identity to leave as few traces as possible. While this list of requirements is quite long, if you do meet all of them it could be used as a somewhat noisy hash dump method, entirely controlled from Entra. There are limits on which accounts we can target with this, so users like Domain Admins (which shouldn't be synced to Entra in the first place) are not affected. The restrictions and details of how exactly this works are covered in my [blog on Cloud Kerberos Trust](https://dirkjanm.io/obtaining-domain-admin-from-azure-ad-via-cloud-kerberos-trust/).

Let's perform the last step of our attack. We re-use the PRT we got at the first step, so the one requested using the TAP, before we enrolled a Windows Hello key. This PRT contains a partial TGT, which we can exchange for a full TGT using [ROADtools hybrid](https://github.com/dirkjanm/ROADtools_hybrid)'s `partialtofulltgt.py` script.

```
python partialtofulltgt.py -f roadtx.prt hybrid.iminyour.cloud/hybrid
```

![From TAP to NT hash](/assets/img/tap/tap_to_nt_hash.png){: .align-center}

If we want to do this for more users, we simply provision a TAP for them too, request a TGT with the TAP and then recover the NT hash. You could write a script that loops through this and recovers as many hashes as possible, without making permanent changes to the accounts or causing impact on the real user of the account.

# Disclosure, prevention and detection
While many parts of this are following the design principles, the ability to obtain a long-term key (NT hash) with a Temporary Access Pass seemed like a vulnerable feature of the protocol to me. Microsoft did consider it a valid finding when I reported it to MSRC, but not one of immediate concern because of the high privilege requirements, and the fact that an admin in that position would also be able to compromise an on-premises account through something like password write-back if that is enabled in the tenant. 

I agree with them that the privileged required are high, it is not a default configuration, and there are other options to abuse the privileges these roles have. However, I still think that temporary passwords should not immediately give access to long term keys. From a pentester point of view, I also find it an interesting attack since it is non-disruptive to the actual user, which during a red team or pentest engagement is a big advantage. Since this feature will not be addressed in the immediate future, it is something that could be abused by attackers in the lateral movement / post exploitation stage of their attacks.

My recommendations if you have a setup where these features are present would be as follows:

* Avoid syncing accounts that have privileged rights in Active Directory to Entra ID.
* Make sure to scope the Temporary Access Pass authentication method only to regular users, and not to admin accounts that may be synced from on-premises (even though I just told you not to do that).
* Monitor for assignments of Temporary Access Passes on sensitive accounts, especially in high volume.
* Monitor for large numbers of users signing in "from" the same device, which is the event that is generated when a PRT is issued.
* Require compliant or hybrid joined devices for sign-in to prevent fake devices that are registered by attackers from being used to access applications.

As usual, ROADtools is available via [GitHub](https://github.com/dirkjanm/ROADtools) or via PyPI via `pip install roadtx`. [ROADtools hybrid](https://github.com/dirkjanm/ROADtools_hybrid) is available as a collection of standalone scripts on GitHub.