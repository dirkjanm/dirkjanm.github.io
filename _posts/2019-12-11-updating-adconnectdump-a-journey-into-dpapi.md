---
layout: single
classes: wide
title:  "Updating adconnectdump - a journey into DPAPI"
date:   2019-12-11 19:08:57 +0200
---
Last year when I started playing with Azure I looked into Azure AD connect and how it stores its high privilege credentials. When I was revisiting this topic a few weeks ago, it turned out that some things had changed and my previous method of dumping credentials did not work anymore. Because it took me quite some time to figure out what exactly changed, and some help from @gentilkiwi to figure out the DPAPI process, I thought I'd document both the process and the results in the hope it will be useful for others.

# Why attack Azure AD connect
As more and more things are moved to the cloud, the connection between traditional on-prem resources and cloud becomes an interesting target. I've [talked multiple times](/talks/) about the privileges of Azure AD connect in both the cloud and on-prem. As a reminder: if an organization uses Password Hash Synchronization, Azure AD connect has the privileges to perform a DCSync, which allows it to sync all attributes (including password hashes) from domain controllers. This means that the account that Azure AD uses in the on-prem AD is Domain Admin equivalent (which is why the system AD Connect is installed on should be treated as Tier 0). The account used by Azure AD Connect in Azure AD is a member of the "Directory Synchronization Accounts" role. This role also has high privileges, allowing it to manage all service principals, conditional access policies and of course overwrite user passwords. All of this makes it quite interesting to look at how one can obtain those high-privilege credentials once administrative access is achieved on the host where Azure AD connect is installed.

# The previous credential storage mechanism
For my [TROOPERS talk](/assets/raw/TR19-Im%20in%20your%20cloud.pdf) I spent some time figuring out how Azure AD connect stores its data. I won't describe the research approach for this here, but it is described in my slides starting around page 17. There were basically two places where Azure AD connect stored its data:

- A database (MDB) stored in `C:\Program Files\Microsoft Azure AD Sync\Data`.
- The registry.

In the database AAD connect stores the configuration including the accounts that have privileges in Azure and in the on-prem AD. The sensitive properties of these accounts (including the passwords) are stored as encrypted data. To decrypt the data, AAD connect uses a keyset that is stored encrypted in the registry. The keyset ID is stored in the database and this keyset is stored in the registry in `HKLM\Software\Microsoft\Ad Sync\Shared\[keysetid]`. The keyset can be decrypted using DPAPI and some additional entropy that is also stored in the database, using a DPAPI masterkey which in turn can be decrypted with the SYSTEM DPAPI key. Once the keyset is decrypted, the keys it contains can be used to decrypt the encrypted properties from the database. This whole process is quite abstract so here's a diagram showing the whole flow:

![AD Sync decrypt flow](/assets/img/dpapi/dpapiflow.svg){: .align-center}

You can make the decryption process as hard or as easy as you want. The easiest method is using the `mcrypt.dll` methods that load the keyset for you and use that to decrypt the data from the database, ignoring the whole process that happens under water. This does require you to use the DLLs from Azure AD Connect and to have them in your path to execute the tool. An alternative method is to query the required data from the database, the keyset from the registry, decrypt it with DPAPI, dump those on the target and then perform the decryption yourself locally. This doesn't require you to have the DLLs in your path, but since I am not a C# person I did write the part about decrypting the actual data with AES in Python. In the end this resulted in 3 methods of dumping credentials which I bundled in the [adconnectdump repository](https://github.com/fox-it/adconnectdump) on GitHub, with the main differences shown in the table here:

Tool | Requires code execution on target | DLL dependencies | Requires MSSQL locally | Requires python locally
--- | --- | --- | --- | ---
ADSyncDecrypt | Yes | Yes | No | No
ADSyncGather | Yes | No | No | Yes
ADSyncQuery | No (network RPC calls only) | No | Yes | Yes

The third method (for which the ADSyncQuery tool was written) was more of a personal challenge to learn more about DPAPI. This method avoids running binaries or having to upload files to the target host, but instead performs all the steps required via RPC calls over SMB. This is done using a heavily adapted version of secretsdump.py (written by @agsolino and part of [impacket](https://github.com/SecureAuthCorp/impacket)). The steps it performs are as follows:

- Stop the ADSync service in order to release the lock on the MDF/LDF database file
- Download the MDF/LDF files
- Restart the service
- Read the data from the downloaded database files
- Extract the DPAPI system encryption keys from the registry
- Read the encrypted keyset remotely from the registry
- Find the DPAPI masterkey file on the filesystem
- Decrypt the DPAPI masterkey using the system key
- Decrypt the keyset
- Decrypt the credential data stored in the database
- Profit!

This whole chain looks like this when executed:

![adconnectdump in action](/assets/img/dpapi/adconnectdump_old.png){: .align-center}

# The new method
When I tried this method again a few weeks back I got several errors thrown by the script. A quick investigation showed me that the step where it failed was the registry. The registry key that previously held the keyset simply didn't exist anymore. I couldn't find the key on other places in the registry either.

Whereas previously I was able to use the key export utility included in AD Connect and watch the API calls it made using API Monitor, this time this utility (as well as the ADSyncDecrypt tool) reported the same error and thus didn't get me anywhere. The quickest way for me to debug this was to attach API Monitor to the service and see which API calls the service made in order to find the keyset. Since API Monitor doesn't support attaching to a service start out of the box (if it does I'd love to hear how), I had to attach to the running process as fast as possible after the service started. After a few tries I was pretty sure I was attached early enough to watch the keyset being decrypted using DPAPI:

![keyset dpapi data in api monitor](/assets/img/dpapi/keysetdpapi.png){: .align-center}

The keyset still looked pretty similar to how it did before and the encrypted DPAPI data did include the "MMS_ENCRYPTION_KEYSET" string in UTF-16 in the description. While this all was running I used procmon to capture events, but did not find any events that indicated the keyset being read from the registry or from disk. Neither did running procmon on the non-working extraction tools yield useful information about where it was looking, apart from that it tried to query the same registry key as I was, which did not exist.

To make sure the encrypted keyset was not stored anywhere on disk, I even wrote a simple YARA rule that would find the bytes with the description in the unencrypted part of the keyset data. I ran this recursively on all files on disk without getting any useful results, which made me pretty certain the encrypted keyset was not anywhere on disk in unencrypted (or uncompressed, though that seemed illogical) form.

At this point I went back to the figurative drawing board and had another look at the API calls made by the AD Connect server. I loaded `mcrypt.dll` into API Monitor and confirmed that AD Connect still used the same functions to load the keyset. The only remaining difference was that the actual AD Connect service was running under the `NT SERVICE\ADSync` user, whereas my tool was running as a domain user with local administrator privileges. So which storage mechanism outside the registry would store data that is only accessible to the user who put it there? How about the Windows Credential Manager (or Credential Vault)? This is a per-user vault which uses DPAPI to encrypted the secrets stored in it. A quick way to verify this theory was to simply dump the credentials in the vault. There are multiple tools for this but since I needed to do this from the context of the `NT SERVICE\ADSync` user I opted for Mimikatz, that can impersonate the user by stealing a token from the running service and then access the vault:

![Mimikatz vault dump](/assets/img/dpapi/mimikatz_vault.png){: .align-center}

This leads us to the conclusion that instead of storing the keyset in the registry, it is now stored in the credential vault of the `NT SERVICE\ADSync` user. So running the gathering scripts as the `NT SERVICE\ADSync` user should make sure the dumping of credentials works again. But this only solved it for the method which executes binaries on the host, and not for the network-only approach, for which I had to dig a bit deeper.

## DPAPI and Virtual Accounts
The `NT SERVICE\ADSync` is a virtual account. According to the Microsoft [documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts#bkmk-virtualserviceaccounts) these accounts were introduced in Server 2008 and don't require any password management. Nevertheless, the do apparently have unique DPAPI keys that allow them to use the Credential Manager. Since I didn't have any idea of how the Credential Manager stored its secrets, I went to the [Mimikatz documentation](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials) and [harmj0ys blog](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/) about the Credential Manager and the relationship with DPAPI. The short version is:

- The Credential Manager stores its credentials in encrypted files on the filesystem
- These are encrypted with DPAPI masterkeys
- The DPAPI masterkeys are encrypted with a key based on the users password

So if you have the user's password you can walk this path in reverse, loading and decrypting the masterkey file, then using the masterkey to decrypt the credential file, then access the credentials within, after which the process is the same as in our previous approach. Both Mimikatz and impacket have support for reading these files, as well as decrypting the master keys. However this is where I got stuck. Virtual Accounts do not have a password (or at least not one that I could find) but instead use the computer account to do any network activity. Dumping the passwords from LSASS also gives us the computer account hash/password and not the virtual accounts.

```
mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 12566491 (00000000:00bfbfdb)
Session           : Service from 0
User Name         : ADSync
Domain            : NT SERVICE
Logon Server      : (null)
Logon Time        : 11/23/2019 10:24:10 AM
SID               : S-1-5-80-3245704983-3664226991-764670653-2504430226-901976451
        msv :
         [00000003] Primary
         * Username : iyc-app-server$
         * Domain   : cloud
         * NTLM     : 45b7d3fda0363b98cffd51e4e2126720
         * SHA1     : b98982da072e3254f161981cb05ceaff6e9d21a9
```

There are two DPAPI keys for the computer account, called the DPAPI_SYSTEM keys by Mimikatz and impacket. The two keys are called the machine key and the user key and they can be dumped remotely by secretsdump.py (on which adconnectdump is based).

```
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xcedfd61df0a3490788c2791ca9627fd38b12f2d4
dpapi_userkey:0x9d35786f5af6f90ac17cd55695e33146cd6dee20
```

Neither of these was however the correct key to decrypt the masterkey of the virtual account. At this point I asked Benjamin Delpy for some advice, who offered to look into the issue. In less than two hours after I sent him an LSASS dump and masterkey file he had the issue figured out: Virtual Accounts use a combination of the userkey and the SID of the virtual account as a key to decrypt the masterkey, which was a corner case neither impacket nor Mimikatz supported yet. By now both [impacket](https://github.com/SecureAuthCorp/impacket/blob/c5183d42b6cc0b05631612d350283a298f8159b2/examples/dpapi.py#L91) and [Mimikatz](https://github.com/gentilkiwi/mimikatz/commit/3c81f16b5be1edb097898ab2ada0614e31a5195d) have support for this scenario.

## The new flow
To adapt to the new flow, there are some extra layers of crypto and DPAPI that we need to cross, but it is still possible to dump the data via only the network. The new flow looks something like this:

![AD Sync decrypt flow with more DPAPI](/assets/img/dpapi/dpapiflow-new.svg){: .align-center}

In more detail the steps involved are:
- Stop service / download database / start service just like previously
- Enumerate `C:\Users\ADSync\AppData\Local\Microsoft\Credentials` for a folder containing the SID of the account
- Enumerate the credential files in this folder, for each file load and attempt to decrypt the associated masterkey using the userkey + sid
- If the file is found containing the correct keyset, find the system masterkey associated with the keyset and decrypt it using the systemkey
- We now have the decrypted keyset with which we can decrypt the information from the database

And we see that once again the remote extraction of Azure AD Connect credentials is working:

![adconnectdump in action](/assets/img/dpapi/adconnectdump_new.png){: .align-center}

I've uploaded the new version of adconnectdump to [GitHub](https://github.com/fox-it/adconnectdump). It also still supports the old format of dumping credentials with the `--legacy` flag.

# References
Thanks and credits go as always to the ones that researched this topic for much longer than I have and contributed to the tools. Special thanks to [Benjamin](https://twitter.com/gentilkiwi) for figuring out the encryption and for Mimikatz and to [Alberto Solino](https://twitter.com/agsolino) for building and maintaining impacket and for making all the DPAPI/Credential files one import + a few lines of code away from being parsed. Lastly of course [Will](https://twitter.com/harmj0y) for his work in this area and his blog explaining the concepts really well. His [blog on this subject](https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/) contains plenty of more stuff about this subject as well as good references to older research.
