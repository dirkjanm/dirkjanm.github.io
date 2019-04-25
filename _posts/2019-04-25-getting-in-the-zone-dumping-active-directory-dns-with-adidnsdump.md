---
layout: single
classes: wide
title:  "Getting in the Zone: dumping Active Directory DNS using adidnsdump"
date:   2019-04-25 16:08:57 +0100
---
Zone transfers are a classical way of performing reconnaissance in networks (or even from the internet). They require an insecurely configured DNS server that allows anonymous users to transfer all records and gather information about host in the network. What not many people know however is that if Active Directory integrated DNS is used, any user can query all the DNS records by default. This blog introduces a tool to do this and describes a method to do this even for records normal users don't have read rights for.

# Knowing where you are and where to go
Personally whenever I arrive at a new pentest or red team assignment I want to learn about the layout of the network, the software in use and where the interesting data is. If a company has non-descriptive server names or descriptions, tools like BloodHound or ldapdomaindump are not going to help much since `SRV00001.company.local` still doesn't tell me what runs on this host. Running discovery tools like EyeWitness on a large range of IP addresses often returns a lot of default Apache/IIS pages, since most sites are configured to listen on a DNS name and not on the IP address. Knowing that `gitlab.company.local` also points to the same IP as `SRV00001.company.local` tells me that this is an interesting server if I'm after source code. Having access to DNS entries for AD is thus in my opinion quite valuable. Thus I wrote this small tool that can dump those records. You can either run it directly from a host within the network, or through a SOCKS tunnel using your favourite implant.

# Prior work
This started when I was looking at Active Directory DNS, mostly inspired by [Kevin Robertson's work on ADIDNS](https://blog.netspi.com/exploiting-adidns/). I tried to figure out how AD uses zones in LDAP for storing DNS records as I pulled up ADSI Edit and suddenly saw an overview of all the DNS records in the domain, using only a limited regular user. As I shared my surprise, Kevin pointed out to me that [mubix](https://twitter.com/mubix) already wrote about this [back in 2013](https://room362.com/post/2013/2013-10-04-ad-zone-transfers-as-a-user/). So there was already a PowerShell script that could do this, but it didn't do exactly what I wanted, so I decided to write a version in Python and add some options to enumerate more records than possible by default. **Edit**: @3xocyte also wrote a similar version in Python [here](https://gist.github.com/3xocyte/531e06361c58857a82171f104885f5e0).

# The "hidden" DNS records
The most obvious way to query for DNS records in LDAP would be to perform a query selecting all objects of the class `dnsNode`, which represent entries in the DNS zone. When I performed a query with the filter `(objectClass=dnsNode)`, this returned quite limited results, even though I could see several more records when manually browsing to the DNS zone:

![ADSI Edit of DNS zone](/assets/img/dns/dnshidden.png){: .align-center}

As visible on the image above, for several objects the objectClass is not visible. This is because of the default permissions on computer DNS records (and I think on other records not created via the AD DNS gui as well), which don't allow all users to see the contents. Since the IP addresses are actually stored as a property of this object, it isn't possible to view the IP address for these records either.

But like any user can create new DNS records by default, any user can also list the child objects of a DNS zone by default. So we know a records is there, we just can't query it using LDAP.

![DNS zone default permissions](/assets/img/dns/dnsentries.png){: .align-center}

Once we know a records exists by enumerating with LDAP, we can however query for it using DNS directly (since performing regular DNS queries doesn't require privileges). This way we can resolve all records in the zone.

# Querying records with adidnsdump
With adidnsdump, which you can get [from my GitHub](https://github.com/dirkjanm/adidnsdump), it is possible to enumerate all records in the DNS zone. To get started, first display the zones in the domain where you are currently in with `--print-zones`. This will show which zones are present. Not all zones are interesting, for example forward, cache and stub zones don't contain all the records for that domain. If you find these zones, it's better to query the domain to which they actually belong. The output below shows that my test domain has only the default zones:

```
user@localhost:~/adidnsdump$ adidnsdump -u icorp\\testuser --print-zones icorp-dc.internal.corp
Password: 
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Found 2 domain DNS zones:
    internal.corp
    RootDNSServers
[-] Found 2 forest DNS zones:
    ..TrustAnchors
    _msdcs.internal.corp
```

If we specify the zone to the tool (or leave it empty for the default zone), we will get a list of all the records. Records which can be listed but not read (so called "hidden" records) are shown but only with a question mark, as it is unknown which type of record is present and where it points to. The records are all saved to a file called `records.csv`.

![listing the DNS records](/assets/img/dns/dump.png){: .align-center}

To resolve the unknown records, specify the `-r` flag, which will perform an `A` query for all unknown records (you can easily change this to `AAAA` in the code if you're in an IPv6 network). Several nodes which were blank before now suddenly have records:

![listing and resolving DNS records](/assets/img/dns/dump_resolve.png){: .align-center}

If you don't have a direct connection but are working via an agent, you can proxy the tool through socks and perform the DNS queries over TCP with the `--dns-tcp` flag.

# Mitigations
You shouldn't really rely on secrecy of your DNS records for security. If you really want to hide this information, removing the "List contents" permission for "Everyone" and "Pre-Windows 2000 Compatible Access" does prevent regular users from querying the entries, but this does require disabling inheritance on the DNS zone and may break stuff, so I don't really recommend going that way. Monitoring for high volumes of DNS queries or enabling auditing on DNS zone listings may be a better way to deal with this, by detecting instead of blocking this kind of activity.

# The tools
adidnsdump is available on [GitHub](https://github.com/dirkjanm/adidnsdump) and on PyPI (`pip install adidnsdump`). Right now the tool only dumps records to CSV files, but feel free to submit requests for alternate formats.