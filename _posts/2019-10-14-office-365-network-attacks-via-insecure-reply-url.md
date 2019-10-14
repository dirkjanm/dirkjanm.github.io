---
layout: single
classes: wide
title:  "Office 365 network attacks - Gaining access to emails and files via an insecure Reply URL"
date:   2019-10-14 19:08:57 +0200
---
One of the main powers of Office 365 is the tight integration between all the online applications. At the same time this is a risk since those applications have access to other elements such as emails in Outlook or files on SharePoint/Onedrive. This means that if there is a vulnerability (for example an XSS) in one of these applications, the impact may not just be the data stored in that application, but also impact other data stored in Office 365. This blog discusses a vulnerability Microsoft Teams that allowed an attacker to access emails and files stored in Office 365 when they could convince a victim to connect to a rogue (wireless) network. I disclosed this to Microsoft earlier this year and the issue was resolved this week. More apps may be vulnerable to these kind of issues so make sure to check your organization's environment for similar issues.

# OAuth2 and the implicit grant flow
The [OAuth2 implicit grant flow](https://oauth.net/2/grant-types/implicit/) is used in Office 365 applications that live primarily in the browser and request information using for example the Microsoft Graph. It is conceptually pretty straightforward. If an application wants to authenticate a user and request their Office 365 data, they forward the user to the central Microsoft online login page. In the URL they include the unique application ID and a URL to redirect the user back to after authenticating. When the user is authenticated, the access token that can be used by the application to impersonate the user's identity is appended to this URL and used to redirect the user back to the application. Because the access token is added to the URL via a [fragment identifier](https://en.wikipedia.org/wiki/Fragment_identifier) `#`, this token is not sent to the server over the wire, but can be accessed by JavaScript running on the page. To prevent attackers from sending users to the login page with a rogue website they control, the allowed redirect URLs are whitelisted per application. This information is stored on the Service Principal in Azure Active Directory (the identity component of Office 365) and can be queried with the AzureAD PowerShell module using the `Get-AzureADServicePrincipal` cmdlet.

# The vulnerability
When browsing through some of the service principals and their properties, I noticed that the `Microsoft Teams Web Client` service principal had some odd entries:

![http dev.local reply URLs](/assets/img/o365/replyurls.png){: .align-center}

Apart from the fact that someone on the Teams team likes wine, there are some references to `dev.local` in here, including one that allows HTTP instead of HTTPS. This means that tokens issues to Microsoft teams can be sent to `http://dev.local` and anyone with control over that page can use those tokens to interact with Office 365. I've outlined two attack scenarios:

## Rogue Wifi network
If a victim connects to an attacker controlled Wifi network, they can use automatic captive portal detection to redirect the victim to a site of their choosing. This site can then redirect the victim to the Microsoft online sign-in page using the Microsoft Teams Web Client application ID and the `http://dev.local` reply URL. After logging in the Microsoft Online login page will send the victim to the `dev.local` site. This redirect which will work automatically without any user interaction if the Azure AD environment supports Single Sign On or the user is already signed in. Because the attacker controls the network, and thus controls DNS replies, they can serve the user JavaScript on a page that captures this access token and forwards it to the attacker. There are no security prompts since the website is served over HTTP and thus no TLS certificate verification is used. Here is a demo video in which I use a fully up-to-date Azure AD joined Windows 10 device to connect to a rogue wireless network, which obtains the token allowing access to my email without any user interaction:

<video width="100%" controls>
  <source src="/assets/raw/replyurlwifi.mp4" type="video/mp4">
</video> 

## Local network access
Since `.local` is not an allowed DNS top level domain, DNS servers on the internet will not resolve the domain name. Windows clients will (rightfully) attempt to resolve this using broadcast protocols such as mDNS and LLMNR. An attacker which already has access to the local network can reply to these broadcast resolution requests using tools such as Responder.

# The impact
The Microsoft Teams Web Client has quite some privileges. The privileges can be analyzed by decoding the JSON Web Token issued by Azure AD for the different API's that Microsoft offers. This reveals the following rights for Microsoft Teams:

API | Access
--- | ---
Azure AD Graph | UserProfile.Read
Microsoft Graph | Files.ReadWrite.All Notes.ReadWrite.All Sites.ReadWrite.All
Outlook API | Calendars.ReadWrite Contacts.ReadWrite EWS.AccessAsUser.All Mail.ReadWrite Mail.Send User.Read User.ReadBasic.All

This means an attacker can read all victims' emails, send emails as the victim, access their OneDrive files and all SharePoint sites and files on those sites that the victim user has access to. While this access is not permanent as the access token expires after 1 hour by default, this offers the attacker plenty of time to access sensitive files and emails. Additionally there is no reliable way to identify this attack in the logs since the reply URL is not logged in the Azure AD sign-in log. And since this is a completely legitimate sign-in into Microsoft Teams, most conditional access policies will pass if the requirements are related to the device state or MFA (assuming the user is signed in or has Single Sign On enabled).

The TL;DR of this is that if you use Office 365 on your laptop (I haven't tested this with mobile devices) and join an untrusted wireless network such as airport WiFi or the network of your favourite coffee store, an attacker could have gained access to all your emails and corporate SharePoint/OneDrive files. I have not tested this on personal/small business subscriptions but I imagine that only Office 365 subscriptions that include Microsoft Teams were vulnerable.

# Proof of concept
The way to exploit this is rather straightforward, as an attacker you have to find a way to redirect the victim to a specific URL and make sure that `dev.local` resolves to an attacker controlled machine. The sign-in URL for Microsoft Teams and the Microsoft Graph is:

```
https://login.microsoftonline.com/common/oauth2/authorize?response_type=token&client_id=5e3ce6c0-2b1f-4285-8d4b-75ee78787346&resource=https://graph.windows.net&redirect_uri=http://dev.local
```

# The fix
As far as I've been able to identify, any Office 365 tenant that was created after September 2019 does not have these Reply URLs anymore in the Service Principal properties. Tenants created before this date still have the vulnerable URL showing up in the Reply URL. When trying to visit the above URL however, Azure AD will error out with the following message:

![AADSTS50011: The reply url specified in the request does not match the reply urls configured for the application](/assets/img/o365/replyurl_fix.png){: .align-center}

To identify if this was fixed in your tenant or if your organization is affected, you can visit the sign-in URL above. If you get redirected to dev.local with an access token instead of getting an error message, you are affected. Of course you should make sure that `dev.local` is not pointing to an untrusted host as then they could obtain your access token...

## Reviewing application reply URLs
There may exist other third-party or organization specific applications in your Azure AD that have insecure reply URLs. Besides URLs using HTTP, URLs pointing to expired or unregistered domain names are also a risk. Using the AzureAD PowerShell module, the following commands can list the reply URLs for each Service Principal:

```
Connect-AzureAD
$sp = Get-AzureADServicePrincipal -all $true
$FormatEnumerationLimit=-1
$sp | select displayname,appid,replyurls | fl
```

Note that though some (default) applications do have an insecure reply URL, not all applications actually have the implicit flow enabled (or are even fully disabled), so make sure to test this. Updating the Reply URLs can be done with the `Set-AzureADServicePrincipal` cmdlet.

# Disclosure timeline
I disclosed this to Microsoft back in June this year. The report was assigned a low severity because of the exploitation requirements, which resulted in a quite long time to fix and limited communication. After the 90 days disclosure time had passed I was informed the issue was fixed. Further investigation showed it was indeed fixed but only for new tenants, leaving the majority vulnerable. A month later the issue seems resolved for existing tenants as well.

Communication timeline:

June 17 - Report sent  
June 19 - Sent corrected version of the report with additional details  
June 20 - Case opened  
July 11 - Requested update on case and submitted video POC  
July 12 - Got update that issue is still under investigation  
August 12 - Requested update and reminded of 90 days disclosure deadline  
August 12 - Got update that issue is being worked one  
September 18 - Got update that issue was reproduced and fixed  
October 14 - Testing confirms fix works for existing tenants as well now  
October 14 - Published blog  