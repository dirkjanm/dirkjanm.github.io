---
layout: single
classes: wide
title:  "Persisting on Entra ID applications and User Managed Identities with Federated Credentials"
date:   2024-07-31 20:00:57 +0200
---

Using applications and service principals for persistence and privilege escalation is a well-known topic in Entra ID (Azure AD). I've [written about](/azure-ad-privilege-escalation-application-admin/) these kind of attacks many years ago, and talked about how we can use certificates and application passwords to authenticate as applications and abuse the permissions they have. In this blog, we cover a third way of authenticating as an application: using federated credentials. Federated credentials have been around for a few years, but haven't been covered much yet from the offensive side. For Entra ID applications, there is no large difference between configuring federated credentials or regular client secrets/certificates. The more interesting part on this topic is that we can also configure federated credentials on User Managed Identities in Azure. This is unusual, because normally Managed Identities have their authentication controlled by Microsoft, and their authentication is tied to a certain resource such as a Virtual Machine. With federated credentials, we can bypass that limitation, given that we have sufficient privileges, and authenticate as this managed identity without requiring access to another resource in Azure. With this blog I'm also introducing a new utility to the ROADtools family: roadoidc, which can set up a minimal Identity Provider (IdP), allowing us to authenticate using federated credentials as apps and user managed identities with roadtx.

# Federated credentials concept
The idea behind federated credentials is that you can choose to trust some other Identity Provider (IdP) to authenticate your apps. This solves for example manual credential management on workloads that run outside of Azure, where Managed Identities are unavailable. An example of this is that you can use federated credentials in GitHub actions. This would allow a specific pipeline or pipelines from the same repository to access a workload identity without needing certificates or passwords configured in the pipeline definition. The concept of federated identities in Entra and Azure documented [here](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation).

On a protocol level, federated credentials use OpenID Connect (OIDC) as a way of establishing a trust between Entra and another IdP. The protocol is [standardized](https://openid.net/specs/openid-connect-core-1_0.html) and is commonly used to let applications trust Entra ID as an IdP, but in this case we use it as a way for Entra ID to trust a third-party IdP. Once the IdP is configured as a trusted token issuer, Entra will query the `.well-known/openid-configuration` endpoint [as specified in the OpenID Connect discovery protocol](https://openid.net/specs/openid-connect-discovery-1_0.html). This configuration document also points us to the trusted keys with which ID tokens must be signed.

# Creating our own minimal IdP
The idea behind using federated credentials is that we trust a well-known platform such as GitHub, AWS or GCP. But we can also roll our own IdP with our own keys, as long as we can host them somewhere Entra ID can reach them. At the minimum, we need two files:

* The OpenID Provider Configuration file at `.well-known/openid-configuration`.
* The keys document linked in the `jwks_uri` property of the Provider Configuration file.

The keys document contains a public key and/or certificate that we can use to sign our tokens. The certificate is optional in this deployment, a public/private RSA or EC keypair is sufficient to make it work. The certificate that we want to use can be self-signed, so we don't need to involve a Certificate Authority. I'll show you later how we can generate the keys and configuration with roadoidc, but let us assume for now that we have these files hosted on `https://roadoidcapp.azurewebsites.net`. This site will then become the `issuer` of our tokens.

# Configuring federated credentials on applications and user managed identities
We can configure the federated credential on applications in the tenant we want to target. The permissions here are identical to the permissions you would normally need to configure certificates or passwords on applications, so you would need one of the following:

* Global Administrator (doh)
* (Cloud) Application administrator
* Owner privileges over the app
* *Application.ReadWrite.All* or *Directory.ReadWrite.All* Microsoft Graph permissions

We can then configure the federated credentials on an application as follows:

![Configuring federated credentials on an app](/assets/img/oidc/federatedcredentials-app.png)

The `issuer` should be `https://roadoidcapp.azurewebsites.net` since this is where our keys are hosted. The *subject identifier* and *audience* could be anything since we can put arbitrary strings in our tokens, so just pick something nice or leave it at the default. We can achieve the same with the [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/application-post-federatedidentitycredentials?view=graph-rest-1.0&tabs=http), if preferred over the portal. What is interesting, is that while technically the `federatedIdentityCredentials` property also exists on Service Principals, the Microsoft Graph API does not allow us to configure these credentials there, stating that it is not supported.

## User Managed identities
On User Managed identities this concept is more interesting, since we don't normally manage credentials ourselves on them. In fact, for certificates and password credentials this is not even possible, Microsoft prohibits us from modifying these properties on the service principal representing the managed identity in Entra ID. We can however manage their federated credentials, granted that we have `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write` permissions that come with the following built-in Azure RBAC roles:

* Contributor / Owner
* Managed Identity Contributor
* Azure Red Hat OpenShift Federated Credential Role

With these permissions, we can configure the federated credentials on the user managed identity, and authenticate to it from anywhere without needing to link the identity to a resource and having access to that resource. Note that this attack is only possible on User Managed Identities, not on System Managed Identities, since these are tied to a resource and don't allow federated credential configuration.

![Configuring federated credentials on an app](/assets/img/oidc/federatedcredentials-managed-identity.png)

# Creating an OpenID connect provider with roidoidc
Before we authenticate we need to host the OpenID Connect provider configuration and the public keys somewhere Entra ID can reach them. In this case I'm hosting them as an Azure App Service, but any file host will do, including Azure Blob storage or S3 (which would be cheaper than Azure App Service). I've added some alternative hosting instructions in the [roadoidc readme](https://github.com/dirkjanm/ROADtools/tree/master/roadoidc), but the first commands would be the same.

We need to generate the configuration for our environment with the `genconfig.py` file, found in the `roadoidc` directory of [ROADtools](). I suggest cloning the repository locally after install roadtx and roadrecon, which contain all the dependencies for roadoidc as well. In my case I will be running the app at `roidoidcapp.azurewebsites.net`, which means that becomes my issuer parameter.

```
python3 genconfig.py -c testconfig.py -i https://roadoidcapp.azurewebsites.net
Saving private key to roadoidc.key
Saving certificate to roadoidc.pem
Key ID: 54XPuTfyhvtuy94A6g2YjiL3Rx8=
Saving configuration to testconfig.py
```

Now move the config to the `flaskapp` folder so we can deploy it on Azure App Service. We can upload the app using the Azure CLI, optionally specifying the subscription to deploy to and/or an existing app service plan. The command below will create a new app service plan with the cheapest B1 tier:

```
mv testconfig.py flaskapp/app_config.py
cd flaskapp/
az webapp up -n roadoidcapp --sku B1
```

Once the webapp is up, verify we can reach the discovery document at `https://yourapp.azurewebsites.net/.well-known/openid-configuration`. If that works we can now authenticate to the app or user managed identity that we configured the federated credentials on.

# Authenticating with federated credentials and roadtx
Make sure you have the latest version of roadtx installed. We need to specify quite a few parameters to authenticate with federated credentials and roadtx:

* The **client ID** of the application or user managed identity (`-c`)
* The **tenant** we want to authenticate to. Either as tenant ID or as one of the domains of the tenant (`-t`)
* The **scope** of the token we want to have, for example `https://graph.microsoft.com/.default` (`-s`)
* The **issuer** that we configured in the previous stap (`-i`)
* The certificate and/or key that we created (`--cert-pem` and `--key-pem`)
* The **subject** that we configured in the federated credential configuration (`--subject`)
* An optional **audience** if you changed it in the federated credential configuration (`--audience`)
* An optional **key id** if you chose a custom one when generating the IdP config (`--kid`)

In my case, the command would be as follows:

```
roadtx federatedappauth -c 8a2c36aa-66fb-46cd-9b2d-b94a4945e0a9 --cert-pem roadoidc.pem --key-pem roadoidc.key --subject testapp -t iminyour.cloud --issuer https://roadoidcapp.azurewebsites.net/ -s https://graph.microsoft.com/.default 
```

This will request a token using the client credentials grant flow, using a federated assertion instead of a certificate based assertion, which is [somewhat documented](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow#third-case-access-token-request-with-a-federated-credential) in the Identity Platform documentation. The output of this command will be an access token in the `.roadtools_auth` file.

# Conclusion
This blog shows an alternative approach attackers can use to configure credentials on Entra ID applications and Azure User Managed Identities. It can help them persist in environments or even elevate privileges if they can compromise a service principal with high privileges. Federated Credentials can come from well-known identity providers, but we can also create our own minimal IdP to avoid being limited to a platform such as GitHub for our token requests. Defenders should be aware of this possibility and monitor for unexpected federated credential that are configured on User Managed Identities and Entra ID applications. Thomas Naunheim wrote a [great blog with defensive guidance](https://www.cloud-architekt.net/identify-prevent-abuse-uami-fedcreds/) on this same topic.

The tool that you can use to create your own IdP is available in the [ROADtools](https://github.com/dirkjanm/ROADtools) repository on GitHub in the [roadoidc directory](https://github.com/dirkjanm/ROADtools/tree/master/roadoidc). 
