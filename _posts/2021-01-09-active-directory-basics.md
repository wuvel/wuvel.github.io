---
title: "TryHackMe - Active Directory Basics"
categories:
  - TryHackMe
tags:
  - windows
  - active directory
  - exploit
  - writeup
  - tryhackme
  - hacking
---
Learn the basics of Active Directory and how it is used in the real world today

## Introduction
- Active Directory is the **directory service** for **Windows Domain Networks**. It is used by many of today's top companies and is a vital skill to comprehend when attacking Windows.
- Active Directory is a **collection** of **machines** and **servers** connected inside of **domains**, that are a collective part of a bigger forest of domains, that make up the Active Directory network. 
- Here are the list of Active Directory components. All of these parts of Active Directory come together to make a big network of machines and servers.
  - Domain Controllers
  - Forests, Trees, Domains
  - Users + Groups 
  - Trusts
  - Policies 
  - Domain Services
- Why Active Directory?
  - The majority of large companies use Active Directory because it allows for the **control** and **monitoring** of their user's computers through a **single domain controller**.
  - It allows a single user to sign in to any computer on the active directory network and have access to his or her stored files and folders in the server, as well as the local storage on that machine

## Physical Active Directory
- The physical Active Directory is the **servers** and **machines** on-premise, these can be anything from domain controllers and storage servers to domain user machines; everything needed for an Active Directory environment besides the software.
- Domain Controllers:
  - Domain controller is a **Windows server** that has **Active Directory Domain Services** (AD DS) installed and has been promoted to a domain controller in the forest.
  - Domain controllers are the center of Active Directory -- they control the rest of the domain
  - Domain controller tasks:
    - holds the AD DS data store 
    - handles authentication and authorization services 
    - replicate updates from other domain controllers in the forest
    - allows admin access to manage domain resources
- AD DS Data Store:
  - Active Directory Data Store holds the **databases** and **processes** needed to store and manage directory information such as **users**, **groups**, and **services**.
  - Characteristic of the AD DS Data Store:
    - Contains the `NTDS.dit` - a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users
    - Stored by default in `%SystemRoot%\NTDS`
    - accessible **only** by the domain controller

#### What database does the AD DS contain?
> AD DS contains the `NTDS.dit`, a database that contains all of the information of an Active Directory domain controller as well as password hashes for domain users

#### Where is the NTDS.dit stored?
> `NTDS.dit` database Stored by default in `%SystemRoot%\NTDS`.

#### What type of machine can be a domain controller?
> Windows server or the most part.

## The Forest
- The forest is what defines everything; it is the container that **holds** all of the other bits and pieces of the network together -- without the forest all of the other trees and domains would not be able to **interact**.
- The "forest" term, it is only a way of describing the connection created between these trees and domains by the network.
- Visualization:<br><center><a href="https://blogvaronis2.wpengine.com/wp-content/uploads/2018/12/domain-forest@2x.png"><img src="https://blogvaronis2.wpengine.com/wp-content/uploads/2018/12/domain-forest@2x.png"></a></center>
- A forest is a **collection** of one or more **domain trees** inside of an Active Directory network. It is what categorizes the parts of the network as a whole.
- The Forest consists of these parts:
  - **Trees** - A hierarchy of domains in Active Directory Domain Services
  - **Domains** - Used to group and manage objects 
  - **Organizational Units (OUs)** - Containers for groups, computers, users, printers and other OUs
  - **Trusts** - Allows users to access resources in other domains
  - **Objects** - users, groups, printers, computers, shares
  - **Domain** **Services** - DNS Server, LLMNR, IPv6
  - **Domain Schema** - Rules for object creation

#### What is the term for a hierarchy of domains in a network?
> Trees - A hierarchy of domains in Active Directory Domain Services.

#### What is the term for the rules for object creation?
> Domain Schema - Rules for object creation.

#### What is the term for containers for groups, computers, users, printers, and other OUs?
> Organizational Units (OUs) - Containers for groups, computers, users, printers and other OUs. 

## Users + Groups
- When you create a domain controller it comes with default groups and two default users: Administrator and guest. It is up to you to create new users and create new groups to add users to.
- There are four types of users are: 
  - **Domain Admins** - This is the big boss: they control the domains and are the only ones with access to the domain controller.
  - **Service Accounts** (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair a service with a service account
  - **Local Administrators** - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
  - **Domain Users** - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.
- Groups make it easier to give permissions to users and objects by organizing them into groups with specified permissions. There are two overarching types of Active Directory groups: 
  - **Security Groups** - These groups are used to specify permissions for a large number of users
  - **Distribution Groups** - These groups are used to specify email distribution lists. As an attacker these groups are less beneficial to us but can still be beneficial in enumeration
- There are a lot of default security groups so I won't be going into too much detail of each past a brief description of the permissions that they offer to the assigned group. Here is a brief outline of the security groups:
  - **Domain Controllers** - All domain controllers in the domain
  - **Domain Guests** - All domain guests
  - **Domain Users** - All domain users
  - **Domain Computers** - All workstations and servers joined to the domain
  - **Domain Admins** - Designated administrators of the domain
  - **Enterprise Admins** - Designated administrators of the enterprise
  - **Schema Admins** - Designated administrators of the schema
  - **DNS Admins** - DNS Administrators Group
  - **DNS Update Proxy** - DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
  - **Allowed RODC Password Replication Group** - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
  - **Group Policy Creator Owners** - Members in this group can modify group policy for the domain
  - **Denied RODC Password Replication Group** - Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
  - **Protected Users** - Members of this group are afforded additional protections against authentication security threats. See [http://go.microsoft.com/fwlink/?LinkId=298939](http://go.microsoft.com/fwlink/?LinkId=298939) for more information.
  - **Cert Publishers** - Members of this group are permitted to publish certificates to the directory
  - **Read-Only Domain Controllers** - Members of this group are Read-Only Domain Controllers in the domain
  - **Enterprise Read-Only Domain Controllers** - Members of this group are Read-Only  Domain Controllers in the enterprise
  - **Key Admins** - Members of this group can perform administrative actions on key objects within the domain.
  - **Enterprise Key Admins** - Members of this group can perform administrative actions on key objects within the forest.
  - **Cloneable Domain Controllers** - Members of this group that are domain controllers may be cloned.
  - **RAS and IAS Servers** - Servers in this group can access remote access properties of users

#### Which type of groups specify user permissions?
> Security Groups - These groups are used to specify permissions for a large number of users.

#### Which group contains all workstations and servers joined to the domain?
> Domain Computers - All workstations and servers joined to the domain.

#### Which group can publish certificates to the directory?
> Cert Publishers - Members of this group are permitted to publish certificates to the directory.

#### Which user can make changes to a local machine but not to a domain controller?
> Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller.

#### Which group has their passwords replicated to read-only domain controllers?
> Allowed RODC Password Replication Group - Members in this group can have their passwords replicated to all read-only domain controllers in the domain.

## Trusts + Policies
- Trusts and policies go hand in hand to help the domain and trees communicate with each other and maintain "security" inside of the network.
- Trust and Policies put the rules in place of how the **domains inside of a forest** can interact with each other, how an **external forest** can interact with the forest, and the overall domain **rules** or **policies** that a domain must follow.
- For the most part, trusts **outline the way** that the domains inside of a forest communicate to each other, in some environments trusts can be extended out to external domains and even forests in some cases.
- There are two types of trusts that determine how the domains communicate:
  - **Directional** - The direction of the trust flows from a trusting domain to a trusted domain
  - **Transitive** - The trust relationship expands beyond just two domains to include other trusted domains
- The type of trusts put in place determines how the domains and trees in a forest are able to communicate and send data to and from each other when attacking an Active Directory environment you can sometimes abuse these trusts in order to move laterally throughout the network. 
- Policies dictate how the server operates and what rules it will and will not follow. 
- Policies simply act as a rulebook for Active  Directory that a domain admin can **modify** and **alter** as they deem necessary to keep the network running smoothly and securely.
- The options for domain policies are almost endless and are a big factor for attackers when **enumerating** an Active Directory network.
- Example policies that are default or you can create in an Active Directory environment: 
  - **Disable Windows Defender** - Disables windows defender across all machine on the domain
  - **Digitally Sign Communication** (Always) - Can disable or enable SMB signing on the domain controller

#### What type of trust flows from a trusting domain to a trusted domain?
> Directional - The direction of the trust flows from a trusting domain to a trusted domain.

#### What type of trusts expands to include other trusted domains?
> Transitive - The trust relationship expands beyond just two domains to include other trusted domains.

## Active Directory Domain Services + Authentication
- AD Domain Services allow for management of the domain, security certificates, LDAPs, and much more. This is how the domain controller decides what it wants to do and what services it wants to provide for the domain.
- Outlined below are the default domain services: 
  - **LDAP** - Lightweight Directory Access Protocol; provides communication between applications and directory services
  - **Certificate Services** - allows the domain controller to create, validate, and revoke public key certificates
  - **DNS, LLMNR, NBT-NS** - Domain Name Services for identifying IP hostnames
- There are two main types of authentication in place for Active Directory: 
  - **NTLM** - default Windows authentication protocol uses an encrypted challenge/response protocol.
  - **Kerberos** - The default authentication service for Active Directory uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain.

#### What type of authentication uses tickets? 
> Kerberos - The default authentication service for Active Directory uses ticket-granting tickets.

#### What domain service can create, validate, and revoke public key certificates?
> Certificate Services - allows the domain controller to create, validate, and revoke public key certificates.

## AD in the Cloud
- The most notable AD cloud provider is Azure AD.
- Its default settings are much more secure than an on-premise physical Active Directory network; however, the cloud AD may still have vulnerabilities in it. 
- Azure acts as the **middle man** between your physical Active Directory and your users' sign on. This allows for a more secure transaction between domains, making a lot of Active Directory attacks ineffective.
- Comparison with a cloud Active Directory environment: 

  | **Windows Server AD**	| *Azure AD* |
  | ----------------- | -------- |
  | LDAP |	Rest APIs |
  | NTLM |	OAuth/SAML |
  | Kerberos |	OpenID |
  | OU Tree |	Flat Structure |
  | Domains and Forests |	Tenants |
  | Trusts |	Guests |

#### What is the Azure AD equivalent of LDAP?
> Rest APIs

#### What is the Azure AD equivalent of Domains and Forests?
> Tenants

##### What is the Windows Server AD equivalent of Guests?
> Trusts

## Hands-On Lab
- Follow the instructions.
- Cheatsheet [here](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993).

#### What is the name of the Windows 10 operating system?
```powershell
PS C:\Users\Administrator\Downloads> Get-NetComputer -fulldata | select operatingsystem

operatingsystem
---------------
Windows Server 2019 Standard
Windows 10 Enterprise Evaluation
Windows 10 Enterprise Evaluation
```

#### What is the second "Admin" name?
```powershell
PS C:\Users\Administrator\Downloads> Get-NetUser | select cn

cn
--
Administrator
Guest
krbtgt
Machine-1
Admin2
Machine-2
SQL Service
POST{P0W3RV13W_FTW}
sshd
```

### Which group has a capital "V" in the group name?
```powershell
PS C:\Users\Administrator\Downloads> Get-NetGroup -GroupName *
...
RDS Remote Access Servers
RDS Endpoint Servers
RDS Management Servers
Hyper-V Administrators
...
```

#### When was the password last set for the SQLService user?
```powershell
PS C:\Users\Administrator\Downloads> Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'}


logoncount            : 0
badpasswordtime       : 12/31/1600 4:00:00 PM
description           : My password is MYpassword123#
distinguishedname     : CN=SQL Service,CN=Users,DC=CONTROLLER,DC=local
objectclass           : {top, person, organizationalPerson, user}
displayname           : SQL Service
userprincipalname     : SQLService@CONTROLLER.local
name                  : SQL Service
objectsid             : S-1-5-21-849420856-2351964222-986696166-1107
samaccountname        : SQLService
lastlogon             : 12/31/1600 4:00:00 PM
codepage              : 0
samaccounttype        : 805306368
whenchanged           : 5/14/2020 3:42:53 AM
accountexpires        : 9223372036854775807
countrycode           : 0
adspath               : LDAP://CN=SQL Service,CN=Users,DC=CONTROLLER,DC=local
instancetype          : 4
objectguid            : 1c3f20d7-c383-466a-9a67-92a774650cb8
sn                    : Service
lastlogoff            : 12/31/1600 4:00:00 PM
objectcategory        : CN=Person,CN=Schema,CN=Configuration,DC=CONTROLLER,DC=local
dscorepropagationdata : {5/14/2020 3:29:56 AM, 1/1/1601 12:00:00 AM}
serviceprincipalname  : DOMAIN-CONTROLLER/SQLService.CONTROLLER.local:60111
givenname             : SQL
admincount            : 1
memberof              : {CN=Group Policy Creator Owners,OU=Groups,DC=CONTROLLER,DC=local, CN=Domain
                        Admins,OU=Groups,DC=CONTROLLER,DC=local, CN=Enterprise
                        Admins,OU=Groups,DC=CONTROLLER,DC=local, CN=Schema Admins,OU=Groups,DC=CONTROLLER,DC=local...}
whencreated           : 5/14/2020 3:26:57 AM
badpwdcount           : 0
cn                    : SQL Service
useraccountcontrol    : 66048
usncreated            : 12820
primarygroupid        : 513
pwdlastset            : 5/13/2020 8:26:58 PM
usnchanged            : 12890
```