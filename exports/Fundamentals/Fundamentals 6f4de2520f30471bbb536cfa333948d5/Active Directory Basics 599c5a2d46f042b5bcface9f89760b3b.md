# Active Directory Basics

- Prerequisites
    
    [Windows Basics](https://www.notion.so/Windows-Basics-92e2d4a4698848a88b84cc737a4ae237?pvs=21)
    
    [Windows Security Basics](https://www.notion.so/Windows-Security-Basics-a3be49509de34546b4bd04074f780f95?pvs=21)
    
    [*Windows Command line*](https://www.notion.so/Windows-Command-line-d66d5731cdd642c88249ba31adc99f18?pvs=21)
    

---

- Table Of Contents

---

# Introduction

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled.png)

- active directory similar to a service running on the domain controller (like Apache running on Linux)
- It has come under increasing attack in recent years. It is designed to be backward-compatible, and many features are arguably not "secure by default," and it can be easily misconfigured. This weakness can be leveraged to move laterally and vertically within a network and gain unauthorized access. AD is essentially a sizeable read-only database accessible to all users within the domain, regardless of their privilege level. A basic AD user account with no added privileges can enumerate most objects within AD. This fact makes it extremely important to properly secure an AD implementation because ANY user account, regardless of their privilege level, can be used to enumerate the domain and hunt for misconfigurations and flaws thoroughly

Active Directory is a collection of machines and servers connected inside of domains, that are a collective part of a bigger forest of domains, that make up the Active Directory network. Active Directory contains many functioning bits and pieces, a majority of which we will be covering in the upcoming tasks. To outline what we'll be covering take a look over this list of Active Directory components and become familiar with the various pieces of Active Directory

# Why use Active Directory?

The majority of large companies use Active Directory because it allows for the control and monitoring of their user's computers through a single domain controller. It allows a single user to sign in to any computer on the active directory network and have access to his or her stored files and folders in the server, as well as the local storage on that machine. This allows for any user in the company to use any machine that the company owns, without having to set up multiple users on a machine. Active Directory does it all for you.

# Active Directory Terminologies

## ⇒ **Object**

An object can be defined as ANY resource present within an Active Directory environment such as OUs, printers, users, domain controllers, etc.

## ⇒ **Attributes**

Every object in Active Directory has an associated set of [attributes](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all) used to define characteristics of the given object. A computer object contains attributes such as the hostname and DNS name. All attributes in AD have an associated LDAP name that can be used when performing LDAP queries, such as `displayName` for `Full Name` and `given name` for `First Name`.

## ⇒ **Schema**

The Active Directory [schema](https://docs.microsoft.com/en-us/windows/win32/ad/schema) is essentially the blueprint of any enterprise environment. It defines what types of objects can exist in the AD database and their associated attributes. It lists definitions corresponding to AD objects and holds information about each object. For example, users in AD belong to the class "user," and computer objects to "computer," and so on. Each object has its own information (some required to be set and others optional) that are stored in Attributes. When an object is created from a class, this is called instantiation, and an object created from a specific class is called an instance of that class. For example, if we take the computer RDS01. This computer object is an instance of the "computer" class in Active Directory. Rules for object creation

## ⇒ **Domain**

A domain is a logical group of objects such as computers, users, OUs, groups, etc. We can think of each domain as a different city within a state or country. Domains can operate entirely independently of one another or be connected via trust relationships.

## ⇒ Forests

The forest is what defines everything; it is the container that holds all of the other bits and pieces of the network together -- without the forest all of the other trees and domains would not be able to interact. The one thing to note when thinking of the forest is to not think of it too literally -- it is a physical thing just as much as it is a figurative thing. When we say "forest", it is only a way of describing the connection created between these trees and domains by the network.

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%201.png)

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%202.png)

- when you create a domain you have One domain, One tree, and one forest
- The Forest consists of these parts which we will go into further detail with later:
    - Trees - A hierarchy of domains in Active Directory Domain Services
    - Domains - Used to the group and manage objects
    - Organizational Units (OUs) - Containers for groups, computers, users, printers, and other OUs
    - Trusts - Allows users to access resources in other domains
    - Objects - users, groups, printers, computers, shares
    - Domain Services - DNS Server, LLMNR, IPv6
    - Domain Schema - Rules for object creation

## ⇒ **Tree**

A tree is a collection of Active Directory domains that begins at a single root domain. A forest is a collection of AD trees. Each domain in a tree shares a boundary with the other domains. A parent-child trust relationship is formed when a domain is added under another domain in a tree. Two trees in the same forest cannot share a name (namespace). Let's say we have two trees in an AD forest: `inlanefreight.local` and `ilfreight.local`. A child domain of the first would be `corp.inlanefreight.local` while a child domain of the second could be `corp.ilfreight.local`. All domains in a tree share a standard Global Catalog which contains all information about objects that belong to the tree.

## ⇒ **Container**

Container objects hold other objects and have a defined place in the directory subtree hierarchy.

## ⇒ **Leaf**

Leaf objects do not contain other objects and are found at the end of the subtree hierarchy.

## ⇒ **Global Unique Identifier (GUID)**

A [GUID](https://docs.microsoft.com/en-us/windows/win32/adschema/a-objectguid) is a unique 128-bit value assigned when a domain user or group is created. This GUID value is unique across the enterprise, similar to a MAC address. Every single object created by Active Directory is assigned a GUID, not only user and group objects. The GUID is stored in the `ObjectGUID` attribute. When querying for an AD object (such as a user, group, computer, domain, domain controller, etc.), we can query for its `objectGUID` value using PowerShell or search for it by specifying its distinguished name, GUID, SID, or SAM account name. GUIDs are used by AD to identify objects internally. Searching in Active Directory by GUID value is probably the most accurate and reliable way to find the exact object you are looking for, especially if the global catalog may contain similar matches for an object name. Specifying the `ObjectGUID` value when performing AD enumeration will ensure that we get the most accurate results pertaining to the object we are searching for information about. The `ObjectGUID` property `never` changes and is associated with the object for as long as that object exists in the domain.

your user's Active Directory GUID (Globally Unique Identifier) will not change if your privileges and permissions are modified.

## ⇒ **Security principals**

[Security principals](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals) are anything that the operating system can authenticate, including users, computer accounts, or even threads/processes that run in the context of a user or computer account (i.e., an application such as Tomcat running in the context of a service account within the domain). In AD, security principles are domain objects that can manage access to other resources within the domain. We can also have local user accounts and security groups used to control access to resources on only that specific computer. These are not managed by AD but rather by the [Security Accounts Manager (SAM)](https://en.wikipedia.org/wiki/Security_Account_Manager).

## ⇒ Security IDentifier ( **SID** )

Each of the security principals on the system has a unique security identifier (SID). The system automatically generates SIDs. This means that even if, for example, we have two identical users on the system, Windows can distinguish the two and their rights based on their SIDs. SIDs are string values with different lengths, which are stored in the security database. These SIDs are added to the user's access token to identify all actions that the user is authorized to take.

A SID consists of the Identifier Authority and the Relative ID (RID). In an Active Directory (AD) domain environment, the SID also includes the domain SID.

![Untitled](../Network%20Penetration%20Testing%207bc0c24ad8fe484d8df2696d10985222/Windows%20Security%20Basics%20a3be49509de34546b4bd04074f780f95/Untitled.png)

![Untitled](../Network%20Penetration%20Testing%207bc0c24ad8fe484d8df2696d10985222/Windows%20Security%20Basics%20a3be49509de34546b4bd04074f780f95/Untitled%201.png)

The SID is broken down into this pattern.

```
(SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)
```

Let's break down the SID piece by piece.

`S-1-5-21-674899381-4069889467-2080702030-1002`

| Number | Meaning | Description |
| --- | --- | --- |
| S | SID | Identifies the string as a SID. |
| 1 | Revision Level | To date, this has never changed and has always been 1. |
| 5 | Identifier-authority | A 48-bit string that identifies the authority (the computer or network) that created the SID. |
| 21 | Subauthority1 | This is a variable number that identifies the user's relation or group described by the SID to the authority that created it. It tells us in what order this authority created the user's account. |
| 674899381-4069889467-2080702030 | Subauthority2 | Tells us which computer (or domain) created the number |
| 1002 | Subauthority3 | The RID that distinguishes one account from another. Tells us whether this user is a normal user, a guest, an administrator, or part of some other group |

## ⇒ **Security Identifier (SID)**

A [security identifier](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-principals), or SID is used as a unique identifier for a security principal or security group. Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database. A SID can only be used once. Even if the security principle is deleted, it can never be used again in that environment to identify another user or group. When a user logs in, the system creates an access token for them which contains the user's SID, the rights they have been granted, and the SIDs for any groups that the user is a member of. This token is used to check rights whenever the user performs an action on the computer. There are also [well-known SIDs](https://ldapwiki.com/wiki/Well-known%20Security%20Identifiers) that are used to identify generic users and groups. These are the same across all operating systems. An example is the `Everyone` group.

## ⇒ **Distinguished Name (DN)**

A [Distinguished Name (DN)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names) describes the full path to an object in AD (such as `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`). In this example, the user `bjones` works in the IT department of the company Inlanefreight, and his account is created in an Organizational Unit (OU) that holds accounts for company employees. The Common Name (CN) `bjones` is just one way the user object could be searched for or accessed within the domain.

**`distinguishedname`:  Distinguished Name `CN=Mahmoud Hawash,OU=Users,OU=Nakerah,DC=Domain Name,DC=local`**

## ⇒ **Relative Distinguished Name (RDN)**

A [Relative Distinguished Name (RDN)](https://docs.microsoft.com/en-us/windows/win32/ad/object-names-and-identities) is a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy. In our example, `bjones` is the Relative Distinguished Name of the object. AD does not allow two objects with the same name under the same parent container, but there can be two objects with the same RDNs that are still unique in the domain because they have different DNs. For example, the object `cn=bjones,dc=dev,dc=inlanefreight,dc=local` would be recognized as different from `cn=bjones,dc=inlanefreight,dc=local`.

![https://academy.hackthebox.com/storage/modules/74/dn_rdn2.png](https://academy.hackthebox.com/storage/modules/74/dn_rdn2.png)

## ⇒ **sAMAccountName**

The [sAMAccountName](https://docs.microsoft.com/en-us/windows/win32/ad/naming-properties#samaccountname) is the user's logon name. Here it would just be `bjones`. It must be a unique value and 20 or fewer characters.

## ⇒ **userPrincipalName**

The [userPrincipalName](https://social.technet.microsoft.com/wiki/contents/articles/52250.active-directory-user-principal-name.aspx) attribute is another way to identify users in AD. This attribute consists of a prefix (the user account name) and a suffix (the domain name) in the format of `bjones@inlanefreight.local`. This attribute is not mandatory.

## ⇒ **FSMO Roles**

In the early days of AD, if you had multiple DCs in an environment, they would fight over which DC gets to make changes, and sometimes changes would not be made properly. Microsoft then implemented "last writer wins," which could introduce its own problems if the last change breaks things. They then introduced a model in which a single "master" DC could apply changes to the domain while the others merely fulfilled authentication requests. This was a flawed design because if the master DC went down, no changes could be made to the environment until it was restored. To resolve this single point of failure model, Microsoft separated the various responsibilities that a DC can have into [Flexible Single Master Operation (FSMO)](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles) roles. These give Domain Controllers (DC) the ability to continue authenticating users and granting permissions without interruption (authorization and authentication). There are five FMSO roles: `Schema Master` and `Domain Naming Master` (one of each per forest), `Relative ID (RID) Master` (one per domain), `Primary Domain Controller (PDC) Emulator` (one per domain), and `Infrastructure Master` (one per domain). All five roles are assigned to the first DC in the forest root domain in a new AD forest. Each time a new domain is added to a forest, only the RID Master, PDC Emulator, and Infrastructure Master roles are assigned to the new domain. FSMO roles are typically set when domain controllers are created, but sysadmins can transfer these roles if needed. These roles help replication in AD to run smoothly and ensure that critical services are operating correctly. We will walk through each of these roles in detail later in this section.

| Roles | Description |
| --- | --- |
| Schema Master | This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD. |
| Domain Naming Master | Manages domain names and ensures that two domains of the same name are not created in the same forest. |
| Relative ID (RID) Master | The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID. |
| PDC Emulator | Primary Domain Controller →  this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain. |
| Infrastructure Master | This role translates GUIDs, SIDs, and DNs between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names. |

## ⇒ **Global Catalog**

A [global catalog (GC)](https://docs.microsoft.com/en-us/windows/win32/ad/global-catalog) is a domain controller that stores copies of ALL objects in an Active Directory forest. The GC stores a full copy of all objects in the current domain and a partial copy of objects that belong to other domains in the forest. Standard domain controllers hold a complete replica of objects belonging to its domain but not those of different domains in the forest. The GC allows both users and applications to find information about any objects in ANY domain in the forest. GC is a feature that is enabled on a domain controller and performs the following functions:

- Authentication (provided authorization for all groups that a user account belongs to, which is included when an access token is generated)
- Object search (making the directory structure within a forest transparent, allowing a search to be carried out across all domains in a forest by providing just one attribute about an object.)

## ⇒ Domain Controllers

A domain controller is a Windows server that has Active Directory Domain Services (AD DS) installed and has been promoted to a domain controller in the forest. Domain controllers are the center of Active Directory -- they control the rest of the domain. I will outline the tasks of a domain controller below:

- holds the AD DS data store
- handles authentication and authorization services
- replicate updates from other domain controllers in the forest
- Allows admin access to manage domain resources

## ⇒ **Read-Only Domain Controller (RODC)**

A [Read-Only Domain Controller (RODC)](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema) has a read-only Active Directory database. No AD account passwords are cached on an RODC (other than the RODC computer account & RODC KRBTGT passwords. No changes are pushed out via an RODC's AD database, SYSVOL, or DNS. RODCs also include a read-only DNS server, allow for administrator role separation, reduce replication traffic in the environment, and prevent SYSVOL modifications from being replicated to other DCs.

## ⇒ **Service Principal Name (SPN)**

A [Service Principal Name (SPN)](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names) uniquely identifies a service instance. They are used by Kerberos authentication to associate an instance of a service with a logon account, allowing a client application to request the service to authenticate an account without needing to know the account name.

## ⇒ **Group Policy Object (GPO)**

[Group Policy Objects (GPOs)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) are virtual collections of policy settings. Each GPO has a unique GUID. A GPO can contain local file system settings or Active Directory settings. GPO settings can be applied to both user and computer objects. They can be applied to all users and computers within the domain or defined more granularly at the OU level.

[**Group Policy Security Settings**](https://www.notion.so/Group-Policy-Security-Settings-532dbbddcb2840a2894559bb071e8dcf?pvs=21) 

## ⇒ ACL & ACEs

- **ACE: Access Control Entry**
- **ACL: Access Control List**

![Untitled](../Network%20Penetration%20Testing%207bc0c24ad8fe484d8df2696d10985222/Windows%20Security%20Basics%20a3be49509de34546b4bd04074f780f95/Untitled%202.png)

- ACL is a list of ACE — a list of everyone who has access to this file
- You can’t spoof the  SID because Windows use [access tokens](https://www.notion.so/Windows-Security-Basics-a3be49509de34546b4bd04074f780f95?pvs=21)
- An ACL can be one of two specific varieties: a Discretionary Access Control List (DACL) or a System Access Control List (SACL). **The DACL is primarily used for controlling access to an object, whereas a SACL is primarily used for logging access attempts to an object**.

### → **Discretionary Access Control List (DACL)**

DACLs define which security principles are granted or denied access to an object; it contain a list of ACEs. When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether or not to grant access. **If an object does NOT have a DACL, then the system will grant full access to everyone**, **but if the DACL has no ACE entries, the system will deny all access attempts**. ACEs in the DACL are checked in sequence until a match is found that allows the requested rights or until access is denied.

### → **System Access Control Lists (SACL)**

Allows for administrators to log access attempts that are made to secured objects. ACEs specify the types of access attempts that cause the system to generate a record in the security event log.

## ⇒ **Replication**

[Replication](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/replication/active-directory-replication-concepts) happens in AD when AD objects are updated and transferred from one Domain Controller to another. Whenever a DC is added, connection objects are created to manage replication between them. These connections are made by the Knowledge Consistency Checker (KCC) service, which is present on all DCs. Replication ensures that changes are synchronized with all other DCs in a forest, helping to create a backup in case one domain controller fails.

## ⇒ **Fully Qualified Domain Name (FQDN)**

An FQDN is the complete name for a specific computer or host. It is written with the hostname and domain name in the format [host name].[domain name].[tld]. This is used to specify an object's location in the tree hierarchy of DNS. The FQDN can be used to locate hosts in an Active Directory without knowing the IP address, much like when browsing to a website such as google.com instead of typing in the associated IP address. An example would be the host `DC01` in the domain `INLANEFREIGHT.LOCAL`. The FQDN here would be `DC01.INLANEFREIGHT.LOCAL`.

## ⇒ **Tombstone**

A [tombstone](https://ldapwiki.com/wiki/Tombstone) is a container object in AD that holds deleted AD objects. When an object is deleted from AD, the object remains for a set period known as the `Tombstone Lifetime,` and the `isDeleted` attribute is set to `TRUE`. Once an object exceeds the `Tombstone Lifetime`, it will be entirely removed. Microsoft recommends a tombstone lifetime of 180 days to increase the usefulness of backups, but this value may differ across environments. Depending on the DC operating system version, this value will default to 60 or 180 days. If an object is deleted in a domain that does not have an AD Recycle Bin, it will become a tombstone object. When this happens, the object is stripped of most of its attributes and placed in the `Deleted Objects` container for the duration of the `tombstoneLifetime`. **It can be recovered, but any attributes that were lost can no longer be recovered.**

## ⇒ **AD Recycle Bin**

The [AD Recycle Bin](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/the-ad-recycle-bin-understanding-implementing-best-practices-and/ba-p/396944) was first introduced in Windows Server 2008 R2 to facilitate the recovery of deleted AD objects. This made it easier for sysadmins to restore objects, avoiding the need to restore from backups, restarting Active Directory Domain Services (AD DS), or rebooting a Domain Controller. When the AD Recycle Bin is enabled, any deleted objects are preserved for a period of time, facilitating restoration if needed. Sysadmins can set how long an object remains in a deleted, recoverable state. If this is not specified, the object will be restorable for a default value of 60 days. **The biggest advantage of using the AD Recycle Bin is that most of a deleted object's attributes are preserved**, which makes it far easier to fully restore a deleted object to its previous state.

## ⇒ **SYSVOL**

The [SYSVOL](https://social.technet.microsoft.com/wiki/contents/articles/8548.active-directory-sysvol-and-netlogon.aspx) folder, or share, stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts that are executed to perform various tasks in the AD environment. **The contents of the SYSVOL folder are replicated to all DCs within the environment using File Replication Services (FRS)**. You can read more about the SYSVOL structure [here](http://www.techiebird.com/Sysvol_structure.html).

## ⇒ **AdminSDHolder**

The [AdminSDHolder](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) (Admin Security Descriptor Holder)object is used to manage ACLs for members of built-in groups in AD marked as privileged. It acts as a container that holds the Security Descriptor applied to members of protected groups. The SDProp (SD Propagator) process runs on a schedule on the PDC Emulator Domain Controller. When this process runs, it checks members of protected groups to ensure that the correct ACL is applied to them. It runs every hour by default. For example, suppose an attacker is able to create a malicious ACL entry to grant a user certain rights over a member of the Domain Admins group. In that case, unless they modify other settings in AD, these rights will be removed (and they will lose any persistence they were hoping to achieve) when the SDProp process runs on the set interval.

## ⇒ SDProp

SDProp short for Security Descriptor Propagation, is a process that runs on domain controllers in Windows Active Directory. It is responsible for enforcing the permissions defined in the AdminSDHolder container on all objects that are members of built-in administrative groups.

## ⇒ **dsHeuristics**

The [dsHeuristics](https://docs.microsoft.com/en-us/windows/win32/adschema/a-dsheuristics) attribute is a string value set on the Directory Service object used to define multiple forest-wide configuration settings. One of these settings is to exclude built-in groups from the [Protected Groups](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory) list. Groups in this list are protected from modification via the `AdminSDHolder` object. If a group is excluded via the `dsHeuristics` attribute, then any changes that affect it will not be reverted when the SDProp process runs.

## ⇒ **adminCount**

The [adminCount](https://docs.microsoft.com/en-us/windows/win32/adschema/a-admincount) attribute determines whether or not the SDProp process protects a user. If the value is set to `0` or not specified, the user is not protected. If the attribute value is set to `value`, the user is protected. Attackers will often look for accounts with the `adminCount` attribute set to `1` to target in an internal environment. These are often privileged accounts and may lead to further access or full domain compromise.

When the **`adminCount`** attribute is set to **`0`**, it means that the SDProp process will apply the default security descriptor to the object, which includes the object's Access Control List (ACL). This is the normal behavior for most objects in Active Directory.attribute is set to **`1`** to indicate that they are a privileged user.

## ⇒ **Active Directory Users and Computers (ADUC)**

ADUC is a GUI console commonly used for managing users, groups, computers, and contacts in AD. Changes made in ADUC can be done via PowerShell as well.

## ⇒ **ADSI Edit**

ADSI Edit is a GUI tool used to manage objects in AD. It provides access to far more than is available in ADUC and can be used to set or delete any attribute available on an object, add, remove, and move objects as well. It is a powerful tool that allows a user to access AD at a much deeper level. Great care should be taken when using this tool, as changes here could cause major problems in AD.

## ⇒ **sIDHistory**

[This](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute) attribute holds any SIDs that an object was assigned previously. It is usually used in migrations so a user can maintain the same level of access when migrated from one domain to another. This attribute can potentially be abused if set insecurely, allowing an attacker to gain prior elevated access that an account had before a migration if SID Filtering (or removing SIDs from another domain from a user's access token that could be used for elevated access) is not enabled.

## ⇒ NTDS.DIT

The NTDS.DIT file can be considered the heart of Active Directory. It is stored on a Domain Controller at `%systemroot%\NTDS` means`C:\Windows\NTDS\` on the domain controllers in a [forest](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/using-the-organizational-domain-forest-model). The `.dit` stands for [directory information tree](https://docs.oracle.com/cd/E19901-01/817-7607/dit.html).
 is enabled, then the NTDS.DIT will also store the clear-text passwords for all users created or who changed their password after this policy was set. While rare, some organizations may enable this setting if they use applications or protocols that need to use a user's existing password (and not Kerberos) for authentication.

It is very common to come across network environments where Windows systems are joined to a Windows domain. This is common because it makes it easier for admins to manage all the systems owned by their respective organizations (centralized management). In these cases, the Windows systems will send all login requests to Domain Controllers that belong to the same Active Directory forest. Each Domain Controller hosts a file called `NTDS.dit` that is kept synchronized across all Domain Controllers with the exception of [Read-Only Domain Controllers](https://docs.microsoft.com/en-us/windows/win32/ad/rodc-and-active-directory-schema). NTDS.dit is a database file that stores the data in Active Directory, including but not limited to:

- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects

We will practice methods that allow us to extract credentials from the NTDS.dit file later in this module.

Now that we have gone through a primer on credential storage concepts, let's study the various attacks we can perform to extract credentials to further our access during assessments.

## ⇒ **MSBROWSE**

MSBROWSE is a Microsoft networking protocol that was used in early versions of Windows-based local area networks (LANs) to provide browsing services. It was used to maintain a list of resources, such as shared printers and files, that were available on the network, and to allow users to easily browse and access these resources.

In older version of Windows we could use `nbtstat -A ip-address` to search for the Master Browser. If we see MSBROWSE it means that's the Master Browser. Aditionally we could use `nltest` utility to query a Windows Master Browser for the names of the Domain Controllers.

Today, MSBROWSE is largely obsolete and is no longer in widespread use. Modern Windows-based LANs use the Server Message Block (SMB) protocol for file and printer sharing, and the Common Internet File System (CIFS) protocol for browsing services.

## ⇒ [**Trusts**](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b.md)

## ⇒ Policies

Policies are a very big part of Active Directory, they dictate how the server operates and what rules it will and will not follow. You can think of domain policies like domain groups, except instead of permissions they contain rules, and instead of only applying to a group of users, the policies apply to a domain as a wh ole. They simply act as a rulebook for Active  Directory that a domain admin can modify and alter as they deem necessary to keep the network running smoothly and securely. Along with the very long list of default domain policies, domain admins can choose to add in their own policies not already on the domain controller, for example: if you wanted to disable windows defender across all machines on the domain you could create a new group policy object to disable Windows Defender. The options for domain policies are almost endless and are a big factor for attackers when enumerating an Active Directory network. I'll outline just a few of the  many policies that are default or you can create in an Active Directory environment:

- Disable Windows Defender - Disables windows defender across all machine on the domain
- Digitally Sign Communication (Always) - Can disable or enable SMB signing on the domain controller

---

# Active Directory Objects

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%203.png)

## ⇒ **Users**

These are the users within the organization's AD environment. Users are considered `leaf objects`, which means that they cannot contain any other objects within them. Another example of a leaf object is a mailbox in Microsoft Exchange. A user object is considered a security principal and has a security identifier (SID) and a global unique identifier (GUID). User objects have many possible [attributes](http://www.kouti.com/tables/userattributes.htm), such as their display name, last login time, date of last password change, email address, account description, manager, address, and more. Depending on how a particular Active Directory environment is set up, there can be over 800 possible user attributes when accounting for ALL possible attributes as detailed [here](https://www.easy365manager.com/how-to-get-all-active-directory-user-object-attributes/). This example goes far beyond what is typically populated for a standard user in most environments but shows Active Directory's sheer size and complexity. They are a crucial target for attackers since gaining access to even a low privileged user can grant access to many objects and resources and allow for detailed enumeration of the entire domain (or forest).

Users are one of the objects known as **security principals,** meaning that they can be authenticated by the domain and can be assigned privileges over **resources** like files or printers. You could say that a security principal is an object that can act upon resources in the network.

Users are the core of Active Directory; without users why have Active Directory in the first place? There are four main types of users you'll find in an Active Directory network; however, there can be more depending on how a company manages the permissions of its users. The four types of users are:

- Domain Admins - This is the big boss: they control the domains and are the only ones with access to the domain controller.
- Service Accounts (Can be Domain Admins) - These are for the most part never used except for service maintenance, they are required by Windows for services such as SQL to pair service with a service account
- Local Administrators - These users can make changes to local machines as an administrator and may even be able to control other normal users, but they cannot access the domain controller
- Domain Users - These are your everyday users. They can log in on the machines they have the authorization to access and may have local administrator rights to machines depending on the organization.

## ⇒ **Contacts**

A contact object is usually used to represent an external user and contains informational attributes such as first name, last name, email address, telephone number, etc. They are `leaf objects` and are NOT security principals (securable objects), so they don't have a SID, only a GUID. An example would be a contact card for a third-party vendor or a customer.

## ⇒ **Printers**

A printer object points to a printer accessible within the AD network. Like a contact, a printer is a `leaf object` and **not a security principal**, so it only has a GUID. Printers have attributes such as the printer's name, driver information, port number, etc.

## ⇒ **Computers**

A computer object is any computer joined to the AD network (workstation or server). Computers are `leaf objects` because they do not contain other objects. However, they are considered security principals and have a SID and a GUID. Like users, they are prime targets for attackers since full administrative access to a computer (as the all-powerful `NT AUTHORITY\SYSTEM` account) grants similar rights to a standard domain user and can be used to perform the majority of the enumeration tasks that a user account can (save for a few exceptions across domain trusts.)

By default, all the machines that join a domain (except for the DCs) will be put in the container called "Computers".

The machine accounts themselves are local administrators on the assigned computer, they are generally not supposed to be accessed by anyone except the computer itself, but as with any other account, if you have the password, you can use it to log in.

Machine Account passwords are automatically rotated out (default: every 30 Days) and are generally comprised of 120 random characters, and the generated password is complex so it’s not easy to brute force it. Identifying machine accounts is relatively easy. They follow a specific naming scheme. The machine account name is the computer's name followed by a dollar sign. For example, a machine named `DC01` will have a machine account called `DC01$`.

## ⇒ **Shared Folders**

A shared folder object points to a shared folder on the specific computer where the folder resides. Shared folders can have stringent access control applied to them and can be either accessible to everyone (even those without a valid AD account), open to only authenticated users (which means anyone with even the lowest privileged user account OR a computer account (`NT AUTHORITY\SYSTEM`) could access it), or be locked down to only allow certain users/groups access. Anyone not explicitly allowed access will be denied from listing or reading its contents. Shared folders are NOT security principles and only have a GUID. A shared folder's attributes can include the name, location on the system, security access rights.

## ⇒ **Groups**

A group is considered a `container object` because it can contain other objects, including users, computers, and even other groups. A group IS regarded as a security principal and has a SID and a GUID. In AD, groups are a way to manage user permissions and access to other securable objects (both users and computers). Let's say we want to give 20 help desk users access to the Remote Management Users group on a jump host. Instead of adding the users one by one, we could add the group, and the users would inherit the intended permissions via their membership in the group. In Active Directory, we commonly see what are called "[nested groups](https://docs.microsoft.com/en-us/windows/win32/ad/nesting-a-group-in-another-group)" (a group added as a member of another group), which can lead to a user(s) obtaining unintended rights. Nested group membership is something we see and often leverage during penetration tests. The tool [BloodHound](https://github.com/BloodHoundAD/BloodHound) helps to discover attack paths within a network and illustrate them in a graphical interface. It is excellent for auditing group membership and uncovering/seeing the sometimes unintended impacts of nested group membership. Groups in AD can have many [attributes](http://www.selfadsi.org/group-attributes.htm), the most common being the name, description, membership, and other groups that the group belongs to. Many other attributes can be set, which we will discuss more in-depth later in this module.

There are two overarching types of Active Directory groups:

- Security Groups - These groups are used to specify permissions for a large number of users
- Distribution Groups - These groups are used to specify email distribution lists. As an attacker, these groups are less beneficial to us but can still be beneficial in enumeration

### → Default Security Groups

There are a lot of default security groups so I won't be going into too much detail of each past a brief description of the permissions that they offer to the assigned group. Here is a brief outline of the security groups:

- Domain Controllers - All domain controllers in the domain
- Domain Guests - All domain guests
- Domain Users - All domain users
- Domain Computers - All workstations and servers joined to the domain
- Domain Admins - Designated administrators of the domain
- Enterprise Admins - Designated administrators of the enterprise
- Schema Admins - Designated administrators of the schema
- DNS Admins - DNS Administrators Group
- DNS Update Proxy - DNS clients who are permitted to perform dynamic updates on behalf of some other clients (such as DHCP servers).
- **Allowed RODC Password Replication Group** - Members in this group can have their passwords replicated to all read-only domain controllers in the domain
- Group Policy Creator Owners - Members in this group can modify group policy for the domain
- Denied RODC Password Replication Group - Members in this group cannot have their passwords are replicated to any read-only domain controllers in the domain
- Protected Users - Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
- Cert Publishers - Members of this group are permitted to publish certificates to the directory
- Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the domain
- Enterprise Read-Only Domain Controllers - Members of this group are Read-Only Domain Controllers in the enterprise
- Key Admins - Members of this group can perform administrative actions on key objects within the domain.
- Enterprise Key Admins - Members of this group can perform administrative actions on key objects within the forest.
- Cloneable Domain Controllers - Members of this group that are domain controllers may be cloned.
- RAS and IAS Servers - Servers in this group can access remote access properties of users
- Server Operators This group only exists on domain controllers. Members can modify services, access SMB shares, and backup files on domain controllers. By default, this group has no members.

### → Security Groups vs OUs

- **OUs** are handy for **applying policies** to users and computers, which include specific configurations that pertain to sets of users depending on their particular role in the enterprise. Remember, **a user can only be a member of a single OU at a time, as it wouldn't make sense to try to apply two different sets of policies to a single user.**
- **Security Groups**, on the other hand, are used to **grant permissions over resources**. For example, you will use groups if you want to allow some users to access a shared folder or network printer. A user can be a part of many groups, which is needed to grant access to multiple resources.

## ⇒ **Organizational Units (OUs)**

An organizational unit, or OU from here on out, is a container that systems administrators can use to store similar objects for ease of administration. OUs are often used for administrative delegation of tasks without granting a user account full administrative rights. For example, we may have a top-level OU called Employees and then child OUs under it for the various departments such as Marketing, HR, Finance, Help Desk, etc. If an account were given the right to reset passwords over the top-level OU, this user would have the right to reset passwords for all users in the company. However, if the OU structure were such that specific departments were child OUs of the Help Desk OU, then any user placed in the Help Desk OU would have this right delegated to them if granted. Other tasks that may be delegated at the OU level include creating/deleting users, modifying group membership, managing Group Policy links, and performing password resets. OUs are very useful for managing Group Policy (**LINK ME**) settings across a subset of users and groups within a domain. For example, we may want to set a specific password policy for privileged service accounts so these accounts could be placed in a particular OU and then have a Group Policy object assigned to it, which would enforce this password policy on all accounts placed inside of it. A few OU attributes include its name, members, security settings, and more.

**a user can only be a member of a single OU at a time, as it wouldn't make sense to try to apply two different sets of policies to a single user.**

## ⇒ **Domain**

A domain is the structure of an AD network. Domains contain objects such as users and computers, which are organized into container objects: groups and OUs. Every domain has its own separate database and sets of policies that can be applied to any and all objects within the domain. Some policies are set by default (and can be tweaked), such as the domain password policy. In contrast, others are created and applied based on the organization's need, such as blocking access to cmd.exe for all non-administrative users or mapping shared drives at log in.

## ⇒ **Domain Controllers**

Domain Controllers are essentially the brains of an AD network. They handle authentication requests, verify users on the network, and control who can access the various resources in the domain. All access requests are validated via the domain controller and privileged access requests are based on predetermined roles assigned to users. It also enforces security policies and stores information about every other object in the domain.

## ⇒ **Sites**

A site in AD is a set of computers across one or more subnets connected using high-speed links. They are used to make replication across domain controllers run efficiently.

## ⇒ **Built-in**

In AD, built-in is a container that holds [default groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups) in an AD domain. They are predefined when an AD domain is created.

## ⇒ **Foreign Security Principals**

A foreign security principal (FSP) is an object created in AD to represent a security principal that belongs to a trusted external forest. They are created when an object such as a user, group, or computer from an external (outside of the current) forest is added to a group in the current domain. They are created automatically after adding a security principal to a group. Every foreign security principal is a placeholder object that holds the SID of the foreign object (an object that belongs to another forest.) Windows uses this SID to resolve the object's name via the trust relationship. FSPs are created in a specific container named ForeignSecurityPrincipals with a distinguished name like `cn=ForeignSecurityPrincipals,dc=inlanefreight,dc=local`.

---

# Active Directory Functionality

As mentioned before, there are five Flexible Single Master Operation (FSMO) roles. These roles can be defined as follows:

Depending on the organization, these roles may be assigned to specific DCs or as defaults each time a new DC is added. Issues with FSMO roles will lead to authentication and authorization difficulties within a domain.

---

# **Domain and Forest Functional Levels**

Microsoft introduced functional levels to determine the various features and capabilities available in Active Directory Domain Services (AD DS) at the domain and forest level. They are also used to specify which Windows Server operating systems can run a Domain Controller in a domain or forest. [This](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918(v=ws.10)?redirectedfrom=MSDN) and [this](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels) article describe both the domain and forest functional levels from Windows 2000 native to Windows Server 2012 R2. Below is a quick overview of the differences in `domain functional levels` from Windows 2000 native up to Windows Server 2016, aside from all default Active Directory Directory Services features from the level just below it (or just the default AD DS features in the case of Windows 2000 native.)

| Domain Functional Level | Features Available | Supported Domain Controller Operating Systems |
| --- | --- | --- |
| Windows 2000 native | Universal groups for distribution and security groups, group nesting, group conversion (between security and distribution and security groups), SID history. | Windows Server 2008 R2, Windows Server 2008, Windows Server 2003, Windows 2000 |
| Windows Server 2003 | Netdom.exe domain management tool, lastLogonTimestamp attribute introduced, well-known users and computers containers, constrained delegation, selective authentication. | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008, Windows Server 2003 |
| Windows Server 2008 | Distributed File System (DFS) replication support, Advanced Encryption Standard (AES 128 and AES 256) support for the Kerberos protocol, Fine-grained password policies | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2, Windows Server 2008 |
| Windows Server 2008 R2 | Authentication mechanism assurance, Managed Service Accounts | Windows Server 2012 R2, Windows Server 2012, Windows Server 2008 R2 |
| Windows Server 2012 | KDC support for claims, compound authentication, and Kerberos armoring | Windows Server 2012 R2, Windows Server 2012 |
| Windows Server 2012 R2 | Extra protections for members of the Protected Users group, Authentication Policies, Authentication Policy Silos | Windows Server 2012 R2 |
| Windows Server 2016 | https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-require-smart-card new https://docs.microsoft.com/en-us/windows-server/security/kerberos/whats-new-in-kerberos-authentication features and new https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/whats-new-in-credential-protection features | Windows Server 2019 and Windows Server 2016 |

A new functional level was not added with the release of Windows Server 2019. However, Windows Server 2008 functional level is the minimum requirement for adding Server 2019 Domain Controllers to an environment. Also, the target domain has to use [DFS-R](https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview) for SYSVOL replication.

Forest functional levels have introduced a few key capabilities over the years:

| Version | Capabilities |
| --- | --- |
| Windows Server 2003 | saw the introduction of the forest trust, domain renaming, read-only domain controllers (RODC), and more. |
| Windows Server 2008 | All new domains added to the forest default to the Server 2008 domain functional level. No additional new features. |
| Windows Server 2008 R2 | Active Directory Recycle Bin provides the ability to restore deleted objects when AD DS is running. |
| Windows Server 2012 | All new domains added to the forest default to the Server 2012 domain functional level. No additional new features. |
| Windows Server 2012 R2 | All new domains added to the forest default to the Server 2012 R2 domain functional level. No additional new features. |
| Windows Server 2016 | https://docs.microsoft.com/en-us/windows-server/identity/whats-new-active-directory-domain-services#privileged-access-management |

---

# **Trusts**

A trust is used to establish `forest-forest` or `domain-domain` authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in. A trust creates a link between the authentication systems of two domains.

There are several trust types.

| Trust Type | Description |
| --- | --- |
| Parent-child | Domains within the same forest. The child domain has a two-way transitive trust with the parent domain. |
| Cross-link | a trust between child domains to speed up authentication. |
| External | A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering. |
| Tree-root | a two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest. |
| Forest | a transitive trust between two forest root domains. |

## ⇒ **Trust Example**

![https://academy.hackthebox.com/storage/modules/74/trusts-diagram.png](https://academy.hackthebox.com/storage/modules/74/trusts-diagram.png)

Trusts can be transitive or non-transitive.

- A transitive trust means that trust is extended to objects that the child domain trusts.
- In a non-transitive trust, only the child domain itself is trusted.

Trusts can be set up to be one-way or two-way (bidirectional).

- In bidirectional trusts, users from both trusting domains can access resources.
- In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.

Often, domain trusts are set up improperly and provide unintended attack paths. Also, trusts set up for ease of use may not be reviewed later for potential security implications. Mergers and acquisitions can result in bidirectional trusts with acquired companies, unknowingly introducing risk into the acquiring company’s environment. It is not uncommon to be able to perform an attack such as Kerberoasting against a domain outside the principal domain and obtain a user that has administrative access within the principal domain.

The graphic below shows two forests, `INLANEFREIGHT.LOCAL` and `FREIGHTLOGISTICS.LOCAL`. The two-way arrow represents a bidirectional trust between the two forests, meaning that users in `INLANEFREIGHT.LOCAL` can access resources in `FREIGHTLOGISTICS.LOCAL` and vice versa. We can also see multiple child domains under each root domain. In this example, we can see that the root domain trusts each of the child domains, but the child domains in forest A do not necessarily have trusts established with the child domains in forest B. This means that a user that is part of `admin.dev.freightlogistics.local` would NOT be able to authenticate to machines in the `wh.corp.inlanefreight.local` domain by default even though a bidirectional trust exists between the top-level `inlanefreight.local` and `freightlogistics.local` domains. To allow direct communication from `admin.dev.freightlogistics.local` and `wh.corp.inlanefreight.local`, another trust would need to be set up.

![https://academy.hackthebox.com/storage/modules/74/ilflog2.png](https://academy.hackthebox.com/storage/modules/74/ilflog2.png)

---

## ⇒ Domain Services

### →Domain Services Overview

Domain Services are exactly what they sound like. They are services that the domain controller provides to the rest of the domain or tree. There is a wide range of various services that can be added to a domain controller; however, in this room we'll only be going over the default services that come when you set up a Windows server as a domain controller. Outlined below are the default domain services:

- LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
- Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
- DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames

### → Domain Authentication Overview

The most important part of Active Directory -- as well as the most vulnerable part of Active Directory -- is the authentication protocols set in place. There are two main types of authentication in place for Active Directory: NTLM and Kerberos. Since these will be covered in more depth in later rooms we will not be covering past the very basics needed to understand how they apply to Active Directory as a whole. For more information on NTLM and Kerberos check out the Attacking Kerberos room - [https://tryhackme.com/room/attackingkerberos](https://tryhackme.com/room/attackingkerberos).

- Kerberos - The default authentication service for Active Directory uses ticket-granting tickets and service tickets to authenticate users and give users access to other resources across the domain.
- NTLM - default Windows authentication protocol uses an encrypted challenge/response protocol

The Active Directory domain services are the main access point for attackers and contain some of the most vulnerable protocols for Active Directory, this will not be the last time you see them mentioned in terms of Active Directory security.

- **All of these parts of Active Directory come together to make a big network of machines and servers. Now that we know what Active Directory is let's talk about the why?**
- **A forest is a collection of trees that share a common global catalog, directory schema, logical structure and directory configuration. But, a domain is a logical group of network objects (computers, users, devices) that share the same Active Directory database**

---

# **User Rights Assignment**

Depending on their current group membership, and other factors such as privileges that administrators can assign via Group Policy (GPO), users can have various rights assigned to their account. This Microsoft article on [User Rights Assignment](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment) provides a detailed explanation of each of the user rights that can be set in Windows. Not every right listed here is important to us from a security standpoint as penetration testers or defenders, but some rights granted to an account can lead to unintended consequences such as privilege escalation or access to sensitive files. For example, let's say we can gain write access over a Group Policy Object (GPO) applied to an OU containing one or more users that we control. In this example, we could potentially leverage a tool such as [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to assign targeted rights to a user. We may perform many actions in the domain to further our access with these new rights. A few examples include:

Se stands for Security Enabled

| Privilege | Description |
| --- | --- |
| SeRemoteInteractiveLogonRight | This privilege could give our target user the right to log onto a host via Remote Desktop (RDP), which could potentially be used to obtain sensitive data or escalate privileges. |
| SeBackupPrivilege | This grants a user the ability to create system backups and could be used to obtain copies of sensitive system files that can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file. |
| SeDebugPrivilege | This allows a user to debug and adjust the memory of a process. With this privilege, attackers could utilize a tool such as https://github.com/ParrotSec/mimikatz to read the memory space of the Local System Authority (LSASS) process and obtain any credentials stored in memory. |
| SeImpersonatePrivilege | This privilege allows us to impersonate a token of a privileged account such as NT AUTHORITY\SYSTEM. This could be leveraged with a tool such as JuicyPotato, RogueWinRM, PrintSpoofer, etc., to escalate privileges on a target system. |
| SeLoadDriverPrivilege | A user with this privilege can load and unload device drivers that could potentially be used to escalate privileges or compromise a system. |
| SeTakeOwnershipPrivilege | This allows a process to take ownership of an object. At its most basic level, we could use this privilege to gain access to a file share or a file on a share that was otherwise not accessible to us. |

There are many techniques available to abuse user rights detailed [here](https://blog.palantir.com/windows-privilege-abuse-auditing-detection-and-defense-3078a403d74e) and [here](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens). Though outside the scope of this module, it is essential to understand the impact that assigning the wrong privilege to an account can have within Active Directory. A small admin mistake can lead to a complete system or enterprise compromise.

---

# Active Directory Structure

- Active Directory is arranged in a hierarchical tree structure, with a forest at the top containing one or more domains

```
INLANEFREIGHT.LOCAL/
├── ADMIN.INLANEFREIGHT.LOCAL
│   ├── GPOs
│   └── OU
│       └── EMPLOYEES
│           ├── COMPUTERS
│           │   └── FILE01
│           ├── GROUPS
│           │   └── HQ Staff
│           └── USERS
│               └── barbara.jones
├── CORP.INLANEFREIGHT.LOCAL
└── DEV.INLANEFREIGHT.LOCAL
```

---

# Active Directory **DNS**

Active Directory Domain Services (AD DS) uses DNS to allow clients (workstations, servers, and other systems that communicate with the domain) to locate Domain Controllers and for Domain Controllers that host the directory service to communicate amongst themselves. DNS is used to resolve hostnames to IP addresses and is broadly used across internal networks and the internet. Private internal networks use Active Directory DNS namespaces to facilitate communications between servers, clients, and peers. AD maintains a database of services running on the network in the form of service records (SRV). These service records allow clients in an AD environment to locate services that they need, such as a file server, printer, or Domain Controller. Dynamic DNS is used to make changes in the DNS database automatically should a system's IP address change. Making these entries manually would be very time-consuming and leave room for error. If the DNS database does not have the correct IP address for a host, clients will not be able to locate and communicate with it on the network. When a client joins the network, it locates the Domain Controller by sending a query to the DNS service, retrieving an SRV record from the DNS database, and transmitting the Domain Controller's hostname to the client. The client then uses this hostname to obtain the IP address of the Domain Controller. **DNS uses TCP and UDP port 53. UDP port 53 is the default, but it falls back to TCP when no longer able to communicate and DNS messages are larger than 512 bytes.**

---

# Types of Active Directory

There are two types of Active Directory:

- On-Premise Active Directory (AD) (Inside the company)
- Azure Active Directory (AAD) (Cloud)

---

# Delegation

One of the nice things you can do in AD is to give specific users some control over some OUs. This process is known as **delegation** and allows you to grant users specific privileges to perform advanced tasks on OUs without needing a Domain Administrator to step in.

One of the most common use cases for this is granting `IT support` the privileges to reset other low-privilege users' passwords. According to our organisational chart, Phillip is in charge of IT support, so we'd probably want to delegate the control of resetting passwords over the Sales, Marketing and Management OUs to him.

For this example, we will delegate control over the Sales OU to Phillip. To delegate control over an OU, you can right-click it and select **Delegate Control**:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/74f8d615658a03aeb1cfdb6767d0a0a3.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/74f8d615658a03aeb1cfdb6767d0a0a3.png)

This should open a new window where you will first be asked for the users to whom you want to delegate control:

**Note:** To avoid mistyping the user's name, write "phillip" and click the **Check Names** button. Windows will autocomplete the user for you.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2814715e1dbadaef334973028e02da69.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2814715e1dbadaef334973028e02da69.png)

Click OK, and on the next step, select the following option:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/3f81df2b38e35ca5729aee7a76c6b220.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/3f81df2b38e35ca5729aee7a76c6b220.png)

Click next a couple of times, and now Phillip should be able to reset passwords for any user in the sales department. While you'd probably
want to repeat these steps to delegate the password resets of the Marketing and Management departments, we'll leave it here for this task. You are free to continue to configure the rest of the OUs if you so desire.

Now let's use Phillip's account to try and reset Sophie's password. Here are Phillip's credentials for you to log in via RDP

---

# Understanding the authentication process

- Authentication is a process for verifying the identity of a person (or an object or service). When you authenticate a person, the goal is to verify that the person is not an imposter.

## ⇒ Local Authentication

- Local authentication is done using the Local Security Authority (LSA). LSA is a protected subsystem that keeps track of the security policies and the accounts that are on a computer system. It also maintains information about all aspects of local security on a computer.
- **"LSA" is the concept, and "lsass.exe", a process that implements many of the functions of LSA**

## ⇒ Active Directory Authentication

- On-Premise AD ⇒ NTLM/NTLM2, LDAP, Kerberos
- Azure AD (Cloud) ⇒ SAML, OAuth, OpenID
- **so if you login into a local system without using AD you use LSASS, if you use AD to login you use on of these protocols On-premise AD → (NTLM, LDAP, KERBEROS)Azure AD → (SAML, OAUTH, OpenID)**

---

# On-Premise Active Directory Authentication Protocols

- **Hash Protocol Comparison**

| Hash/Protocol | Cryptographic technique | Mutual Authentication | Message Type | Trusted Third Party |
| --- | --- | --- | --- | --- |
| NTLM | Symmetric key cryptography | No | Random number | Domain Controller |
| NTLMv1 | Symmetric key cryptography | No | MD4 hash, random number | Domain Controller |
| NTLMv2 | Symmetric key cryptography | No | MD4 hash, random number | Domain Controller |
| Kerberos | Symmetric key cryptography & asymmetric cryptography | Yes | Encrypted ticket using DES, MD5 | Domain Controller,/Key Distribution Center (KDC) |

## ⇒ NTLM / NTLM 2

NTLM is a single sign-on (SSO) solution that uses a challenge-response protocol to verify the user's identity without having them provide a password. With NTLM, passwords stored on the server and domain controller are not "salted," which means that an adversary with a password hash can authenticate a session without knowing the original password. We call this a `Pass the Hash (PtH) Attack`. they are considerably stronger than LM hashes (supporting the entire Unicode character set of 65,536 characters), they can still be brute-forced offline relatively quickly using a tool such as Hashcat. GPU attacks have shown that the entire NTLM 8 character keyspace can be brute-forced in under `3 hours`. Longer NTLM hashes can be more challenging to crack depending on the password chosen, and even long passwords (15+ characters) can be cracked using an offline dictionary attack combined with rules. NTLM is also vulnerable to the pass-the-hash attack, which means an attacker can use just the NTLM hash (after obtaining via another successful attack) to authenticate to target systems where the user is a local admin without needing to know the clear-text value of the password.

An NT hash takes the form of `b4b9b02e6f09a9bd760f388b67351e2b`, which is the second half of the full NTLM hash. An NTLM hash looks like this:

```
Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::
```

Looking at the hash above, we can break the NTLM hash down into its individual parts:

- `Rachel` is the username
- `500` is the Relative Identifier (RID). 500 is the known RID for the `administrator` account
- `aad3c435b514a4eeaad3b935b51304fe` is the LM hash and, if LM hashes are disabled on the system, can not be used for anything
- `e46b9e548fa0d122de7f59fb6d48eaa2` is the NT hash. This hash can either be cracked offline to reveal the clear-text value (depending on the length/strength of the password) or used for a pass-the-hash attack.
- Users use NTLM authentication:
    - if they authenticate by IP address instead of using the hostname
    - if the hostname is not registered in the AD-integrated DNS server
    - third party applications

NTLM  provides authentication based on a **challenge-response authentication** scheme. It does **not provide data integrity or data confidentiality protection for the authenticated network connection**.

NetNTLM, also often referred to as Windows Authentication or just NTLM Authentication, allows the application to play the role of a middleman between the client and AD. All authentication material is forwarded to a Domain Controller in the form of a challenge, and if completed successfully, the application will authenticate the user.

This means that the application is authenticating on behalf of the user and not authenticating the user directly on the application itself. This prevents the application from storing AD credentials, which should only be stored on a Domain Controller. This process is shown in the diagram below:

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%204.png)

![https://i.imgur.com/z7VT6PM.png](https://i.imgur.com/z7VT6PM.png)

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%205.png)

1. The client sends an authentication request to the server they want to access.
2. The server generates a random number and sends it as a challenge to the client.
3. The client combines his NTLM password hash with the challenge (and other known data) to generate a response to the challenge and sends it back to the server for verification.
4. The server forwards both the challenge and the response to the Domain Controller for verification.
5. The domain controller uses the challenge to recalculate the response and compares it to the initial response sent by the client. If they both match, the client is authenticated; otherwise, access is denied.The authentication result is sent back to the server.
6. The server forwards the authentication result to the client.

---

## ⇒ LDAP / LDAPS

Active Directory supports [Lightweight Directory Access Protocol (LDAP)](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) for directory lookups. LDAP is an open-source and cross-platform protocol used for authentication against various directory services (such as AD). The latest LDAP specification is [Version 3](https://tools.ietf.org/html/rfc4511), published as RFC 4511. A firm understanding of how LDAP works in an AD environment is crucial for attackers and defenders. LDAP uses port 389, and LDAP over SSL (LDAPS) communicates over port 636.

AD stores user account information and security information such as passwords and facilitates sharing this information with other devices on the network. LDAP is the language that applications use to communicate with other servers that provide directory services. In other words, LDAP is how systems in the network environment can "speak" to AD.

An LDAP session begins by first connecting to an LDAP server, also known as a Directory System Agent. The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests.

![https://academy.hackthebox.com/storage/modules/74/LDAP_auth.png](https://academy.hackthebox.com/storage/modules/74/LDAP_auth.png)

The relationship between AD and LDAP can be compared to Apache and HTTP. The same way Apache is a web server that uses the HTTP protocol, **Active Directory is a directory server that uses the LDAP protocol.**

While uncommon, you may come across organization while performing an assessment that do not have AD but are using LDAP, meaning that they most likely use another type of LDAP server such as [OpenLDAP](https://en.wikipedia.org/wiki/OpenLDAP).

The main difference between LDAP and LDAPS is that LDAPS supports encryption and therefore the credentials are not sent in plain text across the network.

Another thing to keep in mind is that the Domain Controller (DC) can be considered a database of users, groups, computers, and so on (contains information about objects). Using LDAP/LDAPS the user's workstation sends the credentials using an **API** to the Domain Controller in order to validate them and be able to log in.

The procedure is similar to the image below:

![https://i.imgur.com/Vep5s0C.png](https://i.imgur.com/Vep5s0C.png)

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%206.png)

LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session. There are two types of LDAP authentication.

1. `Simple Authentication`: This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a `username` and `password` create a BIND request to authenticate to the LDAP server.
2. `SASL Authentication`: [The Simple Authentication and Security Layer (SASL)](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer) framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP. The LDAP server uses the LDAP protocol to send an LDAP message to the authorization service, which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication. SASL can provide additional security due to the separation of authentication methods from application protocols.

LDAP authentication messages are sent in clear-text by default so anyone can sniff out LDAP messages on the internal network. It is recommended to use TLS encryption or similar to safeguard this information in transit.

---

## ⇒ **MSRPC**

As mentioned above, MSRPC is Microsoft's implementation of Remote Procedure Call (RPC), an interprocess communication technique used for client-server model-based applications. Windows systems use MSRPC to access systems in Active Directory using four key RPC interfaces.

| Interface Name | Description |
| --- | --- |
| lsarpc | A set of RPC calls to the https://networkencyclopedia.com/local-security-authority-lsa/ system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies. |
| netlogon | Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background. |
| samr | Remote SAM (samr) provides management functionality for the domain account database, storing information about users and groups. IT administrators use the protocol to manage users, groups, and computers by enabling admins to create, read, update, and delete information about security principles. Attackers (and pentesters) can use the samr protocol to perform reconnaissance about the internal domain using tools such as https://github.com/BloodHoundAD/ to visually map out the AD network and create "attack paths" to illustrate visually how administrative access or full domain compromise could be achieved. Organizations can https://stealthbits.com/blog/making-internal-reconnaissance-harder-using-netcease-and-samri1o/ against this type of reconnaissance by changing a Windows registry key to only allow administrators to perform remote SAM queries since, by default, all authenticated domain users can make these queries to gather a considerable amount of information about the AD domain. |
| drsuapi | drsuapi is the Microsoft API that implements the Directory Replication Service (DRS) Remote Protocol which is used to perform replication-related tasks across Domain Controllers in a multi-DC environment. Attackers can utilize drsuapi to https://attack.mitre.org/techniques/T1003/003/ (NTDS.dit) file to retrieve password hashes for all accounts in the domain, which can then be used to perform Pass-the-Hash attacks to access more systems or cracked offline using a tool such as Hashcat to obtain the cleartext password to log in to systems using remote management protocols such as Remote Desktop (RDP) and WinRM. |

---

## Kerberos → 88 TCP/UDP

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%207.png)

- **Kerberos uses symmetric-key cryptography and requires trusted third-party authorization to verify user identities. The authentication process is similar to the one below:**
- Hint: AS-REQ (username + hashed_password) == **Pre-Authentication |** AS-REQ(username) == no pre-authentication required

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%208.png)

- **limbo photos (Simple)**
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%209.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2010.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2011.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2012.png)
    
- **limbo photos (Detailed)**
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2013.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2014.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2015.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2016.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2017.png)
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2018.png)
    

![https://i.imgur.com/nnsV5NM.png](https://i.imgur.com/nnsV5NM.png)

- hashes type in Kerberos  is NTLM hash
- Kerberos Authenticate you, but the service you request TGS for will authorize you
- SPN: Service Principle Name
- use SPN → Kerberos | use IP → NTLM  Authentication

### Components (Three)

1. KDC: Key Distribution Center (port TCP/88, UDP/88) (has all the user names, krbtgt  and services, and its hashes )
2.  AS: Authentication Service
3. TGS: Ticket Granting Service

### **Common Terminology**

- **Ticket Granting Ticket (TGT)** - A ticket-granting ticket is an authentication ticket used to request service tickets from the TGS for specific resources from the domain.
- **Key Distribution Center (KDC)** - The Key Distribution Center is a service for issuing TGTs and service tickets that consist of the Authentication Service and the Ticket Granting Service.
- **Authentication Service (AS)** - The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- **Ticket Granting Service (TGS)** - The Ticket Granting Service takes the TGT and returns a ticket to a machine on the domain.
- **Service Principal Name (SPN)** - A Service Principal Name is an identifier given to a service instance to associate a service instance with a domain service account. Windows requires that services have a domain service account which is why a service needs an SPN set.
- **KDC Long Term Secret Key (KDC LT Key)** The KDC key is based on the KRBTGT service account. It is used to encrypt the TGT and sign the PAC.
- **Client Long Term Secret Key (Client LT Key)**  The client key is based on the computer or service account. It is used to check the encrypted timestamp and encrypt the session key.
- **Service Long Term Secret Key (Service LT Key)**  The service key is based on the service account. It is used to encrypt the service portion of the service ticket and sign the PAC.
- **Session Key** - Issued by the KDC when a TGT is issued. The user will provide the session key to the KDC along with the TGT when requesting a service ticket.
- **Privilege Attribute Certificate (PAC) - The PAC holds all of the user's relevant information, it is sent along with the TGT to the KDC to be signed by the Target LT Key and the KDC LT Key in order to validate the user.**

---

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2019.png)

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2020.png)

<aside>
💡 You Don’t send your password or your password hash → you send the date and time encrypted with your hash so it’s very secure

</aside>

---

# Azure Active Directory Authentication Methods

- SAML (Security Assertion Markup Language)
- OAUTH 2.0
- OpenID Connect

## ⇒ SAML (Security Assertion Markup Language)

Security Assertion Markup Language (SAML) is a type of Single Sign-On (SSO) standard. It defines a set of rules/protocols that allow users to access web applications with a single login. This is possible because those applications (referred to as “Service Providers”) all trust the systems that verify users’ identities (referred to as “Identity Providers”).

Service Providers - These are the systems and applications that users access throughout the day.

Identity Providers - This would be the system that performs user authentication.

## ⇒ OAUTH 2.0

OAuth 2.0 is a standard that apps use to provide client applications with access.

OAuth 2.0 spec has four important roles:

- The authorization server, which is the server that issues the access token.
- The resource owner, normally your application's end-user, that grants permission to access the resource server with an access token.
- The client, which is the application that requests the access token, and then passes it to the resource server.
- The resource server, which accepts the access token and must verify that it is valid. In this case, this is your application.

## ⇒ OpenID Connect

OpenID Connect is an authentication standard built on top of OAuth 2.0. It adds an additional token called an ID token.

For that, it uses simple JSON Web Tokens (JWT). While OAuth 2.0 is about resource access and sharing, OIDC is all about user authentication

---

# **What are Group Policy Objects?**

- A GPO or a Group Policy Object is a feature of Active Directory that adds additional controls to user accounts and computers.
- Group Policy settings include local settings, site-wide settings, domain-level settings, and settings applied to organizational units.
- To create a GPO we need to go to **Tools > Group Policy Management** inside the Server Manager.

## ⇒ GPO distribution

GPOs are distributed to the network via a network share called `SYSVOL`, which is stored in the DC. All users in a domain should typically have
access to this share over the network to sync their GPOs periodically. The SYSVOL share points by default to the `C:\Windows\SYSVOL\sysvol\` directory on each of the DCs in our network.

Once a change has been made to any GPOs, it might take up to 2 hours for computers to catch up. If you want to force any particular computer to sync its GPOs immediately, you can always run the following command on the desired computer:

---

![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2021.png)

---

# Active Directory Certificate Services(AD CS)

When talking about certificates, we usually only think about the most common ones, such as those used to upgrade website traffic to HTTPS. But these are usually only used for applications that the organisation exposes to the internet. What about all those applications running on the internal network? Do we now have to give them internet access to allow them to request a certificate from a trusted Certificate Authority (CA)? Well, not really. Cue AD CS.

- some terminology:
    - PKI - Public Key Infrastructure is a system that manages certificates and public key encryption
    - AD CS - Active Directory Certificate Services is Microsoft's PKI implementation which usually runs on domain controllers
    - CA - Certificate Authority is a PKI that issues certificates
    - Certificate Template - a collection of settings and policies that defines how and when a certificate may be issued by a CA
    - CSR - Certificate Signing Request is a message sent to a CA to request a signed certificate
    - EKU - Extended/Enhanced Key Usage are object identifiers that define how a generated certificate may be used
- Since AD CS is such a privileged function, it normally runs on selected domain controllers. Meaning normal users can't really interact with the service directly. On the other side of the coin, organisations tend to be too large to have an administrator create and distribute each certificate manually. This is where certificate templates come in. Administrators of AD CS can create several templates that can allow any user with the relevant permissions to request a certificate themselves. These templates have parameters that say which user can request the certificate and what is required. What SpecterOps has found, was that specific combinations of these parameters can be incredibly toxic and be abused for privilege escalation and persistent access!
    
    ![Untitled](Active%20Directory%20Basics%20599c5a2d46f042b5bcface9f89760b3b/Untitled%2022.png)
    
- List Certificate templates

```powershell
certutil -v -template > cert_templates.txt
```

---

# **Domain Cached Credentials (MSCache2)**

In an AD environment, the authentication methods mentioned in this section and the previous require the host we are trying to access to communicate with the "brains" of the network, the Domain Controller. Microsoft developed the [MS Cache v1 and v2](https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/) algorithm (also known as `Domain Cached Credentials` (DCC) to solve the potential issue of a domain-joined host being unable to communicate with a domain controller (i.e., due to a network outage or other technical issue) and, hence, NTLM/Kerberos authentication not working to access the host in question. Hosts save the last `ten` hashes for any domain users that successfully log into the machine in the `HKEY_LOCAL_MACHINE\SECURITY\Cache` registry key. These hashes cannot be used in pass-the-hash attacks. Furthermore, the hash is very slow to crack with a tool such as Hashcat, even when using an extremely powerful GPU cracking rig, so attempts to crack these hashes typically need to be extremely targeted or rely on a very weak password in use. These hashes can be obtained by an attacker or pentester after gaining local admin access to a host and have the following format: `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`. It is vital as penetration testers that we understand the varying types of hashes that we may encounter while assessing an AD environment, their strengths, weaknesses, how they can be abused (cracking to cleartext, pass-the-hash, or relayed), and when an attack may be futile (i.e., spending days attempting to crack a set of Domain Cached Credentials).

---

# **General Active Directory Hardening Measures**

## **LAPS**

The [Microsoft Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.

Accounts can be set up to have their password rotated on a fixed interval (i.e., 12 hours, 24 hours, etc.). This free tool can be beneficial in reducing the impact of an individual compromised host in an AD environment. Organizations should not rely on tools like this alone. Still, when combined with other hardening measures and security best practices, it can be a very effective tool for local administrator account password management.

## **Audit Policy Settings (Logging and Monitoring)**

Every organization needs to have logging and monitoring setup to detect and react to unexpected changes or activities that may indicate an attack. Effective logging and monitoring can be used to detect an attacker or unauthorized employee adding a user or computer, modifying an object in AD, changing an account password, accessing a system in an unauthorized or non-standard manner, performing an attack such as password spraying, or more advanced attacks such as modern Kerberos attacks.

## **Group Policy Security Settings**

As mentioned earlier in the module, Group Policy Objects (GPOs) are virtual collections of policy settings that can be applied to specific users, groups, and computers at the OU level. These can be used to apply a wide variety of [security policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings) to help harden Active Directory. The following is a non-exhaustive list of the types of security policies that can be applied:

- [Account Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-policies) - Manage how user accounts interact with the domain. These include the password policy, account lockout policy, and Kerberos-related settings such as the lifetime of Kerberos tickets
- [Local Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-options) - These apply to a specific computer and include the security event audit policy, user rights assignments (user privileges on a host), and specific security settings such as the ability to install drivers, whether the administrator and guest accounts are enabled, renaming the guest and administrator accounts, preventing users from installing printers or using removable media, and a variety of network access and network security controls.
- [Software Restriction Policies](https://docs.microsoft.com/en-us/windows-server/identity/software-restriction-policies/software-restriction-policies) - Settings to control what software can be run on a host.
- [Application Control Policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control) - Settings to control which applications can be run by certain users/groups. This may include blocking certain users from running all executables, Windows Installer files, scripts, etc. Administrators use [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview) to restrict access to certain types of applications and files. It is not uncommon to see organizations block access to CMD and PowerShell (among other executables) for users that do not require them for their day-to-day job. These policies are imperfect and can often be bypassed but necessary for a defense-in-depth strategy.
- [Advanced Audit Policy Configuration](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/secpol-advanced-security-audit-policy-settings) - A variety of settings that can be adjusted to audit activities such as file access or modification, account logon/logoff, policy changes, privilege usage, and more.

## **Update Management (SCCM/WSUS)**

Proper patch management is critical for any organization, especially those running Windows/Active Directory systems. The [Windows Server Update Service (WSUS)](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus) can be installed as a role on a Windows Server and can be used to minimize the manual task of patching Windows systems. `System Center Configuration Manager` (SCCM) is a paid solution that relies on the WSUS Windows Server role being installed and offers more features than WSUS on its own. A patch management solution can help ensure timely deployment of patches and maximize coverage, making sure that no hosts miss critical security patches. If an organization relies on a manual method for applying patches, it could take a very long time depending on the size of the environment and also could result in systems being missed and left vulnerable.

## **Group Managed Service Accounts (gMSA)**

A gMSA is an account managed by the domain that offers a higher level of security than other types of service accounts for use with non-interactive applications, services, processes, and tasks that are run automatically but require credentials to run. They provide automatic password management with a 120 character password generated by the domain controller. The password is changed at a regular interval and does not need to be known by any user. It allows for credentials to be used across multiple hosts.

## **Account Separation**

Administrators must have two separate accounts. One for their day-to-day work and a second for any administrative tasks they must perform. For example, a user could log into their machine using their `sjones` account to send/receive an email, create documents, etc. They should have a separate account, such as `sjones_adm`, to access a [secure administrative host](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-secure-administrative-hosts) used to perform administrative tasks. This can help ensure that if a user's host is compromised (through a phishing attack, for example), the attacker would be limited to that host and would not obtain credentials for a highly privileged user with considerable access within the domain. It is also essential for the individual to use different passwords for each account to mitigate the risk of password reuse attacks if their non-admin account is compromised.

## **Password Complexity Policies + Passphrases + 2FA**

Ideally, an organization should be using passphrases or large randomly generated passwords using an enterprise password manager. The standard 7-8 character passwords can be cracked offline using a tool such as Hashcat very quickly with a GPU password cracking rig. Shorter, less complex passwords may also be guessed through a password spraying attack, giving an attacker a foothold in the domain. Password complexity rules alone in AD are not enough to ensure strong passwords. For example, the password `Welcome1` would meet the standard complexity rules (3 out of 4 of uppercase, lowercase, number, and special character) but would be one of the first passwords I would try in a password spraying attack. An organization should also consider implementing a password filter to disallow passwords containing the months or seasons of the year, the company name, and common words such as `password` and `welcome`. The minimum password length for standard users should be at least 12 characters and ideally longer for administrators/service accounts. Another important security measure is the implementation of multi-factor authentication (MFA) for Remote Desktop Access to any host. This can help to limit lateral movement attempts that may rely on GUI access to a host.

## **Limiting Domain Admin Account Usage**

All-powerful Domain Admin accounts should only be used to log in to Domain Controllers, not personal workstations, jump hosts, web servers, etc. This can significantly reduce the impact of an attack and cut down potential attack paths should a host be compromised. This would ensure that Domain Admin account passwords are not left in memory on hosts throughout the environment.

## **Periodically Auditing and Removing Stale Users and Objects**

It is important for an organization to periodically audit Active Directory and remove or disable any unused accounts. For example, there may be a privileged service account that was created eight years ago with a very weak password that was never changed, and the account is no longer in use. Even if the password policy had since been changed to be more resistant to attacks such as password spraying, an account such as this may be a quick and easy foothold or method for lateral movement or privilege escalation within the domain.

## **Auditing Permissions and Access**

Organizations should also periodically perform access control audits to ensure that users only have the level of access required for their day-to-day work. It is important to audit local admin rights, the number of Domain Admins (do we really need 30 of them?), and Enterprise Admins to limit the attack surface, file share access, user rights (i.e., membership in certain privileged security groups), and more.

## **Audit Policies & Logging**

Visibility into the domain is a must. An organization can achieve this through robust logging and then using rules to detect anomalous activity (such as many failed login attempts that could be indicative of a password spraying attack) or indicators that a Kerberoasting attack is being attempted. These can also be used to detect Active Directory enumeration. It is worth familiarizing ourselves with Microsoft's [Audit Policy Recommendations](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) to help detect compromise.

## **Using Restricted Groups**

[Restricted Groups](https://social.technet.microsoft.com/wiki/contents/articles/20402.active-directory-group-policy-restricted-groups.aspx) allow for administrators to configure group membership via Group Policy. They can be used for a number of reasons, such as controlling membership in the local administrator's group on all hosts in the domain by restricting it to just the local Administrator account and Domain Admins and controlling membership in the highly privileged Enterprise Admins and Schema Admins groups and other key administrative groups.

## **Limiting Server Roles**

It is important not to install additional roles on sensitive hosts, such as installing the `Internet Information Server` (IIS) role on a Domain Controller. This would increase the attack surface of the Domain Controller, and this type of role should be installed on a separate standalone web server. Some other examples would be not hosting web applications on an Exchange mail server and separating web servers and database servers out to different hosts. This type of role separation can help to reduce the impact of a successful attack.

## **Limiting Local Admin and RDP Rights**

Organizations should tightly control which users have local admin rights on which computers. As stated above, this can be achieved using Restricted Groups. I have seen too many organizations with the entire Domain Users group with local admin rights on one or more hosts. This would allow an attacker that compromises `ANY` account (even a very low privileged one) to access that host as a local admin and potentially obtain sensitive data or steal high privileged domain account credentials from memory if another user is logged in. The same goes for Remote Desktop (RDP) rights. If many users can RDP to one or many machines, this increases the risk of sensitive data exposure or potential privilege escalation attacks, leading to further compromise.

This [link](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory) provides further reading on Microsoft's Best Practices for Securing Active Directory.

---

# Next Step

[Active Directory Attacks](https://www.notion.so/Active-Directory-Attacks-a601a542708147a097fd5a8f01f33c43?pvs=21)