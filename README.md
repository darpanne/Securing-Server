# Server Security Lab

## Objective
The Server Security Lab focuses on securing network infrastructures, implementing advanced identity management solutions, auditing policies, and deploying secure file server systems. The repository enables learners to design and implement robust security solutions for servers, directories, and network traffic.

---

## Skills Gained
- Advanced firewall management, including creating policies and securing traffic with IPSec.
- Designing and implementing Active Directory Forests, Domains, and Group Policies with a focus on security and performance.
- Implementing advanced identity control mechanisms such as Just-in-Time Access and Just Enough Administration.
- Configuring auditing policies to monitor logins, changes to registry, and other system activities.
- Deploying and managing Advanced Threat Analytics (ATA) to identify suspicious network traffic.
- Designing and implementing a Public Key Infrastructure (PKI) solution, including certificate management.
- Securing file servers with classification policies, Attribute-Based Access Control (ABAC), and AD RMS.
- Leveraging tools like Azure AD, DNS Manager, and PowerShell for secure server management.

---

## Tools Used
- **Microsoft Active Directory**: For managing domains, forests, and group policies.
- **ADCS, ADDS, and ADFS**: For certificate services and federation.
- **Windows Server Tools**: DNS Manager, Group Policy Management Console (GPMC), and Advanced Threat Analytics (ATA).
- **PowerShell ISE**: For Just Enough Administration (JEA) and auditing scripts.
- **Azure Active Directory (Azure AD)**: For cloud-based identity management.
- **Audit Policies**: For monitoring login activities and system changes.
- **File Encryption Tools**: To secure file systems.
- **SIEM Solutions**: For integrating ATA and analyzing suspicious activity.

---

## Tasks
Below are the tasks and concepts covered in this repository. Screenshots and implementation details will be added as they become available.

### 1. Securing Network Infrastructure
- Configured advanced firewall policies to control and secure network traffic.
- Deployed IPSec to secure traffic flow across the network.
- Implemented baseline configurations for auditing software firewalls.

### 2. Active Directory Design and Implementation
![image](https://github.com/user-attachments/assets/0890ee0a-feac-4e13-a90f-b60fc31632cc)
![image](https://github.com/user-attachments/assets/625df01d-0ef7-47c0-8a1b-b783405a885b)
- Designed and implemented Active Directory Forests, Domains, and Sites with performance and security in mind.
- Configured Group Policy Objects (GPOs) for advanced access and security control.
- Managed group policy settings to enforce secure configurations across the network.

### 3. Advanced Identity Management
![image](https://github.com/user-attachments/assets/36148ba7-e352-4d8f-b87b-211ce75cce91)
![image](https://github.com/user-attachments/assets/a88e2c7e-2bc0-47b1-a2c6-7c46168d2311)
![image](https://github.com/user-attachments/assets/75dd1ea5-9369-48fc-94bb-bc3d246bedd8)


- Implemented Just-in-Time Access (JIT) to grant access only when needed.
- Configured Just Enough Administration (JEA) using PowerShell ISE to restrict administrative privileges.
- Deployed Azure AD for cloud-based identity and Single Sign-On (SSO).

### 4. Audit Policy Design and Implementation
- Configured advanced audit policies to monitor special accounts and log login activities.
- Audited changes to system registries and critical attributes.

### 5. Advanced Threat Analytics (ATA) Integration
- Deployed ATA to monitor and analyze traffic for Kerberos, NTLM, and DNS protocols.
- Integrated ATA with a SIEM solution to identify and track suspicious activities in real-time.

### 6. Public Key Infrastructure (PKI) Deployment
![image](https://github.com/user-attachments/assets/8241b9a1-7b81-4fbe-a051-4c7668170c55)
![image](https://github.com/user-attachments/assets/cc05d958-eb4d-4c37-a4cf-b4b42212f93e)
![image](https://github.com/user-attachments/assets/b01b642c-1bf5-4215-9096-a8b520f32297)
- Designed and implemented a full PKI solution, including certificate templates and policies.
- Expanded server security using certificates for encryption and secure communication.

### 7. Advanced File Server Design
- Configured file servers with advanced classification policies using regular expressions.
- Implemented Attribute-Based Access Control (ABAC) for fine-grained permissions.
- Secured files with Active Directory Rights Management Services (AD RMS).

### 8. DNS and Server Configuration
- Managed DNS settings and secured configurations using DNS Manager.
- Configured server baselines and audited DNS activities for potential threats.

### 9. Implementing Azure Solutions
- Deployed secure Azure environments with advanced configurations.
- Managed hybrid identity solutions integrating Azure AD with on-premises infrastructure.
---

```powershell
### 1. Advanced Firewall Configuration
# Allow specific traffic using firewall rules
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

# Block all outbound traffic except whitelisted applications
New-NetFirewallRule -DisplayName "Block Outbound Traffic" -Direction Outbound -Action Block

### 2. Active Directory Management
# Create a new Active Directory Forest
Install-ADDSForest -DomainName "darpanne.local" -SafeModeAdministratorPassword (ConvertTo-SecureString "SecureP@ssw0rd" -AsPlainText -Force)

# Add a new user to Active Directory
New-ADUser -Name "darpanne" -GivenName "Darpan" -SamAccountName "darpanne" -AccountPassword (ConvertTo-SecureString "SecureP@ssw0rd" -AsPlainText -Force) -Enabled $true

### 3. Group Policy Configuration
# Create a new Group Policy Object
New-GPO -Name "SecureLogonPolicy"

# Link a GPO to an Organizational Unit
New-GPLink -Name "SecureLogonPolicy" -Target "OU=SecureOU,DC=darpanne,DC=local"

### 4. Just Enough Administration (JEA)
# Create a JEA session configuration file
New-PSSessionConfigurationFile -Path "C:\JEA\darpanneJEA.pssc" -SessionType RestrictedRemoteServer

# Register the JEA configuration
Register-PSSessionConfiguration -Name "JEAConfig" -Path "C:\JEA\darpanneJEA.pssc"

### 5. Auditing and Monitoring
# Enable auditing for account logon events
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable

# Get a list of current audit policies
auditpol /get /category:*

### 6. Public Key Infrastructure (PKI)
# Create a new Certificate Authority
Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -HashAlgorithm SHA256 -KeyLength 2048

# Issue a certificate
certreq -submit -config "CAserver\darpanneCA" "C:\Requests\darpanneCert.req"

### 7. Secure File Server Configuration
# Enable Access-Based Enumeration on a file share
Set-SmbShare -Name "SecureShare" -FolderEnumerationMode AccessBased

# Encrypt a folder using EFS
cipher /e /s:"C:\SecureFolder"

### 8. Advanced Threat Analytics (ATA)
# Install ATA Gateway
msiexec /i "C:\Installers\Microsoft ATA Gateway Setup.msi" /quiet GATEWAYNAME=darpanneGW CENTERIP=192.168.1.20

### 9. DNS Configuration
# Create a new DNS zone
Add-DnsServerPrimaryZone -Name "darpanne.local" -ZoneFile "darpanne.local.dns"

# Add a new A record
Add-DnsServerResourceRecordA -ZoneName "darpanne.local" -Name "webserver" -IPv4Address "192.168.1.10"

### 10. Azure Integration
# Add a user to Azure AD
New-AzureADUser -DisplayName "Darpan Neupane" -PasswordProfile (New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile -Property @{Password="SecureP@ssw0rd"; ForceChangePasswordNextLogin=$false}) -UserPrincipalName "darpanne@domain.onmicrosoft.com"

# Assign a role in Azure AD
New-AzRoleAssignment -SignInName "darpanne@domain.onmicrosoft.com" -RoleDefinitionName "Contributor" -Scope "/subscriptions/<SubscriptionID>/resourceGroups/darpanneResourceGroup"

### 11. IPSec Traffic Security
# Create an IPSec rule to secure traffic
New-NetIPsecRule -DisplayName "SecureIPSecRule" -PolicyStore ActiveStore -KeyModule IKEv2 -LocalAddress "192.168.1.10" -RemoteAddress "192.168.1.20" -Action RequireInboundAndOutbound

