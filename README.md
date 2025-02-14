# Azure Privilege Escalation Checker

##  Overview
This C# project analyses Azure environments to identify potential **privilege escalation vectors** based on available credentials. It helps security professionals assess misconfigurations and weak permissions that could be exploited by attackers.

## Usage
The app will run and prompt you to login with credentials you have. This will start a device code flow and an access token will be gained. If an access token is already within your environment variables it will check if its valid and not re-auth you.
Once the access token is collected and stored it will run the following checks:

- Check your Granted Pemissions and print to screen
- User Allowed to Create Apps
- User Allowed to Create Security Groups
- User Allowed to Create Tenants
- User Allowed to Read Bitlocker Keys for Owned Device
- User Allowed to Read Other Users
- User can invite guests

##  Why?
When do engagements you often gathere credentials and have to login and check individual areas one by one. I wanted a tool to quickly check all potentail areas and output a response based on what was vulnerable.


##  Features
- **Credential-Based Analysis** – Detects privilege escalation paths based on provided credentials.
- **Role & Permission Mapping** – Identifies misconfigured roles and inherited permissions.
- **Azure Resource Inspection** – Scans key services for security weaknesses.
- **Actionable Insights** – Highlights security risks with recommendations.

##  Build
### **Prerequisites**
- .NET SDK (latest version recommended)
- Azure CLI or SDK authentication

### **Building**
Git clone and Simply build solution

