# Data Safe
This repo contains samples that demonstrate the use of Data Safe APIs.


Oracle Data Safe is a fully integrated, regional Oracle Cloud Infrastructure cloud service focused on database security. It provides a complete and integrated set of features of the Oracle Cloud Infrastructure (OCI) for protecting sensitive and regulated data in Oracle databases.

Oracle Data Safe delivers essential security services for Oracle Autonomous Database, Exadata Database on Dedicated Infrastructure, Oracle Base Database, and Oracle Databases running in OCI. It also supports on-premises Oracle Databases, Exadata Database on Cloud@Customer, and multi-cloud deployments (e.g. Oracle Database@Azure, Amazon RDS for Oracle). 

All Oracle Database customers can reduce the risk of a data breach and simplify compliance by using Data Safe to assess security and user risk, monitor and audit user activity, discover, classify, mask sensitive data, and manage SQL Firewall for Oracle Database 23ai.


# Prerequisites
Install the [OCI Python SDK] (https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/pythonsdk.htm) or just use your OCI Cloud Shell
as the SDK for Python is pre-configured with your credentials and ready to use immediately from within [Cloud Shell] (https://docs.oracle.com/en-us/iaas/Content/API/Concepts/cloudshellintro.htm#Cloud_Shel).

Python samples assume you have configured `oci cli` and have a config file staged under `/home/user/.oci`
that contains the following details:

```
[DEFAULT]
user=<user_ocid>
fingerprint=<fingerprint>
tenancy=<tenancy ocid>
region=<region>            #e.g. us-ashburn-1
key_file=<oci_api_key>.pem # pem file

[PROFILE1]
user=<user_ocid>
fingerprint=<fingerprint>
tenancy=<tenancy ocid>
region=<region>            #e.g. us-ashburn-1
key_file=<oci_api_key>.pem # pem file

[PROFILE2]
user=<user_ocid>
fingerprint=<fingerprint>
tenancy=<tenancy ocid>
region=<region>            #e.g. us-ashburn-1
key_file=<oci_api_key>.pem # pem file
```

# Documentation
You can find the online documentation of the Oracle Data Safe including its APIs under https://docs.oracle.com/en/cloud/paas/data-safe/

# Learn more
Check out the following resources for more information about Oracle Data Safe:

- Data Safe at [oracle.com](https://www.oracle.com/security/database-security/data-safe/)
- YouTube [playlist](https://www.youtube.com/playlist?list=PLdtXkK5KBY559R24J8mo2yOTmic7Vruss)
- [Other](https://www.oracle.com/security/database-security/) database security products

