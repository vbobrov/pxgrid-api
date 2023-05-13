
# Introduction
This repo includes two components.
* A python API library making it easier to interact with pxGrid services on ISE
* Interactive CLI utility to interface with pxGrid without writing any code

pxGrid requires FQDNs of all the nodes to be resolvable. It is not possible to use the library or the CLI utility to connect to ISE via IP address, even if there's just one node. Hosts record will work as well.

## Features
* Support for both certificate and password authentication when connecting to pxGrid nodes
* Commands and methods to interact with most pxGrid services
* Websocket support for subscribing to topics.
* Debug capabilities to show all low level interactions with pxGrid

## Limitations

* pxGrid API 2.0 only. No support for 1.0
* Private key must be unencrypted
* No support for Dynamic Topics
* Websockets (subscribing to topics) require that the pxGrid node certificate is trusted

## Additonal reference material:
* https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki
* https://developer.cisco.com/docs/pxgrid/
* https://developer.cisco.com/codeexchange/github/repo/cisco-pxgrid/python-advanced-examples


# pxAPI Library

This library simplifies interaction with ISE pxGrid


## Installation

```
# Optionally create virtual env
python3 -m venv env
pip install px-api
```

## Usage

pxapi.py file has comments throughout describing all functions.  
All data is returned in the original form, converted to python dict

### REST API
These are fairly straight forward. Review the comments in the code for reference.

```python
#!/usr/bin/env python3
from pxapi import PXAPI

# Instatiate object. Root CA argument can be omitted to disable server certificate verification.
api=PXAPI('pxgridnode.example.com','client-name','client.cer','client.key','root.cer')

# Check account activation status. This will connect to pxGrid node and check if our account is in approved and enabled state
# With this default usage, the function will return immediately with either True or False on the state of the account
api.account_activate()

# Optionally, function can wait until the account is approved and retry every 60 seconds
api.account_activate(True)

# Some examples
# Retrive all sessions
print(api.get_sessions())

# Retrieve all Trustsec egress policies
print(api.trustsec_get_egress_policies())

# Retrive all NON-Compliant MDM endpoints
print(api.mdm_get_endpoints_by_type('NON-COMPLIANT'))
```

### Password based authentication
This type of authentication avoids having to work with client side certificates and private keys.

In order to use password based authentication, it needs to be first enabled in ISE under Administration > pxGrid Services > Settings

The first step to use password authentication is to request a bootstrap account with a password generated by ISE.

```python
# Instatiate API object with minimum information. Root CA argument can be omitted to disable server certificate verification.
api=PXAPI('pxgridnode.example.com','pwdclient1','','','root.cer')

# Next, create the account. The account will be created with the username specified as client name above.
# The password returned by ISE has to be stored on the client side.
# The account will show in Initialized state on ISE
# This API call can be executed multiple times with the same name to generate a new password until the account is activated below
account_info=api.account_create()
print(account_info)
{'nodeName': 'pwdclient1', 'password': 'doosV8AEKqL7URUE', 'userName': 'pwdclient1'}
password=accountInfo['password']

# We now need to initialize API again with the password this time
api=PXAPI('pxgridnode.example.com','pwdclient1','','','root.cer',password)

# To request this account to be approved, we need to execute accountActivate API call.
# Note that once this account is requested to be activated, you can no longer call accountCreate API above with the same client name
# Once the account is in Pending state, it has to be approved in ISE under Administration > pxGrid Services > Client Management
account_status=api.account_activate()
print(account_status)
{'accountState': 'PENDING', 'version': '2.0'}

# To confirm that the accounts is approved, we can call accountActivate again.
account_status=api.account_activate()
print(account_status)
{'accountState': 'ENABLED', 'version': '2.0'}

# From here on, you can start using the API using the stored password.
api=PXAPI('pxgridnode.example.com','pwdclient1','','','root.cer',password)

```

### Subscribing to pxGrid topics

ISE uses web sockets as a mechanism for exchange real-time data with pxGrid clients  
When data is received from ISE, the api will convert it to **StompFrame** class and pass it a callback function

```python
def on_message(stomp_frame):
    print(f"Command: {stomp_frame.command}")
    print(f"Headers: {json.dumps(stomp_frame.headers,indent=2)}")
    try:
        print(f"Data: {json.dumps(stomp_frame.data,indent=2)}")
    except:
        pass

api=PXAPI('pxgridnode.example.com','client-name','client.cer','client.key','root.cer')
api.topic_subscribe("com.cisco.ise.session","sessionTopic",on_message)

```

# pxshell

This utility is an interactive wrapper for pxAPI library. It allows interaction with pxGrid using simple CLI interface.

## Usage

All commands are document and help can be retrived using help &lt;command&gt;
```
$ pxshell
pxshell> help

Documented commands (type help <topic>):
========================================
accountcreate  anc     debug  mdm       radius   sxp     trustsec   
activate       config  help   profiler  session  system  trustseccfg

Undocumented commands:
======================
EOF

pxshell> help config
Config options:
                save <file>: Save config to file
                load <file>: Load config from file
                apply [file]: Instatiate connection to pxGrid. Optionaly load the file and apply in one step
                show: Show current settings 
                pxnode <hostname>: Set pxGrid PSN FQDN
                name <clientname>: Set pxGrid client name
                cert <certfile>: Set client certificate file name
                key <keyfile>: Set client private key
                root [<rootfile>]: Set root CA file. Leave out <rootfile> to disable server certificate verification
```

Before the utility can interface with pxGrid, it has to be configured with pxGrid information and certificates.  
Note that client side certificate and private key is not required for password based authentication. See an example below.
This is done with config command. The config can also be saved and loaded from a file. The file is in human readable json format.  
config apply command must be used to instantiate the API connection.

```
pxshell> config pxnode pxgridnode.example.com
pxshell> config name client-name
pxshell> config cert client.cer
pxshell> config key client.key
pxshell> config root root.cer
pxshell> config show
{'client_name': 'client-name', 'px_node': 'pxgridnode.example.com', 'client_cert_file': 'client.cer', 'client_key_file': 'client.key', 'root_ca_file': 'root.cer'}
pxshell> config save px.cfg
pxshell> config load px.cfg
pxshell> config apply <--config apply command is used to create the api object with the requested parameters
pxshell> config apply px.cfg <--config apply can load the config file in one step

```
### Examples

Check if account is approved in ISE
```
pxshell> activate
{'accountState': 'ENABLED', 'version': '2.0'}
```
Using password based authentication
```
pxshell> config pxnode pxgridnode.example.com
pxshell> config name pwdclient
pxshell> config root root.cer
pxshell> config apply
pxshell> accountcreate
{
  "nodeName": "pwdclient",
  "password": "Pbclmnup25NTsKul",
  "userName": "pwdclient"
}
Password automatically set in the config. Use config show to verify

**** Be sure to save the config at this point to save the password ****
pxshell> config save pwdclient.cfg

**** Next, we request the account to be approved on ISE ****
pxshell> config apply
pxshell> activate
{
  "accountState": "PENDING",
  "version": "2.0"
}

**** After the account is approved in ISE GUI, activate returns ENABLED ****
pxshell> activate
{
  "accountState": "ENABLED",
  "version": "2.0"
}

**** From here on, you can use all the other commands to interact with pxGrid ****
```
Working with ANC
```
pxshell> anc create Restrict QUARANTINE
{'name': 'Restrict', 'actions': ['QUARANTINE']}
pxshell> anc policies
{'policies': [{'name': 'Quarantine', 'actions': ['QUARANTINE']}, {'name': 'Restrict', 'actions': ['QUARANTINE']}, {'name': 'Shutdown', 'actions': ['SHUT_DOWN']}]}
pxshell> anc delete Restrict
{}
pxshell> anc policies
{'policies': [{'name': 'Quarantine', 'actions': ['QUARANTINE']}, {'name': 'Shutdown', 'actions': ['SHUT_DOWN']}]}
pxshell> anc topics
statusTopic
pxshell> anc subscribe statusTopic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"operationId":"vb-ise-pan1.vblan.com:35","macAddress":"11:22:33:44:55:66","status":"SUCCESS","policyName":"Quarantine"}
Received Packet: command=MESSAGE content={"operationId":"vb-ise-pan1.vblan.com:36","macAddress":"11:22:33:44:55:66","status":"SUCCESS"}
```
Working with sessions
```
pxshell> session all
{'sessions': [{'timestamp': '2020-09-29T22:45:45.489-04:00', 'state': 'STARTED', 'userName': '18:60:24:00:00:02', 'callingStationId': '18:60:24:00:00:02', 'calledStationId': '88:5A:92:7F:BF:82', 'auditSessionId': 'AC1F01070000005FDCE6C13E', 'ipAddresses': ['172.31.8.150'], 'macAddress': '18:60:24:00:00:02', 'nasIpAddress': '172.31.1.7', 'nasPortId': 'GigabitEthernet1/0/2', 'nasIdentifier': 'sw4', 'nasPortType': 'Ethernet', 'endpointProfile': 'HP-Kali', 'adNormalizedUser': '18:60:24:00:00:02', 'providers': ['None'], 'endpointCheckResult': 'none', 'identitySourcePortStart': 0, 'identitySourcePortEnd': 0, 'identitySourcePortFirst': 0, 'serviceType': 'Call Check', 'networkDeviceProfileName': 'Cisco', 'radiusFlowType': 'WiredMAB', 'mdmRegistered': False, 'mdmCompliant': False, 'mdmDiskEncrypted': False, 'mdmJailBroken': False, 'mdmPinLocked': False, 'selectedAuthzProfiles': ['Quarantine']}]}

pxshell> session topics
sessionTopic
groupTopic
pxshell> session subscribe sessionTopic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"sessions":[{"timestamp":"2020-10-02T16:41:03.984-04:00","state":"STARTED","userName":"18:60:24:00:00:02","callingStationId":"18:60:24:00:00:02","calledStationId":"88:5A:92:7F:BF:82","auditSessionId":"AC1F010700000068EB0BEF16","ipAddresses":["172.31.8.150"],"macAddress":"18:60:24:00:00:02","nasIpAddress":"172.31.1.7","nasPortId":"GigabitEthernet1/0/2","nasIdentifier":"sw4","nasPortType":"Ethernet","ancPolicy":"Quarantine","endpointProfile":"HP-Kali","adNormalizedUser":"18:60:24:00:00:02","providers":["None"],"endpointCheckResult":"none","identitySourcePortStart":0,"identitySourcePortEnd":0,"identitySourcePortFirst":0,"serviceType":"Call Check","networkDeviceProfileName":"Cisco","radiusFlowType":"WiredMAB","mdmRegistered":false,"mdmCompliant":false,"mdmDiskEncrypted":false,"mdmJailBroken":false,"mdmPinLocked":false,"selectedAuthzProfiles":["Quarantine"]}]}
Received Packet: command=MESSAGE content={"sessions":[{"timestamp":"2020-10-02T16:41:13.199-04:00","state":"DISCONNECTED","userName":"18:60:24:00:00:02","callingStationId":"18:60:24:00:00:02","calledStationId":"88:5A:92:7F:BF:82","auditSessionId":"AC1F010700000068EB0BEF16","ipAddresses":["172.31.8.150"],"macAddress":"18:60:24:00:00:02","nasIpAddress":"172.31.1.7","nasPortId":"GigabitEthernet1/0/2","nasIdentifier":"sw4","nasPortType":"Ethernet","ancPolicy":"Quarantine","endpointProfile":"HP-Kali","adNormalizedUser":"18:60:24:00:00:02","providers":["None"],"endpointCheckResult":"none","identitySourcePortStart":0,"identitySourcePortEnd":0,"identitySourcePortFirst":0,"serviceType":"Call Check","networkDeviceProfileName":"Cisco","radiusFlowType":"WiredMAB","mdmRegistered":false,"mdmCompliant":false,"mdmDiskEncrypted":false,"mdmJailBroken":false,"mdmPinLocked":false,"selectedAuthzProfiles":["Quarantine"]}]}
```
Working with Trustsec config
```
pxshell> trustseccfg sgt
{'securityGroups': [{'id': '92bb1950-8c01-11e6-996c-525400b48521', 'name': 'ANY', 'description': 'Any Security Group', 'tag': 65535}, {'id': '934557f0-8c01-11e6-996c-525400b48521', 'name': 'Auditors', 'description': 'Auditor Security Group', 'tag': 9}, {'id': '935d4cc0-8c01-11e6-996c-525400b48521', 'name': 'BYOD', 'description': 'BYOD Security Group', 'tag': 15}, {'id': '9370d4c0-8c01-11e6-996c-525400b48521', 'name': 'Contractors', 'description': 'Contractor Security Group', 'tag': 5}, {'id': '93837260-8c01-11e6-996c-525400b48521', 'name': 'Developers', 'description': 'Developer Security Group', 'tag': 8}, {'id': '9396d350-8c01-11e6-996c-525400b48521', 'name': 'Development_Servers', 'description': 'Development Servers Security Group', 'tag': 12}, {'id': '93ad6890-8c01-11e6-996c-525400b48521', 'name': 'Employees', 'description': 'Employee Security Group', 'tag': 4}, {'id': '93c66ed0-8c01-11e6-996c-525400b48521', 'name': 'Guests', 'description': 'Guest Security Group', 'tag': 6}, {'id': '93e1bf00-8c01-11e6-996c-525400b48521', 'name': 'Network_Services', 'description': 'Network Services Security Group', 'tag': 3}, {'id': '93f91790-8c01-11e6-996c-525400b48521', 'name': 'PCI_Servers', 'description': 'PCI Servers Security Group', 'tag': 14}, {'id': '940facd0-8c01-11e6-996c-525400b48521', 'name': 'Point_of_Sale_Systems', 'description': 'Point of Sale Security Group', 'tag': 10}, {'id': '9423aa00-8c01-11e6-996c-525400b48521', 'name': 'Production_Servers', 'description': 'Production Servers Security Group', 'tag': 11}, {'id': '9437a730-8c01-11e6-996c-525400b48521', 'name': 'Production_Users', 'description': 'Production User Security Group', 'tag': 7}, {'id': '944b2f30-8c01-11e6-996c-525400b48521', 'name': 'Quarantined_Systems', 'description': 'Quarantine Security Group', 'tag': 255}, {'id': '94621290-8c01-11e6-996c-525400b48521', 'name': 'Test_Servers', 'description': 'Test Servers Security Group', 'tag': 13}, {'id': '947832a0-8c01-11e6-996c-525400b48521', 'name': 'TrustSec_Devices', 'description': 'TrustSec Devices Security Group', 'tag': 2}, {'id': '92adf9f0-8c01-11e6-996c-525400b48521', 'name': 'Unknown', 'description': 'Unknown Security Group', 'tag': 0}]}
pxshell> trustseccfg topics
securityGroupVnVlanTopic
securityGroupTopic
securityGroupAclTopic
pxshell> trustseccfg subscribe securityGroupTopic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"operation":"CREATE","securityGroup":{"id":"05000d80-04ea-11eb-8d63-1a05c3bba070","name":"hackers","description":"","tag":16}}
Received Packet: command=MESSAGE content={"operation":"DELETE","securityGroup":{"id":"05000d80-04ea-11eb-8d63-1a05c3bba070","name":"hackers","description":"","tag":16}}
```
Working with profiler
```
pxshell> profiler topics
topic
pxshell> profiler subscribe topic
Ctrl-C to disconnect...
Received Packet: command=CONNECTED content=
Received Packet: command=MESSAGE content={"operation":"CREATE","profile":{"id":"4fd41a00-04ee-11eb-8d63-1a05c3bba070","name":"test-device","fullName":"test-device"}}
Received Packet: command=MESSAGE content={"operation":"DELETE","profile":{"id":"4fd41a00-04ee-11eb-8d63-1a05c3bba070","name":"test-device","fullName":"test-device"}}
```