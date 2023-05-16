pxshell
=======

This utility is an interactive wrapper for PXAPI library. It allows interaction with pxGrid using simple CLI interface.

Installation
------------


.. code-block:: console

  # Install the module
  pip install pxgrid-api

Usage
-----

All commands are document and help can be retrived using help &lt;command&gt;

.. code-block:: console

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

Before the utility can interface with pxGrid, it has to be configured with pxGrid information and certificates.  
Note that client side certificate and private key is not required for password based authentication. See an example below.
This is done with config command. The config can also be saved and loaded from a file. The file is in human readable json format.  
config apply command must be used to instantiate the API connection.

.. code-block:: console

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

Examples
~~~~~~~~

Check if account is approved in ISE

.. code-block:: console

  pxshell> activate
  {'accountState': 'ENABLED', 'version': '2.0'}

Using password based authentication

.. code-block:: console

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

Working with ANC

.. code-block:: console

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

Working with sessions

.. code-block:: console

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

Working with Trustsec config

.. code-block:: console

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

Working with profiler

.. code-block:: console

  pxshell> profiler topics
  topic
  pxshell> profiler subscribe topic
  Ctrl-C to disconnect...
  Received Packet: command=CONNECTED content=
  Received Packet: command=MESSAGE content={"operation":"CREATE","profile":{"id":"4fd41a00-04ee-11eb-8d63-1a05c3bba070","name":"test-device","fullName":"test-device"}}
  Received Packet: command=MESSAGE content={"operation":"DELETE","profile":{"id":"4fd41a00-04ee-11eb-8d63-1a05c3bba070","name":"test-device","fullName":"test-device"}}
