#!/usr/bin/env python3
#
# Copyright (c) 2021 Cisco Systems, Inc. and/or its affiliates
#
from requests import JSONDecodeError
from pxapi import PXAPI
import cmd
import json
import logging
import http.client as http_client
import re

class PXShell(cmd.Cmd):
    intro="Welcome to pxshell."
    prompt="pxshell> "
    config={"client_name":"","px_node":"","client_cert_file":"","client_key_file":"","root_ca_file":"","password": ""}

    def onecmd(self,line):
        if line and not line.split()[0] in ["EOF","accountcreate","config","debug","help"]:
            if self.config["client_name"]=="":
                print("Client name is not defined. Use config show to verify.")
                return
            if self.config["px_node"]=="":
                print("pxGrid Node is not defined. Use config show to verify.")
                return
            if (self.config["client_cert_file"]=="" or self.config["client_key_file"]=="") and self.config["password"]=="":
                print("Either client certificate/key or password is required. Use config show to verify.")
            if not hasattr(self,"api"):
                print("API is not initialized. Use config apply.")
                return
        try:
            return(cmd.Cmd.onecmd(self, line))
        except Exception as e:
            print(f"Error occured: {e}")

    def print_json(self,value):
        print(json.dumps(value,indent=2))

    def show_topics(self,service):
        service_info=self.api.service_lookup(service)
        for service_property in service_info["services"][0]["properties"]:
            if re.search(r"^.*Topic",service_property,re.IGNORECASE):
                self.print_json(service_property)

    def emptyline(self):
        pass

    def do_session(self,line):
        """session options:
        all: Retrive all active sessions
        byip <x.x.x.x>: List all active sessions by IP address
        bymac <hh:hh:hh:hh:hh:hh>: List all active sessions by MAC address
        groups: List all User Groups
        usergroups <username>: List user"s groups
        topics: List topics available for subscription
        subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"all":1,"byip":2,"bymac":2,"groups":1,"usergroups":2,"topics":1,"subscribe":2}
        args=line.split()
        if line and args[0] in valid_options and len(args)==valid_options[args[0]]:
            if args[0]=="all":
                self.print_json(self.api.get_sessions())
            if args[0]=="byip":
                self.print_json(self.api.get_session_by_ip_address(args[1]))
            if args[0]=="bymac":
                self.print_json(self.api.get_session_by_mac_address(args[1]))
            if args[0]=="groups":
                self.print_json(self.api.get_user_groups())
            if args[0]=="usergroups":
                self.print_json(self.api.get_user_group_by_username(args[1]))
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_SESSION)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_SESSION,args[1],on_message)
        else:
            print("Invalid command. See help session")

    def do_anc(self,line):
        """"anc options:
        policies: List all ANC policies
        policybyname <name>: List policy by name
        create <name> <action>: Create new policy. Action must be QUARANTINE, SHUT_DOWN or PORT_BOUNCE
        delete <name>: Delete policy
        endpoints: List endpoints assigned to policies
        endpointpolicies: List endpoints policy assignment by MAC address on a specific device (NAS-IP-Address)
        endpointsbymac <hh:hh:hh:hh:hh:hh>: List policy assigned to MAC address
        endpointsbynas <hh:hh:hh:hh:hh:hh> <x.x.x.x>: List policy assigned to a MAC address on a specific device (NAS-IP-Address)
        applybyip <name> <x.x.x.x>: Apply policy by IP address
        applybymac <name> <hh:hh:hh:hh:hh:hh>: Apply policy by MAC address
        applybynas <name> <hh:hh:hh:hh:hh:hh> <x.x.x.x>: Apply policy by MAC address on a specific device (NAS-IP-Address)
        clearbymac <hh:hh:hh:hh:hh:hh>: Clear policy by MAC address
        clearbynas <hh:hh:hh:hh:hh:hh> <x.x.x.x>: Clear policy by MAC address a specific device (NAS-IP-Address)
        topics: List topics available for subscription
        subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"policies":1,"policybyname":2,"create":3,"delete":2,"endpoints":1,"endpointpolicies":1,"endpointsbymac":2,"endpointsbynas":3,"applybyip":3,"applybymac":3,"applybynas":4,"clearbymac":2,"clearbynas":3,"topics":1,"subscribe":2}
        args=line.split()
        if line and args[0] in valid_options and len(args)==valid_options[args[0]]:
            if args[0]=="policies":
                self.print_json(self.api.anc_get_policies())
            if args[0]=="policybyname":
                self.print_json(self.api.anc_get_policy_by_name(args[1]))
            if args[0]=="create":
                self.print_json(self.api.anc_create_policy(args[1],args[2]))
            if args[0]=="delete":
                self.print_json(self.api.anc_delete_policy_by_name(args[1]))
            if args[0]=="endpoints":
                self.print_json(self.api.anc_get_endpoints())
            if args[0]=="endpointpolicies":
                self.print_json(self.api.anc_get_endpoint_policies())
            if args[0]=="endpointsbymac":
                self.print_json(self.api.anc_get_endpoint_by_mac_address(args[1]))
            if args[0]=="endpointsbynas":
                self.print_json(self.api.anc_get_endpoint_by_nas_ip_address(args[1],args[2]))
            if args[0]=="applybyip":
                self.print_json(self.api.anc_apply_endpoint_by_ip_address(args[1],args[2]))
            if args[0]=="applybymac":
                self.print_json(self.api.anc_apply_endpoint_by_mac_address(args[1],args[2]))
            if args[0]=="applybynas":
                self.print_json(self.api.anc_apply_endpoint_policy(args[1],args[2],args[3]))
            if args[0]=="clearbymac":
                self.print_json(self.api.anc_clear_endpoint_by_mac_address(args[1]))
            if args[0]=="clearbynas":
                self.print_json(self.api.anc_clear_endpoint_policy(args[1],args[2]))
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_ANC)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_ANC,args[1],on_message)
        else:
            print("Invalid command. See help anc")

    def do_mdm(self,line):
        """mdm options:
        endpoints: List all MDM endpoints
        endpointsbymac <hh:hh:hh:hh:hh:hh>: List MDM endpoints by MAC address
        endpointsbytype <type>: List MDM endpoints by type. Type must be NON_COMPLIANT, REGISTERED or DISCONNECTED
        endpointsbyos <ostype>: List MDM endpoints by OS. OS must be ANDROID, IOS or WINDOWS
        topics: List topics available for subscription
        subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"endpoints":1,"endpointsbymac":2,"endpointsbytype":2,"endpointsbyos":2,"topics":1,"subscribe":2}
        args=line.split()
        if line and args[0] in valid_options and len(args)==valid_options[args[0]]:
            if args[0]=="endpoints":
                self.print_json(self.api.mdm_get_endpoints())
            if args[0]=="endpointsbymac":
                self.print_json(self.api.mdm_get_endpoint_by_mac_address(args[1]))
            if args[0]=="endpointsbytype":
                self.print_json(self.api.mdm_get_endpoints_by_type(args[1]))
            if args[0]=="endpointsbyos":
                self.print_json(self.api.mdm_get_endpoints_by_os_type(args[1]))
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_MDM)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_MDM,args[1],on_message)
        else:
            print("Invalid command. See help mdm")
    
    def do_system(self,line):
        """system options:
        healths [nodename] [starttime]: Retrieve health metrics. Optionally can be filtered by node.
            By default, last 1 hour of statistics is returned.
        perfs [nodename] [starttime]: Retrieve performance metrics. Optionally can be filtered by node.
            By default, last 1 hour of statistics is returned.
        """
        args=line.split()
        if line and args[0] in ["healths","perfs"]:
            if len(args)==2:
                node_name=args[1]
            else:
                node_name=None
            if len(args)==3:
                startTimestamp=args[2]
            else:
                startTimestamp=None
            if args[0]=="healths":
                self.print_json(self.api.system_get_healths(node_name,startTimestamp))
            if args[0]=="perfs":
                self.print_json(self.api.system_get_performances(node_name,startTimestamp))
        else:
            print("Invalid command. See help system")
    
    def do_profiler(self,line):
        """profiler options
            list: Retrive profiling policies
            topics: List topics available for subscription
            subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"list":1,"topics":1,"subscribe":2}
        args=line.split()
        if line and args[0] in valid_options and len(args)==valid_options[args[0]]:
            if args[0]=="list":
                self.print_json(self.api.profiler_get_profiles())
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_PROFILER)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_PROFILER,args[1],on_message)
        else:
            print("Invalid command. See help profiler")

    def do_radius(self,line):
        """radius options:
            list [id]: Retrieve RADIUS failure statistics. Otionally specify error code
            topics: List topics available for subscription
            subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"list":[1,2],"topics":[1],"subscribe":[2]}
        args=line.split()
        if line and args[0] in valid_options and len(args) in valid_options[args[0]]:
            if args[0]=="list":
                if len(args)==1:
                    self.print_json(self.api.radius_get_failures())
                else:
                    self.print_json(self.api.radius_get_failures_by_id(int(args[0])))
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_RADIUS)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_RADIUS,args[1],on_message)
        else:
            print("Invalid command. See help radius")

    def do_trustsec(self,line):
        """trustsec options:
        topics: List topics available for subscription
        subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"topics":1,"subscribe":2}
        args=line.split()
        if line and args[0] in valid_options and len(args)==valid_options[args[0]]:
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_TRUSTSEC)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_TRUSTSEC,args[1],on_message)
        else:
            self.print_json("Invalid command. See help trustsec")

    def do_trustseccfg(self,line):
        """trustseccfg options:
        sgt [id]: List all Security Group Tags. Optionally filter by ID
        sgacl [id]: List all SG Access Lists. Optionally filter by ID
        policies: List all Egress policies
        matrices: List all Egress matrices
        topics: List topics available for subscription
        subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"sgt":[1,2],"sgacl":[1,2],"policies":[1],"matrices":[1],"topics":[1],"subscribe":[2]}
        args=line.split()
        if line and args[0] in valid_options and len(args) in valid_options[args[0]]:
            if args[0]=="sgt":
                if len(args)==1:
                    self.print_json(self.api.trustsec_get_security_groups())
                else:
                    self.print_json(self.api.trustsec_get_security_groups(args[1]))
            if args[0]=="sgacl":
                if len(args)==1:
                    self.print_json(self.api.trustsec_get_security_group_acls())
                else:
                    self.print_json(self.api.trustsec_get_security_group_acls(args[1]))
            if args[0]=="policies":
                self.print_json(self.api.trustsec_get_egress_policies())
            if args[0]=="matrices":
                self.print_json(self.api.trustsec_get_egress_matrices())
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_TRUSTSECCFG)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_TRUSTSECCFG,args[1],on_message)
        else:
            print("Invalid command. See help trustseccfg")

    def do_sxp(self,line):
        """sxp options:
        bindings: List all SXP bindings
        topics: List topics available for subscription
        subscribe <topic>: Subscribe to a topic
        """
        def on_message(stomp_frame):
            self.print_json(stomp_frame.data)

        valid_options={"bindings":1,"topics":1,"subscribe":2}
        args=line.split()
        if line and args[0] in valid_options and len(args)==valid_options[args[0]]:
            if args[0]=="bindings":
                self.print_json(self.api.sxp_get_bindings())
            if args[0]=="topics":
                self.show_topics(self.api.SERVICE_SXP)
            if args[0]=="subscribe":
                self.api.topic_subscribe(self.api.SERVICE_SXP,args[1],on_message)
        else:
            print("Invalid command. See help sxp")

    def do_accountcreate(self,line):
        """Create password based account
        Client name (username) is take from config
        """
        if self.config["client_name"]=="" or self.config["px_node"]=="":
            print("client_name and px_node are require for this command. Use config command")
        else:
            self.api=PXAPI(self.config["px_node"],self.config["client_name"],"","",self.config["root_ca_file"])
            accountInfo=self.api.account_create()
            self.print_json(accountInfo)
            self.config["password"]=accountInfo["password"]
            print("Password automatically set in the config. Use config show to verify")

    
    def do_activate(self,line):
        """Activate will attempt to connect to pxGrid node and check if the client is approved
        wait parameter will retry activation every 60 seconds until the client is approved
        """
        if line in ["","wait"]:
            accountState=self.api.account_activate(line=="wait")
            self.print_json(accountState)
        else:
            print("Invalid command. See help config")

    def do_endpoint(self,line):
        """Post endpoint asset information using Context-In
        endpoint <json>. json must be in the format documented here: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Endpoint-Asset.
        The contents of the JSON data must be combined into a single line. Example:
        Source JSON: 
        {
            "opType": "CREATE",
            "asset": {
                "assetId": 1,
                "assetName": "IOT1",
                "assetIpAddress": "1.2.3.4",
                "assetMacAddress": "33:44:55:66:77:88",
                "assetVendor": "CL",
                "assetHwRevision": "1.0",
                "assetSwRevision": "2.0",
                "assetProtocol": "Telnet",
                "assetProductId": "Wifi-IOT",
                "assetSerialNumber": "ABC12345",
                "assetDeviceType": "WiFi",
                "assetConnectedLinks": [
                    {
                        "key": "wifi1",
                        "value": "ssid1"
                    }
                ]
            }
        }
        Command:
        endpoint {"opType": "CREATE","asset": {"assetId": 1,"assetName": "IOT1","assetIpAddress": "1.2.3.4","assetMacAddress": "33:44:55:66:77:88","assetVendor": "CL","assetHwRevision": "1.0","assetSwRevision": "2.0","assetProtocol": "Telnet","assetProductId": "Wifi-IOT","assetSerialNumber": "ABC12345","assetDeviceType": "WiFi","assetConnectedLinks": [{"key": "wifi1","value": "ssid1"}]}}
        """
        endpoint_data=json.dumps(json.loads(line))
        self.api.context_in(endpoint_data)

    def do_config(self,line):
        """Config options:
        save <file>: Save config to file
        load <file>: Load config from file
        apply [file]: Instatiate connection to pxGrid. Optionaly load the file and apply in one step
        show: Show current settings 
        pxnode <hostname>: Set pxGrid PSN FQDN
        name <clientname>: Set pxGrid client name
        cert <certfile>: Set client certificate file name
        key <keyfile>: Set client private key
        root [<rootfile>]: Set root CA file. Leave out <rootfile> to disable server certificate verification
        password <password>: Set password for password based authentication
        """
        valid_options={"save":[2],"load":[2],"show":[1],"pxnode":[2],"name":[2],"cert":[2],"key":[2],"root":[1,2],"password":[2],"apply":[1,2]}
        args=line.split()
        if args[0] in valid_options and len(args) in valid_options[args[0]]:
            if args[0]=="save":
                config_file=open(args[1],"w")
                config_file.write(json.dumps(self.config))
                config_file.close()
            if args[0]=="load":
                config_file=open(args[1],"r")
                self.config=json.loads(config_file.read())
                config_file.close()
            if args[0]=="show":
                self.print_json(self.config)
            if args[0]=="apply":
                if len(args)==2:
                    config_file=open(args[1],"r")
                    self.config=json.loads(config_file.read())
                    config_file.close()
                self.api=PXAPI(self.config["px_node"],self.config["client_name"],self.config["client_cert_file"],self.config["client_key_file"],self.config["root_ca_file"],self.config["password"])
                self.prompt=f"pxshell_{self.config['client_name']}_{self.config['px_node']}> "
            if args[0]=="pxnode":
                self.config["px_node"]=args[1]
            if args[0]=="name":
                self.config["client_name"]=args[1]
            if args[0]=="cert":
                self.config["client_cert_file"]=args[1]
            if args[0]=="key":
                self.config["client_key_file"]=args[1]
            if args[0]=="root":
                if len(args)==2:
                    self.config["root_ca_file"]=args[1]
                else:
                    self.config["root_ca_file"]=""
            if args[0]=="password":
                self.config["password"]=args[1]
        else:
            print("Invalid command. See help config")



    def do_debug(self,line):
        """enable verbose http and websocket messages"""
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    def do_EOF(self,line):
        return(True)
    
    def postloop(self):
        print("Good bye")

def main():
    PXShell().cmdloop()

if __name__=="__main__":
    main()
