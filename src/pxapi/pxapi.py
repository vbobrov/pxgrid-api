#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
#
import requests
import time
import re
import ipaddress
import websocket
import ssl
import base64
from dateutil import parser
from .stompframe import StompFrame

HTTP_GET="GET"
HTTP_POST="POST"

class PXAPI:
    SERVICE_ANC="com.cisco.ise.config.anc"
    SERVICE_SESSION="com.cisco.ise.session"
    SERVICE_ENDPOINT="com.cisco.endpoint.asset"
    SERVICE_MDM="com.cisco.ise.mdm"
    SERVICE_PROFILER="com.cisco.ise.config.profiler"
    SERVICE_RADIUS="com.cisco.ise.radius"
    SERVICE_SYSTEM="com.cisco.ise.system"
    SERVICE_TRUSTSEC="com.cisco.ise.trustsec"
    SERVICE_TRUSTSECCFG="com.cisco.ise.config.trustsec"
    SERVICE_SXP="com.cisco.ise.sxp"
    SERVICE_CONTEXTIN="com.cisco.endpoint.asset"
    SERVICE_PUBSUB="com.cisco.ise.pubsub"

    def __init__(self,px_node,client_name,client_cert_file=None,client_key_file=None,root_ca_file=False,password=None):
        """Initialize class

        :param px_node: FQDN of pxGrid PSN
        :param client_name: Name that will show up in pxGrid clients list in ISE
        :param client_cert_file: File name containing client certificate
        :param client_key_file: File name containing private key. Encrypted key is not supported
        :param root_ca_file: File name containing root CA for pxGrid PSN certificate.
                    If root CA is not specified, server certificate validation is disabled.
        :param node_name: Client name when using password based authentication
        :param password: Password when using password based authentication
        """
        self.px_node=px_node
        self.client_name=client_name
        self.client_cert_file=client_cert_file
        self.client_key_file=client_key_file
        self.password=password
        if root_ca_file:
            self.root_ca_file=root_ca_file
        else:
            self.root_ca_file=False

    def __is_valid_ip(self,ip):
        """Check if IP Address is valid

        :param ip: string containing the IP Address
        :return: boolean if IP Address is in the right format
        """
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return(False)
        return(True)
    
    def __is_valid_mac(self,mac):
        """Check if MAC Address is valid

        :param mac: string containing the MAC Address
        :return: boolean if MAC address is the correct format
        """
        return(re.search(r"^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$",mac,re.IGNORECASE))
    
    def __check_ip(self,ip):
        """Raise an exception if IP Address is not valid

        :param ip: string containing the IP Address
        """
        if not self.__is_valid_ip(ip):
            raise Exception(f"Invalid IP Address: {format(ip)}")
    
    def __check_mac(self,mac):
        """Raise an exception if MAC Address is not valid

        :param mac: string containing the MAC Address
        """
        if not self.__is_valid_mac(mac):
            raise Exception(f"Invalid MAC Address (must be HH:HH:HH:HH:HH:HH) {format(mac)}")

    def __send_http_request(self,request_type,url,username,password,data={},headers={},**kwargs):
        """Send HTTP request

        :param request_type: string containing GET or POST
        :param url: url for the request
        :param username: basic auth username
        :param password: basic auth password
        :param data: (optional) dict containing data to be in the body of the request
        :param headers: (optional) headers to be included in the request
        :param \*\*kwargs: additional arguments

        :Keyword Arguments:
            skipauth: (boolean) if true username and password are not included in the request
        """
        http_params={}
        if self.client_cert_file and self.client_key_file:
            http_params.update({"cert": (self.client_cert_file,self.client_key_file)})
        if not kwargs.get("skipauth"):
            http_params.update({"auth": (username,password)})
        if request_type==HTTP_GET:
            response=requests.get(url,	headers=headers,
                                        verify=self.root_ca_file,
                                        **http_params)
            return(response)
        if request_type==HTTP_POST:
            response=requests.post(url, json=data,
                                        headers=headers,
                                        verify=self.root_ca_file,
                                        **http_params)
            return(response)
        raise Exception(f"sendHTTPRequest: Unknown Request Type {format(request_type)}")
    
    def __send_px_request(self,service,data={},**kwargs):
        """Send pxGrid request

        :param service: pxGrid service name
        :param data: dict containing service-specific data to be sent
        :param \*\*kwargs: additional keywords to be passed to __send_http_request
        """
        url=f"https://{self.px_node}:8910/pxgrid/control/{service}"
        if self.client_cert_file and self.client_key_file:
            password=None
        else:
            password=self.password
        response=self.__send_http_request(HTTP_POST,url,self.client_name,password,data,**kwargs)
        if response.status_code==200:
            return(response.json())
        raise Exception(f"Request {service} failed with code {response.status_code}. Content: {response.text}")
    
    def __send_px_api(self,service,api,data={},**kwargs):
        """Execute pxGrid API

        :param service: pxGrid service name
        :param api: name of the API
        :param data: dict containing service-specific data to be sent
        :param \*\*kwargs: additional keywords to be passed to __send_http_request
        """
        service_info=self.service_lookup(service)
        node_name=service_info["services"][0]["nodeName"]
        rest_base_url=service_info["services"][0]["properties"]["restBaseUrl"]
        secret=self.get_access_secret(node_name)
        url=f"{rest_base_url}/{api}"
        response=self.__send_http_request(HTTP_POST,url,self.client_name,secret,data,**kwargs)
        if response.status_code==200:
            try:
                return(response.json())
            except:
                return({})
        if response.status_code==204:
            return({})
        raise Exception(f"API {api} to service {service} failed with code {response.status_code}. Content: {response.text}")

    def topic_subscribe(self,service,topic,callback):
        """Subscribe to topic

        :param service: name of pxGrid service
        :param topic: name of topic to subscribe to
        :param on_message: callback function that is called every time a websocket message is received
        """
        def on_message(wsapp,message,callback):
            callback(StompFrame.parse_packet(message))

        def on_open(wsapp,node_name,topic):
            wsapp.send(StompFrame("CONNECT",{"accept-version":"1.2","host":node_name}).get_frame(),websocket.ABNF.OPCODE_BINARY)
            wsapp.send(StompFrame("SUBSCRIBE",{"destination":topic,"id":"pxapi"}).get_frame(),websocket.ABNF.OPCODE_BINARY)   
        
        service_info=self.service_lookup(service)
        topic=service_info["services"][0]["properties"][topic]
        pubsub_info=self.service_lookup(service_info["services"][0]["properties"]["wsPubsubService"])
        node_name=pubsub_info["services"][0]["nodeName"]
        ws_url=pubsub_info["services"][0]["properties"]["wsUrl"]
        secret=self.get_access_secret(node_name)
        ssl_context=ssl.create_default_context()
        print("test")
        if self.client_cert_file and self.client_key_file:
            ssl_context.load_cert_chain(certfile=self.client_cert_file,keyfile=self.client_key_file)
        if self.root_ca_file:
            ssl_context.load_verify_locations(cafile=self.root_ca_file)
        wsapp=websocket.WebSocketApp(ws_url,
            on_message=lambda wsapp,message: on_message(wsapp,message,callback),
            on_open=lambda wsapp: on_open(wsapp,node_name,topic),
            header={"Authorization": "Basic "+base64.b64encode((f"{self.client_name}:{secret}").encode()).decode()}
        )
        print("Press ^C to interrupt")
        try:
            wsapp.run_forever(sslopt={"context": ssl_context})
        except KeyboardInterrupt:
            print("^C pressed. Exiting")

    def context_in(self,asset_data):
        """Sent data via Context-In\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Endpoint-Asset

        :param asset_data: dict containing data as documented here: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Endpoint-Asset
        """
        self.service_register(self.SERVICE_CONTEXTIN,{
            "wsPubsubService": "com.cisco.ise.pubsub",
            "assetTopic":"/topic/com.cisco.endpoint.asset"
        })
        pubsub_info=self.service_lookup(self.SERVICE_PUBSUB)
        node_name=pubsub_info["services"][0]["nodeName"]
        ws_url=pubsub_info["services"][0]["properties"]["wsUrl"]
        secret=self.get_access_secret(node_name)
        ssl_context=ssl.create_default_context()
        if self.client_cert_file and self.client_key_file:
            ssl_context.load_cert_chain(certfile=self.client_cert_file,keyfile=self.client_key_file)
        if self.root_ca_file:
            ssl_context.load_verify_locations(cafile=self.root_ca_file)        
        ws=websocket.create_connection(ws_url,
            sslopt={"context": ssl_context},
            header={"Authorization": "Basic "+base64.b64encode((f"{self.client_name}:{secret}").encode()).decode()}
        )
        ws.send(StompFrame("CONNECT",{"accept-version":"1.2","host":node_name}).get_frame(),websocket.ABNF.OPCODE_BINARY)
        ws.send(StompFrame("SEND",{"destination":"/topic/com.cisco.endpoint.asset"},asset_data).get_frame(),websocket.ABNF.OPCODE_BINARY)
        ws.close()

    def account_create(self):
        """Creates a username for password based access\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#accountcreate

        :return: dict with new account information
        """
        return(self.__send_px_request("AccountCreate",{"nodeName": self.client_name},skipauth=True))
    
    def account_activate(self,wait=False):
        """Activate pxGrid Account in ISE\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#accountactivate

        :param wait: if set to True, the API call will retry every 60 seconds until the account is approved in ISE
        :return: dict containing account status
        """
        while True:
            account_state=self.__send_px_request("AccountActivate",{})
            if not wait or account_state["accountState"]=="ENABLED":
                return(account_state)
            time.sleep(60)
    
    def service_lookup(self,service):
        """Looks up pxGrid service information\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#servicelookup

        :param service: name of pxGrid service
        :return: dict containing service information
        """
        return(self.__send_px_request("ServiceLookup",{"name":service}))

    def service_register(self,service,properties):
        """Register pxGrid service\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Provider#serviceregister

        :param service: name of new service
        :param properties: Service properties
        """
        return(self.__send_px_request("ServiceRegister",{"name":service,"properties":properties}))

    def get_access_secret(self,peer_node_name):
        """Retrieve Access Secret to communicate to a pxGrid node\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/pxGrid-Consumer#accesssecret

        :param peer_node_name: Name of the remote node
        :return: node secret
        """
        return(self.__send_px_request("AccessSecret",{"peerNodeName":peer_node_name})["secret"])
    
    def get_sessions(self):
        """Retrieve all active sessions\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#post-restbaseurlgetsessions

        :return: dict containing all sessions
        """
        return(self.__send_px_api(self.SERVICE_SESSION,"getSessions"))
    
    def get_session_by_ip_address(self,ip):
        """Retrieve active session by IP Address\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#post-restbaseurlgetsessionbyipaddress

        :param ip: endpoint IP Address
        :return: dict containing all sessions for the IP Address
        """
        self.__check_ip(ip)
        return(self.__send_px_api(self.SERVICE_SESSION,"getSessionByIpAddress",{"ip":ip}))

    def get_session_by_mac_address(self,mac):
        """Retrieve active session by MAC Address\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#post-restbaseurlgetsessionbymacaddress

        :param mac: endpoint MAC Address
        :return: dict containing all sessions for the MAC Address
        """
        self.__check_mac(mac)
        return(self.__send_px_api(self.SERVICE_SESSION,"getSessionByMacAddress",{"macAddress":mac}))

    def get_user_groups(self):
        """Retrieve all user to group assignments\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#post-restbaseurlgetusergroups

        :return: dict of all user groups
        """
        return(self.__send_px_api(self.SERVICE_SESSION,"getUserGroups"))

    def get_user_group_by_username(self,username):
        """Retries group assignment for a specific user\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Session-Directory#post-restbaseurlgetusergroupbyusername

        :param username: username of the user
        :return: dict of all groups that the user belongs to
        """
        return(self.__send_px_api(self.SERVICE_SESSION,"getUserGroupByUserName",{"userName":username}))
    
    def anc_get_policies(self):
        """Retrieve all ANC Policies\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlgetpolicies

        :return: dict of all ANC policies
        """
        return(self.__send_px_api(self.SERVICE_ANC,"getPolicies"))

    def anc_get_policy_by_name(self,name):
        """Retrieve ANC Policy by name\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlgetpolicybyname

        :param name: name of ANC Policy
        :return: dict containing policy information
        """
        return(self.__send_px_api(self.SERVICE_ANC,"getPolicyByName",{"name":name}))
    
    def anc_create_policy(self,name,actions):
        """Create ANC Policy\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlcreatepolicy
        
        :param name: name of ANC Policy
        :param actions: Action that ISE will perform and ANC policy is assigned.
            Valid options: QUARANTINE, SHUT_DOWN or PORT_BOUNCE
        :return: dict containing policy information
        """
        if not actions in ["QUARANTINE","SHUT_DOWN","PORT_BOUNCE"]:
            raise Exception(f"Invalid action {format(actions)}. Valid options: QUARANTINE, SHUT_DOWN or PORT_BOUNCE")
        return(self.__send_px_api(self.SERVICE_ANC,"createPolicy",{"name":name,"actions":[actions]}))
        
    def anc_delete_policy_by_name(self,name):
        """Delete ANC Policy\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurldeletepolicybyname

        :param name: name of ANC Policy
        """
        return(self.__send_px_api(self.SERVICE_ANC,"deletePolicyByName",{"name":name}))

    def anc_get_endpoints(self):
        """Retrive all endpoints assigned to ANC Policies\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlgetendpoints

        :return: dict of ANC Policy assignments
        """
        return(self.__send_px_api(self.SERVICE_ANC,"getEndpoints"))

    def anc_get_endpoint_by_mac_address(self,mac):
        """Retrieve ANC Policy assignment by MAC Address\n
        Reference https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlgetendpointbymacaddress

        :param mac: MAC Address of the endpoint
        :return: dict of ANC Policy assigned to MAC Address
        """
        self.__check_mac(mac)
        return(self.__send_px_api(self.SERVICE_ANC,"getEndpointByMacAddress",{"macAddress":mac}))
    
    
    def anc_get_endpoint_policies(self):
        """Retrieves endpoint to ANC Policy assignments based on MAC Address and NAS-IP-Address\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlgetendpointpolicies-since-ise-26p7-27p2-30

        :return: dict with ANC Policy assigned to a MAC Address and NAS-IP-Address
        """
        return(self.__send_px_api(self.SERVICE_ANC,"getEndpointPolicies"))
    
    def anc_get_endpoint_by_nas_ip_address(self,mac,nas_ip):
        """Retrieves endpoint to ANC Policy assignments based on MAC Address and NAS-IP-Address\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlgetendpointbynasipaddress-since-ise-26p7-27p2-30
        
        :param mac: endpoint MAC Address
        :param nas_ip: device IP Address
        :return: dict with ANC Policy assigned to a MAC Address and NAS-IP-Address
        """
        self.__check_mac(mac)
        self.__check_ip(nas_ip)
        return(self.__send_px_api(self.SERVICE_ANC,"getEndpointByNasIpAddress",{"macAddress":mac,"nasIpAddress":nas_ip}))

    def anc_apply_endpoint_by_mac_address(self,policy,mac):
        """Apply ANC Policy by MAC Address. Endpoint does not need to be online.\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlapplyendpointbymacaddress
        
        :param policy: name of ANC Policy
        :param mac: MAC Address of endpoint
        """
        self.__check_mac(mac)
        return(self.__send_px_api(self.SERVICE_ANC,"applyEndpointByMacAddress",{"policyName":policy,"macAddress":mac}))

    def anc_apply_endpoint_by_ip_address(self,policy,ip):
        """Apply ANC Policy by IP Address. Requires that the endpoint is connected to the network.\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlapplyendpointbyipaddress

        :param policyName: name of ANC Policy
        :param ip: IP Address of endpoint
        """
        self.__check_ip(ip)
        return(self.__send_px_api(self.SERVICE_ANC,"applyEndpointByIpAddress",{"policyName":policy,"ip":ip}))

    def anc_apply_endpoint_policy(self,policy,mac,nas_ip):
        """Apply ANC Policy by MAC Address and NAS-IP-Address. Endpoint does not need to be connected to the network.\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlapplyendpointpolicy-since-ise-26p7-27p2-30

        :param policy: name of ANC Policy
        :param mac: MAC Address of endpoint
        :param nas_ip: device IP Address
        """
        self.__check_mac(mac)
        self.__check_ip(nas_ip)
        return(self.__send_px_api(self.SERVICE_ANC,"applyEndpointPolicy",{"policyName":policy,"macAddress":mac,"nasIpAddress":nas_ip}))

    def anc_clear_endpoint_by_mac_address(self,mac):
        """Clear ANC Policy from endpoint by MAC Address\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlclearendpointbymacaddress

        :param mac: MAC Address of endpoint
        """
        self.__check_mac(mac)
        return(self.__send_px_api(self.SERVICE_ANC,"clearEndpointByMacAddress",{"macAddress":mac}))
    
    def anc_clear_endpoint_policy(self,mac,nas_ip):
        """Clear ANC Policy from endpoint by MAC Address and NAS-IP-Address\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlclearendpointpolicy-since-ise-26p7-27p2-30

        :param mac: MAC Address of endpoint
        :param nas_ip: device IP Address
        """
        self.__check_mac(mac)
        self.__check_ip(nas_ip)
        return(self.__send_px_api(self.SERVICE_ANC,"clearEndpointPolicy",{"macAddress":mac,"nasIpAddress":nas_ip}))

    def anc_get_operation_status(self,operation_id):
        """Get status of an ongoing ANC operation\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/ANC-configuration#post-restbaseurlgetoperationstatus

        :param operation_id: Operation ID to look up
        :return: dict containing operation status
        """
        return(self.__send_px_api(self.SERVICE_ANC,"getOperationStatus",{"operationId":operation_id}))

    def mdm_get_endpoints(self):
        """Retrieve all MDM endpoints and their MDM attributes\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/MDM#post-restbaseurlgetendpoints

        :return: dict with all endpoints with MDM attributes
        """
        return(self.__send_px_api(self.SERVICE_MDM,"getEndpoints"))
    
    def mdm_get_endpoint_by_mac_address(self,mac):
        """Retrieve MDM status of an endpoint based on MAC Address\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/MDM#post-restbaseurlgetendpointbymacaddress

        :param mac: MAC Address of endpoint
        :return: dict with MDM attributes of the specified MAC Address
        """
        self.__check_mac(mac)
        return(self.__send_px_api(self.SERVICE_MDM,"getEndpointByMacAddress",{"macAddress":mac}))
    
    def mdm_get_endpoints_by_type(self,mdm_type):
        """Retrive MDM endpoints by type\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/MDM#post-restbaseurlgetendpointsbytype

        :param mdm_type: Valid options are NON_COMPLIANT, REGISTERED or DISCONNECTED
        :return: dict with MDM endpoints for the specified type
        """
        if not mdm_type in ["NON_COMPLIANT","REGISTERED","DISCONNECTED"]:
            raise Exception(f"Invalid type {mdm_type}. Valid options: NON_COMPLIANT, REGISTERED or DISCONNECTED")
        return(self.__send_px_api(self.SERVICE_MDM,"getEndpointsByType",{"type":mdm_type}))
    
    def mdm_get_endpoints_by_os_type(self,os_type):
        """Retrive MDM endpoints by OS type\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/MDM#post-restbaseurlgetendpointsbyostype

        :param os_type: valid options are ANDROID, IOS or WINDOWS
        :return: dict with MDM endpoinst for the specified OS
        """
        if not os_type in ["ANDROID","IOS","WINDOWS"]:
            raise Exception(f"Invalid OS type {os_type}. Valid options: ANDROID, IOS or WINDOWS")
        return(self.__send_px_api(self.SERVICE_MDM,"getEndpointsByOsType",{"osType":os_type}))

    def profiler_get_profiles(self):
        """Retrive all profiles\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Profiler-configuration#post-restbaseurlgetprofiles

        :return: dict with all profiling policies
        """
        return(self.__send_px_api(self.SERVICE_PROFILER,"getProfiles"))

    def radius_get_failures(self,start_time=None):
        """Retrieve RADIUS failure statistics\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Radius-Failure#post-restbaseurlgetfailures

        :param start_time: (optional) specify a longer time range. By default, last 1 hour of statistics is retrieved.
        :return: dict of RADIUS failures
        """
        data={}
        if start_time:
            data["startTimestamp"]=parser.parse(start_time).astimezone().isoformat()
        return(self.__send_px_api(self.SERVICE_RADIUS,"getFailures",data))

    def radius_get_failures_by_id(self,id):
        """Retrieve RADIUS failures by ID\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/Radius-Failure#post-restbaseurlgetfailurebyid

        :param id: RADIUS code to retrieve
        :return: dict of RADIUS failures for the specified ID
        """
        return(self.__send_px_api(self.SERVICE_RADIUS,"getFailureById",{"id":id}))

    def system_get_healths(self,node_name=None,start_time=None):
        """Retrieve system health statistics\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/System-Health#post-restbaseurlgethealths

        :param node_name: (ptional) filter by a specific ISE node
        :param start_time: (optional) specify a longer time range. By default, last 1 hour of statistics is retrieved.
        :return: dict of health statistics
        """
        data={}
        if node_name:
            data["nodeName"]=node_name
        if start_time:
            data["startTimestamp"]=parser.parse(start_time).astimezone().isoformat()
        return(self.__send_px_api(self.SERVICE_SYSTEM,"getHealths",data))

    def system_get_performances(self,node_name=None,start_time=None):
        """Retrieve system performance statistics\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/System-Health#post-restbaseurlgetperformances

        :param node_name: (ptional) filter by a specific ISE node
        :param start_time: (optional) specify a longer time range. By default, last 1 hour of statistics is retrieved.
        :return: dict of performance statistics
        """
        data={}
        if node_name:
            data["nodeName"]=node_name
        if start_time:
            data["startTimestamp"]=parser.parse(start_time).astimezone().isoformat()
        return(self.__send_px_api(self.SERVICE_SYSTEM,"getPerformances",data))

    def trustsec_get_security_groups(self,id=None):
        """Retrieve Trustsec SGTs\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/TrustSec-configuration#post-restbaseurlgetsecuritygroups

        :param id: (optional) filter by ID
        :return: dict of security groups
        """
        data={}
        if id:
            data["id"]=id
        return(self.__send_px_api(self.SERVICE_TRUSTSECCFG,"getSecurityGroups",data))

    def trustsec_get_security_group_acls(self,id=None):
        """Retrieve Trustsec ACLs\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/TrustSec-configuration#post-restbaseurlgetsecuritygroupacls

        :param id: (optional) filter by ID
        :return: dict of SG ACLs
        """
        data={}
        if id:
            data["id"]=id
        return(self.__send_px_api(self.SERVICE_TRUSTSECCFG,"getSecurityGroupAcls",data))

    def trustsec_get_virtual_network(self,id=None,start_index=None,record_count=None,start_timestamp=None,end_timestamp=None):
        """Get Virtual Networks\n
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/TrustSec-configuration#post-restbaseurlgetvirtualnetwork

        :param id: (optional) filter by ID
        :param start_index: (optional) first index of the VN to be retrieved
        :param record_count: (optional) limit how many records are returned
        :param start_timestamp: (optional) retrieve VNs that were delete between start_timestamp and end_timestamp
        :param end_timestamp: (optional) retrieve VNs that were delete between start_timestamp and end_timestamp
        :return: dict of Virtual Networks
        """
        data={}
        if id:
            data["id"]=id
        if start_index:
            data["startIndex"]=int(start_index)
        if record_count:
            data["recordCount"]=int(record_count)
        if start_timestamp and end_timestamp:
            data["startTimestamp"]=parser.parse(start_timestamp).astimezone().isoformat()
            data["endTimestamp"]=parser.parse(start_timestamp).astimezone().isoformat()
        return(self.__send_px_api(self.SERVICE_TRUSTSECCFG,"getVirtualNetwork"),data)
        
    def trustsec_get_egress_policies(self):
        """Retrive all Trustsec egress policies
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/TrustSec-configuration#post-restbaseurlgetegresspolicies

        :return: dict of all egress policies
        """
        return(self.__send_px_api(self.SERVICE_TRUSTSECCFG,"getEgressPolicies"))
    
    def trustsec_get_egress_matrices(self):
        """Retrieve all Trustsec egress matrices
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/TrustSec-configuration#post-restbaseurlgetegressmatrices

        :return: dict of all egress matrices
        """
        return(self.__send_px_api(self.SERVICE_TRUSTSECCFG,"getEgressMatrices"))

    def sxp_get_bindings(self):
        """Retrieve all SXP bindings
        Reference: https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki/TrustSec-SXP#post-restbaseurlgetbindings

        :return: dict of all SXP bindings
        """
        return(self.__send_px_api(self.SERVICE_SXP,"getBindings"))
