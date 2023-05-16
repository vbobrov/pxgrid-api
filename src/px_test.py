import json
from pxapi import PXAPI

def on_message(stomp_frame):
    print(f"Command: {stomp_frame.command}")
    print(f"Headers: {json.dumps(stomp_frame.headers,indent=2)}")
    try:
        print(f"Data: {json.dumps(stomp_frame.data,indent=2)}")
    except:
        pass

px=PXAPI("vb-cl-ise-px1.ciscodemo.net","pxgrid-client",".pxgrid-client.crt",".pxgrid-client.key",".demo-ca.cer")

with open(".endpoint.json","r") as f:
    endpoint=json.loads(f.read())
    px.context_in(endpoint)
#quit()
print(px.get_sessions())
print(px.account_activate())
px.topic_subscribe("com.cisco.ise.session","sessionTopic",on_message)
