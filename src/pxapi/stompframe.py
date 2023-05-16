#
# Copyright (c) 2023 Cisco Systems, Inc. and/or its affiliates
#
import json

class StompFrame:
    def __init__(self,command,headers,data=""):
        """Initializes class

        :param command: STOMP command
        :param headers: dict object will headers for the frame
        :param data: (optional) string containing the data to be included in the frame

        """
        self.command=command
        self.headers=headers
        if data!="":
            self.headers["content-length"]=str(len(data))
        self.data=data

    
    def get_frame(self):
        """Returns a binary string containing the raw STOMP frame

        :return: binary string containing raw STOMP frame
        """
        frame=self.command+"\n"
        for key in self.headers:
            frame=frame+key+":"+self.headers[key]+"\n"
        frame=frame+"\n"
        if self.data!="":
            frame=frame+json.dumps(self.data)
        frame=frame+"\x00"
        return(frame.encode("utf-8"))

    @staticmethod
    def parse_packet(packet):
        """Parses a binary string containing raw STOMP frame and returns StompFrame object

        :param packet: binary string containing raw STOMP packet
        :return: StompFrame class
        """
        lines=packet.decode("utf-8").split("\n")
        command=lines[0]
        headers={}
        for lineNum in range (1,len(lines)-2):
            header=lines[lineNum].split(":")
            headers[header[0]]=header[1]
        data=lines[-1].replace("\x00","")
        return(StompFrame(command,headers,data))