Introduction
============

This repo includes two components:
- A python API library making it easier to interact with pxGrid services on ISE
- Interactive CLI utility to interface with pxGrid without writing any code

pxGrid requires FQDNs of all the nodes to be resolvable. It is not possible to use the library or the CLI utility to connect to ISE via IP address, even if there's just one node. Hosts record will work as well.

Features
--------

- Support for both certificate and password authentication when connecting to pxGrid nodes
- Commands and methods to interact with most pxGrid services
- Websocket support for subscribing to topics.
- Debug capabilities to show all low level interactions with pxGrid

Limitations
-----------

- pxGrid API 2.0 only. No support for 1.0
- Private key must be unencrypted
- No support for Dynamic Topics
- Websockets (subscribing to topics) require that the pxGrid node certificate is trusted

Additonal reference material
----------------------------

- https://github.com/cisco-pxgrid/pxgrid-rest-ws/wiki
- https://developer.cisco.com/docs/pxgrid/
- https://developer.cisco.com/codeexchange/github/repo/cisco-pxgrid/python-advanced-examples
