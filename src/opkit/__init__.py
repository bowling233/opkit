"""opkit — a session-oriented layer between AI agents and machines.

Every machine exposes management surfaces over some protocol: an SSH CLI,
a WebUI behind vendor login pages, a Redfish service on a BMC. As long as
something speaks a protocol, an agent can connect to it, operate it, and
control it. opkit provides that connection: protocol backends own the
credentials and the wire conversation, agents get typed tools over MCP.
"""

__version__ = "0.2.0"
