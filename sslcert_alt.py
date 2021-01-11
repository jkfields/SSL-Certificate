#!/usr/bin/env python

"""
Program: SSL Certificate Information <sslcert_alt.py>

Author: Jeff < jkfields at yahoo dot com >

Last Updated: 1-10-2021

Revision History:
  Version 1.0 - Initial release
"""

import ssl
import socket
from pprint import PrettyPrinter
from datetime import datetime

pp = PrettyPrinter(indent=2)
hostname = "www.google.com"
port = 443
cert_datefmt = "%b %d %H:%M:%S %Y %Z"

try:
    ctx = ssl.create_default_context()
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET),
                           server_hostname=hostname)
    conn.connect((hostname, port))
    cert_fields = conn.getpeercert()

except Exception as err:
    raise SystemExit(str(err))
    
print("Expires : " + datetime.strptime(cert_fields['notAfter'], cert_datefmt).isoformat())
"""
print(cert_fields.get('subjectAltName'))
print(cert_fields.get('issuer'))
print(cert_fields.get('subject'))
"""
pp.pprint(cert_fields)
