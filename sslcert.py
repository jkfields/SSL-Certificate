#!/usr/bin/env python

from datetime import datetime
import re
from subprocess import Popen, PIPE
from pprint import PrettyPrinter

PP = PrettyPrinter(indent=2)

""" TO DO:  Move to config file """
S_CLIENT = "/usr/bin/openssl s_client -connect {url}:{port} -{protocol}"
X509 = "/usr/bin/openssl x509 -noout -text"
PING = "/sbin/ping -p {port} -c 1 {host}"

RSA_OID = { '1.2.840.113549.1.1.1' : 'rsaEncryption',
            '1.2.840.113549.1.1.2' : 'md2WithRSAEncryption',
            '1.2.840.113549.1.1.3' : 'md4WithRSAEncryption',
            '1.2.840.113549.1.1.4' : 'md5WithRSAEncryption',
            '1.2.840.113549.1.1.5' : 'sha1-with-rsa-signature',
            '1.2.840.113549.1.1.11' : 'sha256WithRSAEncryption',
            '1.2.840.113549.1.1.12' : 'sha384WithRSAEncryption',
            '1.2.840.113549.1.1.13' : 'sha512WithRSAEncryption',
            '1.2.840.113549.1.1.14' : 'sha224WithRSAEncryption' }

""" END """
            
class CertificateParsingError(Exception):
    pass
    
class HostNotAvailableError(Exception):
    pass
    
class SslCertificate:
    cert_text = ""
    cert_fields = {}
    available = False
    
    def __init__(self, kwargs):
        self.url = kwargs.get('url', 'localhost')
        self.port = kwargs.get('port', 443)
        self.protocol = kwargs.get('protocol', 'tls1')
        
        cmd = PING.format(port=self.port,
                          host=self.url)
        pr = Popen(cmd.split(),
                   shell=False,
                   stdin=PIPE,
                   stdout=PIPE)
        
        out,err = pr.communicate()
        self.available = pr.returncode == 0
        
    def retrieve(self):
        if self.available:
            cmd =  S_CLIENT.format(url=self.url,
                                   port=self.port,
                                   protocol=self.protocol)
        
            with open("/dev/null", "r") as fh:
                pr_cert = Popen(cmd.split(),
                                shell=False,
                                stdin=fh,
                                stdout=PIPE,
                                stderr=PIPE)
            pr_text = Popen(X509.split(),
                            shell=False,
                            stdin=pr_cert.stdout,
                            stdout=PIPE,
                            stderr=PIPE)
            self.cert_text,err = pr_text.communicate()                
    
            if err or pr_text.returncode != 0:
                raise CertificateParsingError
        else:
            raise HostNotAvailable
            
    def parse_cert_text(self):
        try:
            __algo = re.search("\s*Signature Algorithm\s*:\s*(.*)", self.cert_text).groups()[0]
            self.cert_fields['signing_algorithm'] = RSA_OID.get(__algo, __algo)
            
            __issuer = re.search("\s*Issuer.*CN=\s*(.*)", self.cert_text)
            self.cert_fields['issuer'] = __issuer.groups()[0]
            
            __subject = re.search("\s*Subject.*CN=\s*(.*)", self.cert_text)
            self.cert_fields['subject'] = __subject.groups()[0]
            
            self.cert_fields['self_signed'] = __issuer == __subject
                        
            __end = re.search("\s*Not After\s*:\s*(.*)", self.cert_text)       
            self.cert_fields['enddate'] = __end.groups()[0]
            
            __start = re.search("\s*Not Before\s*:\s*(.*)", self.cert_text)       
            self.cert_fields['startdate'] = __start.groups()[0]
            
            __serial = re.search("\s*Serial Number\s*:\s*(.*)", self.cert_text)       
            self.cert_fields['serial'] = __serial.groups()[0]
            
            __vers = re.search("\s*Version\s*:\s*(.*)", self.cert_text)       
            self.cert_fields['version'] = __vers.groups()[0]
            
            regex = re.compile("\s*Subject\s+Alternative\s+Name\s*:\W(?:\n|\r\n?)\s*(.*)", re.MULTILINE)
            match = regex.search(self.cert_text)
            if match:   
                self.cert_fields['san'] = match.groups()[0].replace(' Address', '')
                 
            regex = re.compile("\s*Extended\s+Key\s+Usage\s*:\W(?:\n|\r\n?)\s*(.*)", re.MULTILINE)
            match = regex.search(self.cert_text)
            if match:  self.cert_fields['extended_key_usage'] = match.groups()[0]                 
            
        except Exception as err:
            raise CertificateParsingError(str(err))

    @property
    def isSelfSigned(self):
        return self.cert_fields.get('self_signed')
        
    def dtToIsoDate(self, dt):
        return datetime.strptime(dt, "%b %d %H:%M:%S %Y %Z").isoformat()
        

def main():
    kwargs = { "url" : "www.yahoo.com",
               "port" : 443,
               "protocol" : "tls1" }
               
    cert = SslCertificate(kwargs)
    cert.retrieve()
    cert.parse_cert_text()
        
    PP.pprint(cert.cert_fields)
    print("Self-signed: " + str(cert.isSelfSigned))
    print("available: " + str(cert.available))
        
        
if __name__ == '__main__':
    main()             
