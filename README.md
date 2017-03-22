# Clone-Cert
This script takes as input a certificate, and clones the certificate and all signer certificates in the chain. 
Assume the following certificate chain:
A
|
+--B
   |
   +--C
Where A is a root CA, B is an intermediate CA and C is the end entity certificate. You don't necessarily have the private key to any of these.
If the script is called with the thumbprint of C, it will clone A into Aclone (same properties, different public and private key obviously), 
clone B and sign Bclone with the private key of Aclone, and finally clone C and sign Cclone with the private key of Bclone.
For Cclone to be trusted on the system, the Aclone certificate must be placed in the Trusted Root Certificate Authorities of the currentuser or localmachine store.
The certificates to clone must reside somewhere in the cert:\ store.
The script will save the certificates in the cert:\currentuser\my store (viewable in certmgr.msc as "Personal\Certificates").
