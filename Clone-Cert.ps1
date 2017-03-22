<#
.SYNOPSIS
Clones a certificate and its signers

.DESCRIPTION
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


.PARAMETER CertToCloneThumbprint
Input the thumbprint of the certificate you want to clone. The thumbprint can have spaces in it.

.PARAMETER ExcludeThumbprint
When the script builds its certificate chain, it looks for the issuer name of the certificate to clone in the certificate stores.
If it finds two certificates with different thumbprint but same subject name, the script cannot determine which one to choose (no, I don't do public key verifying).
Use certmgr.msc to find the correct thumbprint of the issuer certificate in question, and use this parameter to exclude the thumbprints that matches the subject name but is not
used to sign the certificate which should be cloned. Yes, I know, this was a bit heavy.


.EXAMPLE

Clone-Cert.ps1 -Host -CertToCloneThumbprint "da fa f7 fa 66 84 ec 06 8f 14 50 bd c7 c2 81 a5 bc a9 64 56" -ExcludeThumbprint "ba ce ca ce 66 84 ec 06 8f 14 50 bd c7 c2 81 a5 bc a9 64 57","deadbeeffa6684ec068f1450bdc7c281a5bfeed7e"
This will clone the certificate with thumbprint starting with "da fa" and exclude two thumbprints ("ba ce.." and "dead..") when searching for signer certificate.


#>

Param([Parameter(Mandatory=$true,Position=0)][string]$CertToCloneThumbprint,[string[]]$ExcludeThumbprint) 
$ErrorActionPreference="stop"
$totalcerts=@()

# Why? Because the world has not enough logos.
$logo=@'

 ____    ___                                    ____                   __      
/\  _`\ /\_ \                                  /\  _`\                /\ \__   
\ \ \/\_\//\ \     ___     ___      __         \ \ \/\_\     __   _ __\ \ ,_\  
 \ \ \/_/_\ \ \   / __`\ /' _ `\  /'__`\ _______\ \ \/_/_  /'__`\/\`'__\ \ \/  
  \ \ \L\ \\_\ \_/\ \L\ \/\ \/\ \/\  __//\______\\ \ \L\ \/\  __/\ \ \/ \ \ \_ 
   \ \____//\____\ \____/\ \_\ \_\ \____\/______/ \ \____/\ \____\\ \_\  \ \__\
    \/___/ \/____/\/___/  \/_/\/_/\/____/          \/___/  \/____/ \/_/   \/__/
                                                                               
'@


# Trim
$CertToCloneThumbprint=$CertToCloneThumbprint -replace " ",""
$ExcludeThumbprint=$ExcludeThumbprint -replace " ",""


# Validates sha1 thumbprint and tries to fix copypaste from explorer certificate thumbprint dialogue
function validateandfixthumbprint([string]$tp)
{
   if ($tp -notmatch "^[0-9a-fA-F]{40}$") {
     # Pasting from certmgr gives an extra unicode character in front... try to fix this for the user here
     $tp=$tp.Substring(1)
     if ($tp -notmatch "^[0-9a-fA-F]{40}$") {
        write-error "The thumbprint is not 40 hexadecimal digits (SHA-1 thumbprint). Here is the culprit: $tp"
       
     } else { return $tp }

   } else { return $tp }
 
}

$CertToCloneThumbprint=validateandfixthumbprint $CertToCloneThumbprint

if ($ExcludeThumbprint) {
$ExcludeThumbprint=$ExcludeThumbprint | % { 
  validateandfixthumbprint $_
}
}
write-host $logo
Write-Host "Searching for certtoclone $CertToCloneThumbprint"
$cert_to_clone=ls Cert:\ -Recurse | ? { $_.Thumbprint -eq $CertToCloneThumbprint }

if (-not $cert_to_clone) {
   Write-Error "Couldn't find thumbprint $CertToCloneThumbprint in any of the stores. Are you sure it's there?"

}
$totalcerts+=$cert_to_clone

# God we love these loops, don't we. Find all certs to clone
while (1) {


   Write-Host ("Processing certificate "+$cert_to_clone.subject+" ("+$cert_to_clone.thumbprint+")")
   # Find issuer by traversing all stores
   $issuercert=ls cert:\ -Recurse | ? { $_.Subject -eq $cert_to_clone.Issuer -and $excludethumbprint -inotcontains $_.Thumbprint} | sort -Unique -Property Thumbprint

   if ($issuercert.length -gt 1) {

      Write-Host -ForegroundColor red ("Found more than one issuercert with subject name "+$cert_to_clone.Issuer)
      write-host 'Choose the ones you want to exclude using the -excludethumbprint "thumbprint1","thumbprint2",.. '
      write-host "Hint: Use certmgr.msc, navigate to the certificate you want to clone, choose 'Certification Path' and find the thumbprint of the offending certificate and exclude the others in the following list:"
      $issuercert | fl thumbprint, subject, issuer, psparentpath
      return
   }
   if ($issuercert.length -lt 1) {
      write-error ("Couldn't find issuer: "+$cert_to_clone.issuer+" in any of the certstores. Please find the issuer and install it")
      
   }
   $totalcerts+=$issuercert
   $cert_to_clone=$issuercert


   if ($issuercert.Subject -eq $issuercert.Issuer) {
     Write-Host ($issuercert.Subject+" is the root certificate. Processing with cloning")
     break
   }
}


# Create root

Write-Host "Creating certificates now"
$selfsigned_issuercert=New-SelfSignedCertificate -CloneCert $totalcerts[-1].PSPath -CertStoreLocation Cert:\CurrentUser\my
# The new-selfsignedcertificate seems to install the CA certificate automatically in the currentuser\CA path. Remove them from there...
rm -ErrorAction SilentlyContinue ("Cert:\CurrentUser\ca\"+$selfsigned_issuercert.thumbprint)
$selfsigned_issuercert.FriendlyName="Clone-Cert Root"
Write-Host ("Created root with thumbprint "+$selfsigned_issuercert.thumbprint)


# Now we traverse the totalcerts from root to end

for($i=-2;$i -ge -$totalcerts.Length; $i--)
{
   $selfsigned_issuercert=New-SelfSignedCertificate -CloneCert $totalcerts[$i].PSPath -Signer $selfsigned_issuercert.PSPath -CertStoreLocation Cert:\CurrentUser\my
   # Ditto from above
   rm -ErrorAction SilentlyContinue ("Cert:\CurrentUser\ca\"+$selfsigned_issuercert.thumbprint)
   $selfsigned_issuercert.FriendlyName="Clone-Cert Intermediate"
   Write-Host ("Created subordinate with thumbprint "+$selfsigned_issuercert.thumbprint)
}

$selfsigned_issuercert.FriendlyName="Clone-Cert EndUser"
Write-Host -ForegroundColor Green ("End user certificate with thumbprint "+$selfsigned_issuercert.thumbprint+" and chain created.`nYou find them in cert:\currentuser\my - check the friendlyname column in certmgr.msc to separate them from the others. Happy pwning!")