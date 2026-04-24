/*
    EICAR test file signature — a harmless string universally recognized
    by antivirus tools. Ships as a self-test so operators can verify the
    WardSOAR cascade is wired correctly without deploying real malware.

    Drop your own *.yar / *.yara files in this directory; they will be
    compiled together at startup.
*/

rule EICAR_Test_File
{
    meta:
        author = "WardSOAR"
        description = "EICAR antivirus test file — cascade self-test"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "test"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
