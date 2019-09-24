rule APT41_RBDoor
{
    meta:
        description = "Looks for the string RBDoor found in APT41 PDB Strings"
        reference = "https://paper.bobylive.com/Security/APT_Report/APT-41.pdf"
        author = "Adam Bradbury"

    strings:
        $s1 = "RBDoor"
        $s2 = { 52 42 44 6f 6f 72 }

    condition:
        $s1 or $s2
}
