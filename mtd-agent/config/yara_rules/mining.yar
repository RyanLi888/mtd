rule Known_Mining_Tool_Strings
{
    meta:
        description = "Known cryptocurrency miner strings"
        owner = "MTD Team"
    strings:
        $xmrig = "xmrig" nocase ascii wide
        $stratum = "stratum+tcp" nocase ascii wide
        $donate = "donate-level" nocase ascii wide
        $pool = "pool.supportxmr.com" nocase ascii wide
    condition:
        2 of them
}
