import "pe"

rule nanolocker_candidate_01 {
    meta:
        author = "automated-threat-detection"
        description = "High-signal substring candidates for Nanolocker"
        family = "nanolocker"
    strings:
        $a1 = "0a-%m]mm" ascii
        $a2 = "9j`mmlm" ascii
        $a3 = "mmm%m]mm" ascii
        $a4 = "mmmmmmmmmmmmmmmmh)m" ascii
        $a5 = "q,1oam" ascii
        $a6 = "|%m]mm" ascii
        $a7 = "inet_addr" ascii
        $a8 = "2.83+?!" ascii
        $a9 = "7th06emz?" ascii
        $a10 = "\\mhavgco&" ascii
        $a11 = "\\whlaecz" ascii
        $a12 = "aadcd[w" ascii
        $a13 = "anrgw|q[" ascii
        $a14 = "atugk^]f" ascii
        $a15 = "b7wot=yy|" ascii
        $a16 = "bst2apqa" ascii
        $a17 = "c8xpbxi" ascii
        $a18 = "cnr|*d\\1" ascii
        $a19 = "ecs{t|0f)" ascii
        $a20 = "evqp1adw" ascii
    condition:
        uint16(0) == 0x5A4D and (pe.imports("advapi32.dll", "abortsystemshutdowna")) and 1 of them
}
