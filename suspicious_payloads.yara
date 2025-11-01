
rule SuspiciousPayload_AEE9FFAD {
    meta:
        description = "Suspicious payload starting with magic bytes AEE9FFAD"
        author = "Harbor Forensics"
    strings:
        $magic = { AE E9 FF AD }
    condition:
        $magic at 0
}

rule SuspiciousPayload_D34FE975 {
    meta:
        description = "Repeated suspicious binary structure starting with D34FE975"
        author = "Harbor Forensics"
    strings:
        $magic = { D3 4F E9 75 }
    condition:
        $magic at 0 or $magic in (1..filesize)
}
