rule VBA_Stomped
{
    meta:
        description = "VBA stomping: p-code present but decompressed source missing/trivial"
        score       = 60
        author      = "yarad"

    strings:
        $marker = "VBA-STOMPED "

    condition:
        $marker
}
