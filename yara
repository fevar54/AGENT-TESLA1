rule Agent Tesla {
    meta:
        description = "Posible presencia de Agent Tesla"
        author = "Fevar54"
    strings:
        $str1 = "6f2b3c82caa732407921ee81ef9bb21c"
        $str2 = "f60135bf8afb40b3aed4e9ac02b4797d9c8df36a"
        $str3 = "79db6adf8c385876e82bd65cb1ab3c48ef35118b6ca0a9a5c9eb41b09533bc90"
        $str4 = "24503665651170859d1010"
        $str5 = "67d1ae1de95127728dc795305d0e85bb063fb74ca15062460a64e45102778f47"
        $str6 = "f34d5f2d4577ed6d9ceec516c1f5a744"
        $str7 = "12288:nkjR+FiVVOonxuLg0oFR+FijVOQCxuRG:nkjwEVVOonx8g0oFwEjVOQCxSG"
        $str8 = "T1B094D082BB854586CCBD5630C51BC2340DA6AC3CD8E446DB3BF9336D4973B9386526EB"
    condition:
        any of ($str1, $str2, $str3, $str4, $str5, $str6, $str7, $str8)    
}
