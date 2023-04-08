rule emotet_malware {
    meta:
        description = "YARA rule to detect Emotet malware"
        author = "Mohab Yehia"
        date = "2023-04-08"
        reference = "https://www.malwarebytes.com/emotet/"

    strings:
        $rc4_key = { 9E 35 94 2B B8 8D 28 45 1C 95 84 72 8F 9B 63 1A }
        $xor_key = { 0A 10 05 12 2C 5A 49 41 47 22 06 03 3E 3F 2E 39 }

        $http_header = "POST /1.0/p.php HTTP/1.1\r\nHost: "
        $http_header += /[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\r\n/
        $http_header += "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\n"
        $http_header += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\n"
        $http_data = "d="
        $http_data += /[A-Za-z0-9+\/]+={0,2}/
        $http_data += "&t="

    condition:
        uint16(0) == 0x5A4D and
        $rc4_key at 0 and
        $xor_key at 0x103 and
        $http_header and
        $http_data and
        (all of them or any of them)
}
