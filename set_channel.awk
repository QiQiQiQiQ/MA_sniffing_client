BEGIN {
    APbssid = "NOT_FOUND"
    APssid = "NOT_FOUND"
    frequency = 2412
}

/^BSS/ {
    bssid = substr($2, 0, 17)
}

/freq/{
    freq = strtonum($2)
}

/SSID/ {
    ssid = $2
}

/OUI/ {
    if ( (substr( $4, 0, 8 ) == "70:b3:d5") && ($6 == "31") && ( $7 == "90" ) ) {
        APbssid = bssid
        APssid = ssid
        frequency = freq
    }
}

END {
    print APssid " " frequency
}
