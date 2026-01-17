#!/usr/bin/env bash

__open_proxy__ () {
    read -p "Protocol? (http, https, socks5) " proxy_protocol
    read -p "IP? (x.x.x.x) "  proxy_ip
    read -p "Port? (1234) " proxy_port
    echo "running open proxy command check": 
    echo "curl --proxy-insecure -x \"$proxy_protocol\"://\"$proxy_ip\":\"$proxy_port\" \"http://httpbin.org/ip\""
    curl --proxy-insecure -x "$proxy_protocol"://"$proxy_ip":"$proxy_port" "http://httpbin.org/ip"
}