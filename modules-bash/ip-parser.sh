#!/usr/bin/env bash

# Pulls the current fabulizer IP list from S3
#    Note: The fabulizer javascript is full of easter eggs, you should check it out sometime.
__UpdateAWSIpList__ () {
    local AWS_IP_LIST_URL="https://ip-ranges.amazonaws.com/ip-ranges.json"
    local AWS_IP_LIST_TEMP_PATH="./data/aws-ip-ranges-temp.json"
    local AWS_IP_LIST_PATH="./data/aws-ip-ranges.json"
    if ! curl -s --fail "${AWS_IP_LIST_URL}" -o "${AWS_IP_LIST_TEMP_PATH}"; then
        echo "Error: Failed to download AWS IP ranges.
        exit 1
    fi
    jq '.' "${AWS_IP_LIST_TEMP_PATH}" > ${AWS_IP_LIST_PATH}
   rm ${AWS_IP_LIST_TEMP_PATH}
}

# query the cloudflare API, download a copy of their current IP ranges. no api auth keys are needed for this.
__UpdateCloudflareIpList__ () {
    curl -s -H 'Authorization: Bearer undefined' -H 'Content-Type: application/json' https://api.cloudflare.com/client/v4/ips | jq '.' > ./data/cloudflare-ip-ranges.json
}


