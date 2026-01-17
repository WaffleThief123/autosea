#!/usr/bin/env bash

# Source module files and env file. 
source ./data/.env || { echo "Error sourcing .env file, please make sure you've copied .env.example to ./data/.env and filled out all API keys and/or tokens"; exit 1; }
source ./modules-bash/virustotal.sh || { echo "Error sourcing virustotal tools, exiting."; exit 1; }
source ./modules-bash/basics.sh || { echo "Error sourcing basics tools, exiting."; exit 1; }
source ./modules-bash/text-handler.sh || { echo "Error sourcing text-handler tools, exiting."; exit 1; }

# Command-line flags
install_requirements=false
config_user_agent=false
json_output=false
input_file=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-requirements)
            install_requirements=true
            shift
            ;;
        --user-agent)
            config_user_agent=true
            shift
            ;;
        --json)
            json_output=true
            export OUTPUT_FORMAT="json"
            shift
            ;;
        --file)
            if [[ -n "$2" && ! "$2" =~ ^-- ]]; then
                input_file="$2"
                shift 2
            else
                error "--file requires a filename argument"
                exit 1
            fi
            ;;
        *)
            break
            ;;
    esac
done

if [ "$install_requirements" = true ]; then
    if command -v dnf &>/dev/null; then
        info "Using $(highlight "DNF") package manager"
        dnf install -y python3 python3-pip
        success "Installed Python3 and pip"
        python3 -m pip install -r ./data/python-requirements.txt -qqq
        success "Installed Python dependencies quietly."
    elif command -v yum &>/dev/null; then
        info "Using $(highlight "Yum") package manager"
        yum install -y python3 python3-pip
        success "Installed Python3 and pip"
        python3 -m pip install -r ./data/python-requirements.txt -qqq
        success "Installed Python dependencies quietly."
    elif command -v apt &>/dev/null; then
        # Use apt on Debian-based systems (Ubuntu, Debian)
        info "Using $(highlight "APT") package manager"
        apt-get update
        apt-get install -y python3 python3-pip
        success "Installed Python3 and pip"
        python3 -m pip install -r ./data/python-requirements.txt -qqq
        success "Installed Python dependencies quietly."
    else
        error "Unsupported package manager or none found. Exiting."
        exit 1
    fi
    success "Requirements installation completed successfully!"
    exit 0
fi



yesnomaybe () {
    while true; do
        read -p "$(highlight "$* [yes/no/y/n]: ")" yn
        case $yn in
            [Yy]*) success "Yes received!"; return 0 ;;  
            [Nn]*) error "No received!"; return 1 ;;
            *) error "Invalid input received, please try again." ;;
        esac
    done
}

if [[ "${config_user_agent:-false}" == "true" ]]; then
    if [[ -n "${CUSTOM_USER_AGENT:-}" ]]; then
        warn "CUSTOM_USER_AGENT is already set in ./data/.env"
        if yesnomaybe "Do you want to overwrite the existing CUSTOM_USER_AGENT?"; then
            python3 ./modules-python/user_agent_config.py
            exit_code=$?
            if [ $exit_code -eq 0 ]; then
                success "Your User Agent has been set to:"
                highlight "$(grep CUSTOM_USER_AGENT ./data/.env | cut -d '=' -f2- | tr -d '"')"
                exit 0
            elif [ $exit_code -eq 1 ]; then
                warn "You've cancelled setting the user agent. Exiting."
                exit 1
            else
                error "Unknown error occurred in user_agent_config.py"
                exit $exit_code
            fi
        else
            info "Keeping existing CUSTOM_USER_AGENT. Exiting."
            exit 3
        fi
    else
        python3 ./modules-python/user_agent_config.py
        exit_code=$?
        if [ $exit_code -eq 0 ]; then
            success "Your User Agent has been set to:"
            highlight "$(grep CUSTOM_USER_AGENT ./data/.env | cut -d '=' -f2- | tr -d '"')"
            exit 0
        elif [ $exit_code -eq 1 ]; then
            warn "You've cancelled setting the user agent. Exiting."
            exit 1
        else
            error "Unknown error occurred in user_agent_config.py"
            exit $exit_code
        fi
    fi
fi


if [ ! -f "${BASH_REQUIREMENTS_YAML}" ]; then
    echo "Error: YAML file '${BASH_REQUIREMENTS_YAML}' not found."
    exit 1
fi

# check to make sure required software is installed and ready to go.
__CheckInstalledSoftware__ "${BASH_REQUIREMENTS_YAML}"
# Collect missing requirements
missing_requirements=()
for requirement in "${requirements[@]}"; do
    if ! command -v "$requirement" > /dev/null 2>&1; then
        missing_requirements+=("$requirement")
    fi
done

# Print missing requirements
if [ ${#missing_requirements[@]} -gt 0 ]; then
    echo "Error: The following software is not installed on the system:"
    printf '  - %s\n' "${missing_requirements[@]}"
    exit 1
fi

# Build URL list from file or command-line arguments
urls=()

if [[ -n "$input_file" ]]; then
    if [[ ! -f "$input_file" ]]; then
        error "Input file not found: $input_file"
        exit 1
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        urls+=("$line")
    done < "$input_file"
fi

# Add command-line URLs
for arg in "$@"; do
    urls+=("$arg")
done

# Input check
if [ ${#urls[@]} -eq 0 ]; then
    error "No URL supplied!"
    info "Please supply one or multiple URLs, like so:"
    highlight "$0 https://example.com"
    info "OR"
    highlight "$0 https://example.com https://example.net https://example.top"
    info "OR use --file to read URLs from a file:"
    highlight "$0 --file urls.txt"
    exit 3
fi

# Function to process a single URL
process_url() {
    local input_url="$1"

    # Deobfuscate the URL
    if [[ "$json_output" != "true" ]]; then
        info "Deobfuscating URL: $(highlight "${input_url}")"
    fi
    deobscufator_url=$(python3 ./modules-python/deobscufator.py "${input_url}")
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        error "Error deobfuscating URL: $(highlight "${input_url}"). Please deobfuscate manually."
        return $exit_code
    fi

    if [[ "$json_output" != "true" ]]; then
        echo -e "${COLOR_MAGENTA}==================${COLOR_RESET}"
        info "Input Domain: $(highlight "${input_url}")"
        success "De-Obfuscated Domain: $(highlight "${deobscufator_url}")"
    fi

    # Verify the URL format
    if [[ "$json_output" != "true" ]]; then
        info "Running URL Formatter Check..."
    fi
    python3 ./modules-python/basics.py url_formatter "${deobscufator_url}"

    # Fetch HTTP headers
    if [[ "$json_output" != "true" ]]; then
        info "Fetching HTTP Headers..."
    fi
    python3 ./modules-python/basics.py curl_headers "${deobscufator_url}"

    # DNS records lookup
    if [[ "$json_output" != "true" ]]; then
        info "Performing DNS Records Lookup..."
    fi
    python3 ./modules-python/dns_records.py "${deobscufator_url}"

    # WHOIS lookup
    if [[ "$json_output" != "true" ]]; then
        info "Performing WHOIS Lookup..."
    fi
    python3 ./modules-python/whois_lookup.py "${deobscufator_url}"

    # SSL certificate check
    if [[ "$json_output" != "true" ]]; then
        info "Checking SSL Certificate..."
    fi
    python3 ./modules-python/ssl_check.py "${deobscufator_url}"

    # Abuse contact lookup
    if [[ "$json_output" != "true" ]]; then
        info "Looking up Abuse Contact..."
    fi
    python3 ./modules-python/abuse_contact.py "${deobscufator_url}"

    # VirusTotal reputation check
    if [[ "$json_output" != "true" ]]; then
        info "Checking VirusTotal reputation..."
    fi
    python3 ./modules-python/virustotal.py "${deobscufator_url}" "$VTAPI_KEY"

    if [[ "$json_output" != "true" ]]; then
        echo -e "${COLOR_MAGENTA}==================${COLOR_RESET}\n"
    fi
}

# Main URL processing loop
for url in "${urls[@]}"; do
    process_url "$url"
done
