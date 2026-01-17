#!/usr/bin/env bash

# Source module files and env file. 
source ./data/.env || { echo "Error sourcing .env file, please make sure you've copied .env.example to ./data/.env and filled out all API keys and/or tokens"; exit 1; }
source ./modules-bash/virustotal.sh || { echo "Error sourcing virustotal tools, exiting."; exit 1; }
source ./modules-bash/basics.sh || { echo "Error sourcing basics tools, exiting."; exit 1; }
source ./modules-bash/text-handler.sh || { echo "Error sourcing text-handler tools, exiting."; exit 1; }

# install base reqs
install_requirements=false

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

# Input check and URL formatter reference.
if [ -z "$1" ]; then
    error "No URL supplied!"
    info "Please supply one or multiple URLs, like so:"
    highlight "$0 https://example.com"
    info "OR"
    highlight "$0 https://example.com https://example.net https://example.top"
    exit 3
fi

# Main URL processing loop
for i; do
    # Deobfuscate the URL
    info "Deobfuscating URL: $(highlight "${i}")"
    deobscufator_url=$(python3 ./modules-python/deobscufator.py "${i}")
    exit_code=$?

    if [ $exit_code -ne 0 ]; then
        error "Error deobfuscating URL: $(highlight "${i}"). Please deobfuscate manually."
        exit $exit_code
    fi

    echo -e "${COLOR_MAGENTA}==================${COLOR_RESET}"
    info "Input Domain: $(highlight "${i}")"
    success "De-Obfuscated Domain: $(highlight "${deobscufator_url}")"

    # Verify the URL format and run subsequent checks
    info "Running URL Formatter Check..."
    python3 ./modules-python/basics.py url_formatter "${deobscufator_url}"
    info "Fetching Curl Headers..."
    python3 ./modules-python/basics.py curl_headers "${deobscufator_url}"
    info "Performing Host Lookup..."
    python3 ./modules-python/basics.py host_lookup "${deobscufator_url}"
    info "Checking VirusTotal reputation..."
    python3 ./modules-python/virustotal.py "${deobscufator_url}" "$VTAPI_KEY"
    echo -e "${COLOR_MAGENTA}==================${COLOR_RESET}\n"
done
