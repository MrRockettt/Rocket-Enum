#!/bin/bash
#
# Advanced Subdomain Enumeration Script
# Author: [Salmon Kumar/MrRockettt]
# Repository: [https://github.com/MrRockettt/rocket-enum]
#
# Description: Comprehensive subdomain enumeration tool combining
# multiple passive and active reconnaissance techniques

export VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
export SECURITYTRAILS_API_KEY="your_securitytrails_api_key_here"
export GITHUB_TOKEN="your_github_token_here"
export CHAOS_API_KEY="your_chaos_api_key_here"
export ALIENVAULT_API_KEY="your_alienvault_api_key_here"
export URLSCAN_API_KEY="your_urlscan_api_key_here"
export SHODAN_API_KEY="your_shodan_api_key_here"
export CENSYS_API_ID="your_censys_api_id_here"
export CENSYS_API_SECRET="your_censys_api_secret_here"

# Configuration paths - update these to match your system
export SUBFINDER_CONFIG_PATH="/root/.config/subfinder/provider-config.yaml"
export AMASS_CONFIG_PATH="/root/.config/amass/datasources.yaml"
export SUBDOMINATOR_CONFIG_PATH="/root/.config/Subdominator/provider-config.yaml"
export RESOLVERS_PATH="/home/kali/Wordlists/resolvers.txt"
export ALTDNS_PATH="/home/kali/Tools/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt"
export WORDLIST_PATH="/home/kali/Tools/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt"

# --- Timeout Configuration ---
# (Use 's' for seconds, 'm' for minutes, 'h' for hours)
# Example: "600s" = 10 minutes, "20m" = 20 minutes
export TIMEOUT_API="300s"                 # For curl API calls (VT, Shodan, crt.sh, etc.)
export TIMEOUT_PASSIVE_TOOLS="600s"      # For fast passive tools (assetfinder, amass)
export TIMEOUT_ACTIVE_TOOLS="1200s"       # For long-running active tools (puredns, shuffledns)
export TIMEOUT_PIPELINES="900s"          # For alterx/dnsgen pipelines
export TIMEOUT_RESOLUTION="900s"         # For final dnsx resolution
export SUBFINDER_TIMEOUT_FLAG="20"       # For subfinder -timeout flag (just the number)
# --- End Timeout Configuration ---



# Function to check if required tools are installed
check_dependencies() {
    local missing_tools=()
    # --- NEW: Added 'gau' and 'dnsx' to required list ---
    local required_tools=("subfinder" "assetfinder" "dnsx" "curl" "jq" "gau")
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        echo "[!] Missing required tools: ${missing_tools[*]}"
        echo "[!] Please install missing tools before running the script"
        return 1
    fi
    
    return 0
}

# Function to validate domain format
validate_domain() {
    local domain="$1"
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        echo "[!] Invalid domain format: $domain"
        return 1
    fi
    return 0
}

# Function to safely create directories
safe_mkdir() {
    local dir="$1"
    if ! mkdir -p "$dir" 2>/dev/null; then
        echo "[!] Failed to create directory: $dir"
        return 1
    fi
    return 0
}

subenum() {
    local domain="$1"
    local threads="${2:-100}"
    local output_dir="${3}"

    # Input validation
    if [ -z "$domain" ] || [ -z "$output_dir" ]; then
        echo "[!] Usage: subenum <domain> [threads] <output_directory>"
        return 1
    fi
    
    # Validate domain format
    if ! validate_domain "$domain"; then
        return 1
    fi
    
    # Validate thread count
    if ! [[ "$threads" =~ ^[0-9]+$ ]] || [ "$threads" -lt 1 ] || [ "$threads" -gt 1000 ]; then
        echo "[!] Invalid thread count. Must be between 1-1000"
        return 1
    fi
    
    # --- FIX: Resource Exhaustion Check ---
    local max_procs
    max_procs=$(nproc 2>/dev/null || echo 4) # Default to 4 if nproc fails
    if [ "$threads" -gt $((max_procs * 50)) ]; then
        echo "[!] WARNING: Thread count ($threads) is very high for $max_procs cores."
        echo "[!] This may cause system instability or get you rate-limited."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi
    # --- END FIX ---
    
    # Check dependencies
    if ! check_dependencies; then
        return 1
    fi

    # Check resolvers file
    if [ ! -f "$RESOLVERS_PATH" ]; then
        echo "[!] WARNING: Resolvers file not found: $RESOLVERS_PATH"
        echo "[!] Resolution will be limited. Download from:"
        echo "    https://github.com/trickest/resolvers"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            return 1
        fi
    fi

    # Checkpoint handling
    local checkpoint_file="$output_dir/.checkpoint"
    local resume_from_stage=""
    
    if [ -f "$checkpoint_file" ]; then
        echo "[*] Previous scan detected. Resume? (y/N)"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            source "$checkpoint_file" 2>/dev/null || true
            resume_from_stage="$LAST_COMPLETED_STAGE"
            echo "[*] Resuming from checkpoint: $resume_from_stage"
        fi
    fi
    
    # --- FIX: Checkpoint Waterfall Logic ---
    local run_stage_passive_nonapi=true
    local run_stage_passive_api=true
    # --- NEW: Added dns_records stage ---
    local run_stage_dns_records=true
    local run_stage_active_enum=true
    local run_stage_permutation=true
    local run_stage_ct_logs=true

    if [[ -n "$resume_from_stage" ]]; then
        case "$resume_from_stage" in
            "passive_nonapi")
                run_stage_passive_nonapi=false
                ;;
            "passive_api")
                run_stage_passive_nonapi=false
                run_stage_passive_api=false
                ;;
            # --- NEW: Added dns_records to waterfall ---
            "dns_records")
                run_stage_passive_nonapi=false
                run_stage_passive_api=false
                run_stage_dns_records=false
                ;;
            "active_enum")
                run_stage_passive_nonapi=false
                run_stage_passive_api=false
                run_stage_dns_records=false
                run_stage_active_enum=false
                ;;
            "permutation")
                run_stage_passive_nonapi=false
                run_stage_passive_api=false
                run_stage_dns_records=false
                run_stage_active_enum=false
                run_stage_permutation=false
                ;;
            "ct_logs")
                run_stage_passive_nonapi=false
                run_stage_passive_api=false
                run_stage_dns_records=false
                run_stage_active_enum=false
                run_stage_permutation=false
                run_stage_ct_logs=false
                ;;
        esac
    fi
    # --- END FIX ---

    echo "[*] Running Advanced Subdomain Enumeration for $domain"
    echo "[*] Using $threads threads for concurrent operations"

    # Setup directories
    if ! safe_mkdir "$output_dir"/{passive,active,resolved,final}; then
        return 1
    fi
    
    local tmp_dir
    if ! tmp_dir=$(mktemp -d); then
        echo "[!] Failed to create temporary directory"
        return 1
    fi
    
        # --- Better Exit Trap ---
    # Function to clean up child processes and temp files
    cleanup() {
        local main_pid=$$
        echo
        echo "[!] Interrupted (PID $main_pid). Cleaning up..."
    
        # Kill all child processes of this script
        # pkill -P $main_pid
    
        # A more compatible way to kill all processes in the group
        kill 0
    }
    
    # Set the trap to call the cleanup function *only once*
    trap 'trap - INT TERM EXIT; cleanup' INT TERM EXIT
    # --- End Trap ---
    
    local start_time
    start_time=$(date +%s)

    ##################################
    # NON-API PASSIVE ENUMERATION (PARALLEL)
    ##################################
    if [[ "$run_stage_passive_nonapi" == true ]]; then
        echo "[*] Starting Non-API Passive Enumeration (Parallel)..."

        # Function for parallel non-API passive enumeration
        run_nonapi_passive_enum() {
            local source="$1"
            local domain="$2"
            local output_dir="$3"
            local threads="$4"
            
            case "$source" in
                "subfinder")
                    if command -v subfinder >/dev/null 2>&1; then
                        echo "[*] Running Subfinder..."
                        subfinder -d "$domain" -all -silent \
                            $([ -f "$SUBFINDER_CONFIG_PATH" ] && echo "-config $SUBFINDER_CONFIG_PATH") \
                            -t "$threads" -timeout "$SUBFINDER_TIMEOUT_FLAG" \
                            -o "$output_dir/passive/subfinder_${domain}.txt" 2>/dev/null \
                            || echo "[!] Subfinder failed" >&2
                    fi
                    ;;
                "assetfinder")
                    if command -v assetfinder >/dev/null 2>&1; then
                        echo "[*] Running Assetfinder..."
                        timeout "$TIMEOUT_PASSIVE_TOOLS" assetfinder --subs-only "$domain" 2>/dev/null \
                            > "$output_dir/passive/assetfinder_${domain}.txt" \
                            || echo "[!] Assetfinder failed" >&2
                    fi
                    ;;
                "amass")
                    if command -v amass >/dev/null 2>&1; then
                        echo "[*] Running Amass (passive)..."
                        timeout "$TIMEOUT_PASSIVE_TOOLS" amass enum -passive -d "$domain" \
                            $([ -f "$AMASS_CONFIG_PATH" ] && echo "-config $AMASS_CONFIG_PATH") \
                            -o "$output_dir/passive/amass_${domain}.txt" 2>/dev/null \
                            || echo "[!] Amass failed" >&2
                    fi
                    ;;
                "findomain")
                    if command -v findomain >/dev/null 2>&1; then
                        echo "[*] Running Findomain..."
                        timeout "$TIMEOUT_PASSIVE_TOOLS" findomain -t "$domain" -q 2>/dev/null \
                            > "$output_dir/passive/findomain_${domain}.txt" \
                            || echo "[!] Findomain failed" >&2
                    fi
                    ;;
                "chaos")
                    if command -v chaos >/dev/null 2>&1 && [ -n "$CHAOS_API_KEY" ] && [[ ! "$CHAOS_API_KEY" == "your_"* ]]; then
                        echo "[*] Running Chaos..."
                        timeout "$TIMEOUT_PASSIVE_TOOLS" chaos -d "$domain" -key "$CHAOS_API_KEY" -silent 2>/dev/null \
                            > "$output_dir/passive/chaos_${domain}.txt" \
                            || echo "[!] Chaos failed" >&2
                    fi
                    ;;
                # --- NEW: Replaced weak curl with 'gau' ---
                "gau")
                    if command -v gau >/dev/null 2>&1; then
                        echo "[*] Running gau (Web Archives)..."
                        timeout "$TIMEOUT_PASSIVE_TOOLS" gau --subs "$domain" 2>/dev/null \
                            | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                            | sort -u > "$output_dir/passive/gau_${domain}.txt" \
                            || echo "[!] gau failed" >&2
                    fi
                    ;;
                "crtsh")
                    echo "[*] Running crt.sh..."
                    timeout "$TIMEOUT_API" curl -sk "https://crt.sh/?q=%.${domain}&output=json" 2>/dev/null \
                        | jq -r '.[].name_value // empty' 2>/dev/null \
                        | sed 's/\*\.//g' | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                        | sort -u > "$output_dir/passive/crtsh_${domain}.txt" 2>/dev/null \
                        || echo "[!] crt.sh failed" >&2
                    ;;
            esac
        }

        # Export function for subshells
        export -f run_nonapi_passive_enum

        # --- NEW: Added 'gau' to sources list ---
        local nonapi_sources=("subfinder" "assetfinder" "amass" "findomain" "chaos" "gau" "crtsh")
        
        for source in "${nonapi_sources[@]}"; do
            run_nonapi_passive_enum "$source" "$domain" "$output_dir" "$threads" &
        done
        
        echo "[*] Waiting for non-API passive enumeration to complete..."
        wait
        echo "[+] Non-API passive enumeration complete"
        
        # Save checkpoint
        echo "LAST_COMPLETED_STAGE='passive_nonapi'" > "$checkpoint_file"
    fi

    ##################################
    # API-BASED SOURCES (SEQUENTIAL WITH DELAYS)
    ##################################
    if [[ "$run_stage_passive_api" == true ]]; then
        echo "[*] Starting API-based enumeration (Sequential with rate limiting)..."

        # Function for API-based enumeration with error handling
        run_api_enum() {
            local api_name="$1"
            local domain="$2"
            local output_dir="$3"
            
            case "$api_name" in
                "virustotal")
                    if [ -n "$VIRUSTOTAL_API_KEY" ] && [[ ! "$VIRUSTOTAL_API_KEY" == "your_"* ]]; then
                        echo "[*] Running VirusTotal API..."
                        if vt_resp=$(timeout "$TIMEOUT_API" curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" \
                            "https://www.virustotal.com/ui/domains/${domain}/subdomains?limit=40" 2>/dev/null); then
                            if [ -n "$vt_resp" ] && echo "$vt_resp" | jq empty >/dev/null 2>&1; then
                                echo "$vt_resp" | jq -r '.data[]?.id // empty' 2>/dev/null \
                                    | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                                    | grep -v "^null$" | grep -v "^$" \
                                    > "$output_dir/passive/virustotal_${domain}.txt" \
                                    || echo "[!] VirusTotal jq processing failed" >&2
                                local count
                                count=$(wc -l < "$output_dir/passive/virustotal_${domain}.txt" 2>/dev/null || echo "0")
                                echo "[+] VirusTotal: $count results"
                            else
                                echo "[!] VirusTotal: Invalid JSON response"
                                touch "$output_dir/passive/virustotal_${domain}.txt"
                            fi
                        else
                            echo "[!] VirusTotal: API request failed"
                            touch "$output_dir/passive/virustotal_${domain}.txt"
                        fi
                    else
                        echo "[!] VirusTotal: API key not configured"
                        touch "$output_dir/passive/virustotal_${domain}.txt"
                    fi
                    ;;
                "securitytrails")
                    if [ -n "$SECURITYTRAILS_API_KEY" ] && [[ ! "$SECURITYTRAILS_API_KEY" == "your_"* ]]; then
                        echo "[*] Running SecurityTrails API..."
                        if st_resp=$(timeout "$TIMEOUT_API" curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
                            "https://api.securitytrails.com/v1/domain/${domain}/subdomains" 2>/dev/null); then
                            if [ -n "$st_resp" ] && echo "$st_resp" | jq empty >/dev/null 2>&1; then
                                echo "$st_resp" | jq -r '.subdomains[]? // empty' 2>/dev/null \
                                    | sed "s/$/.$domain/" \
                                    | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                                    > "$output_dir/passive/securitytrails_${domain}.txt" \
                                    || echo "[!] SecurityTrails jq processing failed" >&2
                                local count
                                count=$(wc -l < "$output_dir/passive/securitytrails_${domain}.txt" 2>/dev/null || echo "0")
                                echo "[+] SecurityTrails: $count results"
                            else
                                echo "[!] SecurityTrails: Invalid JSON response"
                                touch "$output_dir/passive/securitytrails_${domain}.txt"
                            fi
                        else
                            echo "[!] SecurityTrails: API request failed"
                            touch "$output_dir/passive/securitytrails_${domain}.txt"
                        fi

                        # SecurityTrails History API
                        echo "[*] Running SecurityTrails History API..."
                        if st_history=$(timeout "$TIMEOUT_API" curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" \
                            "https://api.securitytrails.com/v1/history/${domain}/dns/a" 2>/dev/null); then
                            if [ -n "$st_history" ] && echo "$st_history" | jq empty >/dev/null 2>&1; then
                                echo "$st_history" | jq -r '.records[].values[].ip // empty' 2>/dev/null \
                                    | sort -u > "$output_dir/passive/securitytrails_history_${domain}.txt" \
                                    || echo "[!] SecurityTrails History processing failed" >&2
                            fi
                        fi
                    else
                        echo "[!] SecurityTrails: API key not configured"
                        touch "$output_dir/passive/securitytrails_${domain}.txt"
                    fi
                    ;;
                "shodan")
                    if [ -n "$SHODAN_API_KEY" ] && [[ ! "$SHODAN_API_KEY" == "your_"* ]]; then
                        echo "[*] Running Shodan API..."
                        
                        if shodan_resp=$(timeout "$TIMEOUT_API" curl -s \
                            "https://api.shodan.io/dns/domain/${domain}?key=${SHODAN_API_KEY}" 2>/dev/null); then
                            
                            if [ -n "$shodan_resp" ] && echo "$shodan_resp" | jq empty >/dev/null 2>&1; then
                                if echo "$shodan_resp" | jq -e '.error' >/dev/null 2>&1; then
                                    local error_msg
                                    error_msg=$(echo "$shodan_resp" | jq -r '.error')
                                    echo "[!] Shodan API error: $error_msg"
                                    touch "$output_dir/passive/shodan_${domain}.txt"
                                else
                                    echo "$shodan_resp" | jq -r '.data[]? // empty' 2>/dev/null \
                                        | while read -r subdomain; do
                                            if [ -n "$subdomain" ] && [ "$subdomain" != "null" ]; then
                                                echo "${subdomain}.${domain}"
                                            fi
                                        done | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                                        | sort -u > "$output_dir/passive/shodan_${domain}.txt" \
                                        || echo "[!] Shodan processing failed" >&2
                                    
                                    local count
                                    count=$(wc -l < "$output_dir/passive/shodan_${domain}.txt" 2>/dev/null || echo "0")
                                    echo "[+] Shodan: $count results"
                                fi
                            else
                                echo "[!] Shodan: Invalid or empty response"
                                touch "$output_dir/passive/shodan_${domain}.txt"
                            fi
                        else
                            echo "[!] Shodan: API request failed or timed out"
                            touch "$output_dir/passive/shodan_${domain}.txt"
                        fi
                    else
                        echo "[!] Shodan: API key not configured"
                        touch "$output_dir/passive/shodan_${domain}.txt"
                    fi
                    ;;
                "github")
                    if [ -n "$GITHUB_TOKEN" ] && [[ ! "$GITHUB_TOKEN" == "your_"* ]]; then
                        echo "[*] Running GitHub API..."
                        if gh_resp=$(timeout "$TIMEOUT_API" curl -s -H "Authorization: token $GITHUB_TOKEN" \
                            "https://api.github.com/search/code?q=${domain}+extension:json+OR+extension:txt+OR+extension:xml" 2>/dev/null); then
                            if [ -n "$gh_resp" ] && echo "$gh_resp" | jq empty >/dev/null 2>&1; then
                                echo "$gh_resp" | jq -r '.items[]?.name // empty' 2>/dev/null \
                                    | grep -oE "[a-zA-Z0-9.-]+\.${domain}" 2>/dev/null \
                                    | sort -u > "$output_dir/passive/github_${domain}.txt" \
                                    || echo "[!] GitHub processing failed" >&2
                                local count
                                count=$(wc -l < "$output_dir/passive/github_${domain}.txt" 2>/dev/null || echo "0")
                                echo "[+] GitHub: $count results"
                            else
                                echo "[!] GitHub: Invalid JSON response"
                                touch "$output_dir/passive/github_${domain}.txt"
                            fi
                        else
                            echo "[!] GitHub: API request failed"
                            touch "$output_dir/passive/github_${domain}.txt"
                        fi
                    else
                        echo "[!] GitHub: Token not configured"
                        touch "$output_dir/passive/github_${domain}.txt"
                    fi
                    ;;
                "urlscan")
                    if [ -n "$URLSCAN_API_KEY" ] && [[ ! "$URLSCAN_API_KEY" == "your_"* ]]; then
                        echo "[*] Running URLScan API..."
                        if us_resp=$(timeout "$TIMEOUT_API" curl -s -H "API-Key: $URLSCAN_API_KEY" \
                            "https://urlscan.io/api/v1/search/?q=domain:${domain}" 2>/dev/null); then
                            if [ -n "$us_resp" ] && echo "$us_resp" | jq empty >/dev/null 2>&1; then
                                echo "$us_resp" | jq -r '.results[]?.page?.domain // empty' 2>/dev/null \
                                    | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                                    | sort -u > "$output_dir/passive/urlscan_${domain}.txt" \
                                    || echo "[!] URLScan processing failed" >&2
                                local count
                                count=$(wc -l < "$output_dir/passive/urlscan_${domain}.txt" 2>/dev/null || echo "0")
                                echo "[+] URLScan: $count results"
                            else
                                echo "[!] URLScan: Invalid JSON response"
                                touch "$output_dir/passive/urlscan_${domain}.txt"
                            fi
                        else
                            echo "[!] URLScan: API request failed"
                            touch "$output_dir/passive/urlscan_${domain}.txt"
                        fi
                    else
                        echo "[!] URLScan: API key not configured"
                        touch "$output_dir/passive/urlscan_${domain}.txt"
                    fi
                    ;;
                "censys")
                    if [ -n "$CENSYS_API_ID" ] && [ -n "$CENSYS_API_SECRET" ] && [[ ! "$CENSYS_API_ID" == "your_"* ]]; then
                        echo "[*] Running Censys API..."
                        if censys_resp=$(timeout "$TIMEOUT_API" curl -s -u "$CENSYS_API_ID:$CENSYS_API_SECRET" \
                            "https://search.censys.io/api/v2/hosts/search?q=services.service_name:HTTP+and+names:*.${domain}" 2>/dev/null); then
                            if [ -n "$censys_resp" ] && echo "$censys_resp" | jq empty >/dev/null 2>&1; then
                                echo "$censys_resp" | jq -r '.result.hits[].names[]? // empty' 2>/dev/null \
                                    | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                                    | sort -u > "$output_dir/passive/censys_${domain}.txt" \
                                    || echo "[!] Censys processing failed" >&2
                                local count
                                count=$(wc -l < "$output_dir/passive/censys_${domain}.txt" 2>/dev/null || echo "0")
                                echo "[+] Censys: $count results"
                            else
                                echo "[!] Censys: Invalid JSON response"
                                touch "$output_dir/passive/censys_${domain}.txt"
                            fi
                        else
                            echo "[!] Censys: API request failed"
                            touch "$output_dir/passive/censys_${domain}.txt"
                        fi
                    else
                        echo "[!] Censys: API credentials not configured"
                        touch "$output_dir/passive/censys_${domain}.txt"
                    fi
                    ;;
                # --- NEW: Added AlienVault OTX ---
                "alienvault")
                    if [ -n "$ALIENVAULT_API_KEY" ] && [[ ! "$ALIENVAULT_API_KEY" == "your_"* ]]; then
                        echo "[*] Running AlienVault OTX API..."
                        if av_resp=$(timeout "$TIMEOUT_API" curl -s -H "X-OTX-API-KEY: $ALIENVAULT_API_KEY" \
                            "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" 2>/dev/null); then
                            if [ -n "$av_resp" ] && echo "$av_resp" | jq empty >/dev/null 2>&1; then
                                echo "$av_resp" | jq -r '.passive_dns[]?.hostname // empty' 2>/dev/null \
                                    | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                                    | sort -u > "$output_dir/passive/alienvault_${domain}.txt" \
                                    || echo "[!] AlienVault processing failed" >&2
                                local count
                                count=$(wc -l < "$output_dir/passive/alienvault_${domain}.txt" 2>/dev/null || echo "0")
                                echo "[+] AlienVault: $count results"
                            else
                                echo "[!] AlienVault: Invalid JSON response"
                                touch "$output_dir/passive/alienvault_${domain}.txt"
                            fi
                        else
                            echo "[!] AlienVault: API request failed"
                            touch "$output_dir/passive/alienvault_${domain}.txt"
                        fi
                    else
                        echo "[!] AlienVault: API key not configured"
                        touch "$output_dir/passive/alienvault_${domain}.txt"
                    fi
                    ;;
            esac
        }

        # --- NEW: Added 'alienvault' to API list ---
        local api_sources=("virustotal" "securitytrails" "shodan" "github" "urlscan" "censys" "alienvault")
        
        for api_source in "${api_sources[@]}"; do
            if ! run_api_enum "$api_source" "$domain" "$output_dir"; then
                echo "[!] Skipped $api_source due to error"
            fi
            echo "[*] Waiting 1 second before next API call..."
            sleep 1
        done
        
        # Save checkpoint
        echo "LAST_COMPLETED_STAGE='passive_api'" > "$checkpoint_file"
    fi

    ##################################
    # MERGE PASSIVE RESULTS
    ##################################
    echo "[*] Merging passive results..."
    find "$output_dir/passive" -name "*_${domain}.txt" -type f -exec cat {} + 2>/dev/null \
        | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
        | sort -u > "$output_dir/passive_all_${domain}.txt" \
        || echo "[!] Failed to merge passive results" >&2

    local passive_count
    passive_count=$(wc -l < "$output_dir/passive_all_${domain}.txt" 2>/dev/null || echo "0")
    echo "[+] Passive enumeration found: $passive_count subdomains"

    # --- NEW: DNS Record Mining Stage ---
    ##################################
    # DNS RECORD MINING (MX, TXT, SRV)
    ##################################
    if [[ "$run_stage_dns_records" == true ]]; then
        echo "[*] Starting DNS Record Mining (MX, TXT, SRV)..."
        if [ -f "$RESOLVERS_PATH" ]; then
            # Query for MX, NS, TXT, SRV records
            timeout "$TIMEOUT_API" dnsx -d "$domain" -t MX -t NS -t TXT -t SRV -resp -silent -r "$RESOLVERS_PATH" 2>/dev/null \
                | grep -oE "[a-zA-Z0-9.-]+\.${domain}" \
                | sort -u > "$output_dir/active/dns_records_${domain}.txt" \
                || echo "[!] DNS Record Mining failed" >&2
            
            local dns_rec_count
            dns_rec_count=$(wc -l < "$output_dir/active/dns_records_${domain}.txt" 2>/dev/null || echo "0")
            echo "[+] DNS Record Mining found: $dns_rec_count potential subdomains"
        fi
        
        # Save checkpoint
        echo "LAST_COMPLETED_STAGE='dns_records'" > "$checkpoint_file"
    fi
    # --- END NEW STAGE ---

    ##################################
    # ACTIVE ENUMERATION & BRUTEFORCE
    ##################################
    if [[ "$run_stage_active_enum" == true ]]; then
        echo "[*] Starting Active Enumeration..."

        # Ensure active directory exists
        mkdir -p "$output_dir/active"

        # --- NEW: Zone Transfer (AXFR) Check ---
        if [ -f "$RESOLVERS_PATH" ]; then
            echo "[*] Running DNS Zone Transfer (AXFR) check..."
            {
                # Get NS servers for the domain
                local ns_servers
                ns_servers=$(dnsx -d "$domain" -t NS -resp-only -silent -r "$RESOLVERS_PATH" 2>/dev/null)
                if [ -n "$ns_servers" ]; then
                    for ns in $ns_servers; do
                        echo "[*] Trying AXFR against $ns..."
                        # Use dnsx to attempt the transfer
                        timeout "$TIMEOUT_API" dnsx -d "$domain" -axfr -s "$ns" -silent -r "$RESOLVERS_PATH" 2>/dev/null \
                            | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                            >> "$output_dir/active/axfr_${domain}.txt"
                    done
                    sort -u -o "$output_dir/active/axfr_${domain}.txt" "$output_dir/active/axfr_${domain}.txt" \
                        || echo "[!] AXFR sort failed" >&2
                    local axfr_count
                    axfr_count=$(wc -l < "$output_dir/active/axfr_${domain}.txt" 2>/dev/null || echo "0")
                    echo "[+] Zone Transfer check found: $axfr_count subdomains"
                else
                    echo "[!] Could not find NS servers for $domain, skipping AXFR."
                fi
            } & # Run AXFR checks in the background
        fi
        # --- END NEW CHECK ---

        # High-speed DNS bruteforce with puredns
        if command -v puredns >/dev/null 2>&1 && [ -f "$WORDLIST_PATH" ] && [ -f "$RESOLVERS_PATH" ]; then
            echo "[*] Running puredns bruteforce..."
            timeout "$TIMEOUT_ACTIVE_TOOLS" puredns bruteforce "$WORDLIST_PATH" "$domain" \
                -r "$RESOLVERS_PATH" --rate-limit 1000 -q \
                -w "$output_dir/active/puredns_${domain}.txt" 2>/dev/null \
                || echo "[!] puredns bruteforce failed" >&2
        fi

        # Fast DNS resolution with massdns
        if command -v massdns >/dev/null 2>&1 && [ -f "$WORDLIST_PATH" ] && [ -f "$RESOLVERS_PATH" ]; then
            echo "[*] Running massdns bruteforce..."
            {
                head -100000 "$WORDLIST_PATH" | sed "s/$/.$domain/" \
                    | timeout "$TIMEOUT_ACTIVE_TOOLS" massdns -r "$RESOLVERS_PATH" -t A -o S -w "$tmp_dir/massdns_raw.txt" 2>/dev/null \
                    || echo "[!] massdns failed" >&2
                if [ -f "$tmp_dir/massdns_raw.txt" ]; then
                    awk '{print $1}' "$tmp_dir/massdns_raw.txt" | sed 's/\.$//' \
                        > "$output_dir/active/massdns_${domain}.txt"
                fi
            } &
        fi

        # Shuffledns for comprehensive bruteforce
        if command -v shuffledns >/dev/null 2>&1 && [ -f "$WORDLIST_PATH" ] && [ -f "$RESOLVERS_PATH" ]; then
            echo "[*] Running shuffledns..."
            timeout "$TIMEOUT_ACTIVE_TOOLS" shuffledns -d "$domain" -w "$WORDLIST_PATH" -r "$RESOLVERS_PATH" \
                -silent -mode bruteforce -t "$threads" \
                -o "$output_dir/active/shuffledns_${domain}.txt" 2>/dev/null \
                || echo "[!] shuffledns failed" >&2 &
        fi

        wait
        
        # Save checkpoint
        echo "LAST_COMPLETED_STAGE='active_enum'" > "$checkpoint_file"
    fi

    ##################################
    # PERMUTATION & MUTATION
    ##################################
    if [[ "$run_stage_permutation" == true ]]; then
        echo "[*] Starting Permutation & Mutation..."

        # --- LOGIC FIX: Create a combined seed list ---
        echo "[*] Creating combined seed list for permutations..."
        local base_domains="$tmp_dir/all_seeds_for_permutation.txt"
        find "$output_dir" -path "*/passive_all_${domain}.txt" -o -path "*/active/*_${domain}.txt" -type f -exec cat {} + 2>/dev/null \
            | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
            | sort -u > "$base_domains" \
            || echo "[!] Failed to create combined seed list" >&2
        
        local seed_count
        seed_count=$(wc -l < "$base_domains" 2>/dev/null || echo "0")
        echo "[+] Using $seed_count combined subdomains as seeds for permutation"
        # --- END LOGIC FIX ---

        # Alterx for fast permutations
        if command -v alterx >/dev/null 2>&1 && [ -s "$base_domains" ] && [ -f "$RESOLVERS_PATH" ]; then
            echo "[*] Running alterx permutations..."
            {
                # --- FIX: Use head on the combined list ---
                head -5000 "$base_domains" | \
                timeout "$TIMEOUT_PIPELINES" alterx -l - -silent -enrich -limit 50000 \
                    | timeout "$TIMEOUT_PIPELINES" dnsx -silent -r "$RESOLVERS_PATH" -t "$threads" \
                    -o "$output_dir/active/alterx_${domain}.txt" 2>/dev/null \
                    || echo "[!] alterx pipeline failed" >&2
            } &
        fi

        # Dnsgen + dnsx for intelligent permutations
        if command -v dnsgen >/dev/null 2>&1 && [ -s "$base_domains" ] && [ -f "$RESOLVERS_PATH" ]; then
            echo "[*] Running dnsgen permutations..."
            {
                # --- FIX: Use head on the combined list ---
                head -2000 "$base_domains" | timeout "$TIMEOUT_PIPELINES" dnsgen - | head -100000 \
                    | timeout "$TIMEOUT_PIPELINES" dnsx -silent -r "$RESOLVERS_PATH" -t "$threads" \
                    -o "$output_dir/active/dnsgen_${domain}.txt" 2>/dev/null \
                    || echo "[!] dnsgen pipeline failed" >&2
            } &
        fi

        wait
        
        # Save checkpoint
        echo "LAST_COMPLETED_STAGE='permutation'" > "$checkpoint_file"
    fi

    ##################################
    # CERTIFICATE TRANSPARENCY MINING
    ##################################
    if [[ "$run_stage_ct_logs" == true ]]; then
        echo "[*] Advanced Certificate Transparency Mining..."

        # Multiple CT log sources
        local ct_sources=(
            "https://crt.sh/?q=%.${domain}&output=json"
        )

        for ct_url in "${ct_sources[@]}"; do
            {
                timeout "$TIMEOUT_API" curl -sk "$ct_url" 2>/dev/null \
                    | jq -r '.[].name_value // empty' 2>/dev/null \
                    | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
                    | sed 's/\*\.//g' \
                    | sort -u >> "$output_dir/active/ct_multiple_${domain}.txt" \
                    || echo "[!] CT log retrieval failed for $ct_url" >&2
            } &
        done

        wait
        
        # Save checkpoint
        echo "LAST_COMPLETED_STAGE='ct_logs'" > "$checkpoint_file"
    fi

    ##################################
    # MERGE ALL RESULTS
    ##################################
    echo "[*] Merging all enumeration results..."
    
    find "$output_dir" -name "*_${domain}.txt" -type f -exec cat {} + 2>/dev/null \
        | grep -E "^[a-zA-Z0-9.-]+\.${domain}$" \
        | grep -v "^\*\." \
        | sort -u > "$output_dir/all_subdomains_${domain}.txt" \
        || echo "[!] Failed to merge all results" >&2

    ##################################
    # FAST RESOLUTION & VALIDATION
    ##################################
    echo "[*] Fast resolution and validation..."

    # Ensure resolved directory exists
    mkdir -p "$output_dir/resolved"
    mkdir -p "$output_dir/final"

    # Use puredns for fast resolution if available
    if command -v puredns >/dev/null 2>&1 && [ -f "$RESOLVERS_PATH" ]; then
        echo "[*] Resolving with puredns..."
        timeout "$TIMEOUT_RESOLUTION" puredns resolve "$output_dir/all_subdomains_${domain}.txt" \
            -r "$RESOLVERS_PATH" --rate-limit 1000 -q \
            -w "$output_dir/resolved/puredns_resolved_${domain}.txt" 2>/dev/null \
            || echo "[!] puredns resolve failed" >&2
    else
        # Fallback to dnsx
        echo "[*] Resolving with dnsx..."
        if [ -f "$RESOLVERS_PATH" ]; then
            timeout "$TIMEOUT_RESOLUTION" dnsx -l "$output_dir/all_subdomains_${domain}.txt" \
                -silent -r "$RESOLVERS_PATH" -t "$threads" \
                -o "$output_dir/resolved/dnsx_resolved_${domain}.txt" 2>/dev/null \
                || echo "[!] dnsx resolve failed" >&2
        fi
    fi
    
    # Get final resolved list
    find "$output_dir/resolved" -name "*resolved*${domain}.txt" -type f -exec cat {} + 2>/dev/null \
        | sort -u > "$output_dir/final/${domain}_final_resolved.txt" \
        || echo "[!] Failed to create final resolved list" >&2

    ##################################
    # ADVANCED INFORMATION GATHERING
    ##################################
    echo "[*] Advanced information gathering..."

    local resolved_file="$output_dir/final/${domain}_final_resolved.txt"

    if [ -s "$resolved_file" ]; then
        # Get A records and IPs
        if [ -f "$RESOLVERS_PATH" ]; then
            timeout "$TIMEOUT_RESOLUTION" dnsx -l "$resolved_file" -silent -a -resp-only \
                -r "$RESOLVERS_PATH" -t "$threads" \
                | sort -u > "$output_dir/final/${domain}_ips.txt" 2>/dev/null \
                || echo "[!] dnsx A record scan failed" >&2 &

            # Get CNAME records
            timeout "$TIMEOUT_RESOLUTION" dnsx -l "$resolved_file" -silent -cname -resp-only \
                -r "$RESOLVERS_PATH" -t "$threads" \
                | sort -u > "$output_dir/final/${domain}_cnames.txt" 2>/dev/null \
                || echo "[!] dnsx CNAME record scan failed" >&2 &
        fi


        wait
    fi

    ##################################
    # CLEANUP & SUMMARY
    ##################################
    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo ""
    echo "+-------------------------------------------------------------------+"
    echo "|                   ROCKET ENUMERATION COMPLETE                     |"
    echo "+-------------------------------------------------------------------+"
    echo "| Domain: $domain"
    echo "| Duration: ${duration}s"
    echo "|"
    echo "| Results:"

    local total_found
    total_found=$(wc -l < "$output_dir/all_subdomains_${domain}.txt" 2>/dev/null || echo "0")
    local resolved_count
    resolved_count=$(wc -l < "$output_dir/final/${domain}_final_resolved.txt" 2>/dev/null || echo "0")
    
    local ip_count=0
    if [ -f "$output_dir/final/${domain}_ips.txt" ]; then
        ip_count=$(wc -l < "$output_dir/final/${domain}_ips.txt" 2>/dev/null || echo "0")
    fi
    
    echo "| • Total subdomains found: $total_found"
    echo "| • Resolved subdomains: $resolved_count"
    echo "| • Unique IP addresses: $ip_count"
    
    # --- NOTE: This file is no longer created, but check is harmless ---
    if [ -f "$output_dir/final/${domain}_open_ports.txt" ]; then
        local port_count
        port_count=$(wc -l < "$output_dir/final/${domain}_open_ports.txt" 2>/dev/null || echo "0")
        echo "| • Open ports found: $port_count"
    fi
    
    echo "|"
    echo "| Output directory: $output_dir"
    echo "+-------------------------------------------------------------------+"
    echo ""

    # Cleanup
    rm -rf "$tmp_dir"
    rm -f "$checkpoint_file"
    
    # --- FIX: Updated summary template ---
    cat > "$output_dir/SUMMARY_${domain}.txt" << EOF
Subdomain Enumeration Summary for $domain
==========================================
Date: $(date)
Duration: ${duration} seconds
Threads: $threads

Results:
- Total subdomains found: $total_found
- Resolved subdomains: $resolved_count  
- Unique IP addresses: $ip_count

Key Files:
- All subdomains: all_subdomains_${domain}.txt
- Resolved subdomains: final/${domain}_final_resolved.txt
- IP addresses: final/${domain}_ips.txt
- CNAME records: final/${domain}_cnames.txt
EOF
    # --- END FIX ---

    echo "[+] Summary saved to: $output_dir/SUMMARY_${domain}.txt"
    return 0
}

# Export the function so it's available to subshells
export -f subenum

# Bulk subdomain enumeration function
sublist() {
    local domain_list="$1"
    local parallel_jobs="${2:-5}"
    local threads_per_domain="${3:-50}"
    
    if [ ! -f "$domain_list" ]; then
        echo "[!] Usage: sublist <domain_list_file> [parallel_jobs] [threads_per_domain]"
        echo "[!] Example: sublist domains.txt 10 30"
        echo "[!] File not found: $domain_list"
        return 1
    fi

    # Validate inputs
    if ! [[ "$parallel_jobs" =~ ^[0-9]+$ ]] || [ "$parallel_jobs" -lt 1 ] || [ "$parallel_jobs" -gt 20 ]; then
        echo "[!] Invalid parallel jobs count. Must be between 1-20"
        return 1
    fi
    
    if ! [[ "$threads_per_domain" =~ ^[0-9]+$ ]] || [ "$threads_per_domain" -lt 1 ] || [ "$threads_per_domain" -gt 200 ]; then
        echo "[!] Invalid threads per domain. Must be between 1-200"
        return 1
    fi

    echo "[*] Running Bulk Subdomain Enumeration"
    echo "[*] Domain list: $domain_list"
    echo "[*] Parallel jobs: $parallel_jobs"
    echo "[*] Threads per domain: $threads_per_domain"
    
    # Create main results directory with timestamp
    local timestamp
    timestamp=$(date +"%Y%m%d_%H%M%S")
    local main_output_dir="bulk_enum_$timestamp"
    if ! safe_mkdir "$main_output_dir"; then
        return 1
    fi
    
    main_output_dir=$(readlink -f "$main_output_dir")
    
    # Count total domains
    local total_domains
    total_domains=$(grep -v "^#" "$domain_list" | grep -v "^$" | wc -l)
    echo "[*] Total domains to process: $total_domains"
    
    # Start time tracking
    local bulk_start_time
    bulk_start_time=$(date +%s)
    
    # Create progress tracking files
    local progress_file="$main_output_dir/.progress"
    local failed_domains="$main_output_dir/failed_domains.txt"
    local completed_domains="$main_output_dir/completed_domains.txt"
    
    touch "$progress_file" "$failed_domains" "$completed_domains"
    
    # Create a temporary script for the parallel execution
    local temp_script
    temp_script=$(mktemp)
    
    cat > "$temp_script" << 'SCRIPT_EOF'
#!/bin/bash

# Get the domain from the argument
domain="$1"
threads_per_domain="$2"
main_output_dir="$3"
progress_file="$4"
failed_domains="$5"
completed_domains="$6"
script_path="$7"

# Validate domain
if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
    echo "$(date) [!] Invalid domain format: $domain" >&2
    echo "$domain" >> "$failed_domains"
    exit 1
fi

echo "$(date) [*] Starting enumeration for: $domain"

# Source this script to get the subenum function and environment variables
source "$script_path"

# Define the specific output directory for this domain
domain_output_dir="${main_output_dir}/${domain}-results"

# Run enumeration, passing the final output directory directly
if subenum "$domain" "$threads_per_domain" "$domain_output_dir"; then
    echo "$(date) [+] ✓ Completed: $domain"
    echo "$domain" >> "$completed_domains"
    # Update progress
    completed_count=$(wc -l < "$completed_domains" 2>/dev/null || echo "0")
    echo "Progress: $completed_count domains completed" > "$progress_file"
else
    echo "$(date) [!] ✗ Failed: $domain" >&2
    echo "$domain" >> "$failed_domains"
    exit 1
fi
SCRIPT_EOF

    chmod +x "$temp_script"
    
    # Progress monitoring function
    monitor_progress() {
        local main_dir="$1"
        local total="$2"
        local progress_file="$3"
        
        while [ -f "$progress_file" ]; do
            if [ -f "$main_dir/completed_domains.txt" ] && [ -f "$main_dir/failed_domains.txt" ]; then
                local completed
                local failed
                completed=$(wc -l < "$main_dir/completed_domains.txt" 2>/dev/null || echo "0")
                failed=$(wc -l < "$main_dir/failed_domains.txt" 2>/dev/null || echo "0")
                local processed=$((completed + failed))
                
                if [ "$processed" -gt 0 ] && [ "$total" -gt 0 ]; then
                    local percentage=$((processed * 100 / total))
                    echo "[*] Progress: $processed/$total domains processed ($percentage%) - Completed: $completed, Failed: $failed"
                fi
            fi
            sleep 10
        done
    }
    
    # Start progress monitor in background
    monitor_progress "$main_output_dir" "$total_domains" "$progress_file" &
    local monitor_pid=$!
    
    echo "[*] Starting parallel enumeration..."
    
    # Get the absolute path of the script to pass to xargs
    local script_full_path
    script_full_path=$(readlink -f "${BASH_SOURCE[0]}")
    
    # Process domains in parallel with enhanced monitoring
    grep -v "^#" "$domain_list" | grep -v "^$" | \
    xargs -P "$parallel_jobs" -I {} "$temp_script" {} "$threads_per_domain" "$main_output_dir" "$progress_file" "$failed_domains" "$completed_domains" "$script_full_path"
    
    local bulk_exit_code=$?
    
    # Stop progress monitor
    rm -f "$progress_file"
    kill $monitor_pid 2>/dev/null
    wait $monitor_pid 2>/dev/null
    
    # Cleanup temporary script
    rm -f "$temp_script"
    
    # Calculate bulk processing time
    local bulk_end_time
    bulk_end_time=$(date +%s)
    local bulk_duration=$((bulk_end_time - bulk_start_time))
    
    # Create bulk summary
    local completed_count
    local failed_count
    completed_count=$(wc -l < "$completed_domains" 2>/dev/null || echo "0")
    failed_count=$(wc -l < "$failed_domains" 2>/dev/null || echo "0")
    
    # Calculate total subdomains found across all domains
    local total_subdomains=0
    local total_resolved=0
    local total_ips=0
    
    echo "[*] Calculating statistics across all domains..."
    
    for result_dir in "$main_output_dir"/*-results; do
        if [ -d "$result_dir" ]; then
            # Count subdomains
            if [ -f "$result_dir/all_subdomains_"*.txt ]; then
                local domain_subs
                domain_subs=$(cat "$result_dir/all_subdomains_"*.txt 2>/dev/null | wc -l || echo "0")
                total_subdomains=$((total_subdomains + domain_subs))
            fi
            
            # Count resolved
            if [ -f "$result_dir/final/"*"_final_resolved.txt" ]; then
                local domain_resolved
                domain_resolved=$(cat "$result_dir/final/"*"_final_resolved.txt" 2>/dev/null | wc -l || echo "0")
                total_resolved=$((total_resolved + domain_resolved))
            fi
            
            # Count IPs
            if [ -f "$result_dir/final/"*"_ips.txt" ]; then
                local domain_ips
                domain_ips=$(cat "$result_dir/final/"*"_ips.txt" 2>/dev/null | wc -l || echo "0")
                total_ips=$((total_ips + domain_ips))
            fi
        fi
    done
    
    # Create consolidated results
    echo "[*] Creating consolidated results..."
    
    # ConsolidATE all subdomains
    find "$main_output_dir" -name "all_subdomains_*.txt" -type f -exec cat {} + 2>/dev/null \
        | sort -u > "$main_output_dir/ALL_SUBDOMAINS_CONSOLIDATED.txt" \
        || echo "[!] Failed to consolidate all subdomains" >&2
    
    # Consolidate all resolved subdomains
    find "$main_output_dir" -name "*_final_resolved.txt" -type f -exec cat {} + 2>/dev/null \
        | sort -u > "$main_output_dir/ALL_RESOLVED_CONSOLIDATED.txt" \
        || echo "[!] Failed to consolidate all resolved subdomains" >&2
    
    # Consolidate all IPs
    find "$main_output_dir" -name "*_ips.txt" -type f -exec cat {} + 2>/dev/null \
        | sort -u > "$main_output_dir/ALL_IPS_CONSOLIDATED.txt" \
        || echo "[!] Failed to consolidate all IPs" >&2
    
    # Get final consolidated counts
    local consolidated_subs
    local consolidated_resolved
    local consolidated_ips
    consolidated_subs=$(wc -l < "$main_output_dir/ALL_SUBDOMAINS_CONSOLIDATED.txt" 2>/dev/null || echo "0")
    consolidated_resolved=$(wc -l < "$main_output_dir/ALL_RESOLVED_CONSOLIDATED.txt" 2>/dev/null || echo "0")
    consolidated_ips=$(wc -l < "$main_output_dir/ALL_IPS_CONSOLIDATED.txt" 2>/dev/null || echo "0")
    
    echo ""
    echo "+-------------------------------------------------------------------+"
    echo "|              BULK ENUMERATION COMPLETE                            |"
    echo "+-------------------------------------------------------------------+"
    echo "| Total domains: $total_domains"
    echo "| Completed domains: $completed_count"
    echo "| Failed domains: $failed_count"
    if [ "$total_domains" -gt 0 ]; then
        echo "| Success rate: $(( completed_count * 100 / total_domains ))%"
    fi
    echo "|"
    echo "| Total runtime: ${bulk_duration}s"
    if [ "$total_domains" -gt 0 ] && [ "$bulk_duration" -gt 0 ]; then
        echo "| Average time per domain: $((bulk_duration / total_domains))s"
    fi
    echo "| Parallel jobs: $parallel_jobs"
    echo "| Threads per domain: $threads_per_domain"
    echo "|"
    echo "| CONSOLIDATED RESULTS:"
    echo "| • Total subdomains: $consolidated_subs"
    echo "| • Resolved subdomains: $consolidated_resolved"
    echo "| • Unique IP addresses: $consolidated_ips"
    echo "|"
    echo "| Results directory: $main_output_dir"
    echo "+-------------------------------------------------------------------+"
    echo ""
    
    # Create comprehensive bulk summary file
    cat > "$main_output_dir/BULK_SUMMARY.txt" << EOF
Bulk Subdomain Enumeration Summary
=================================
Date: $(date)
Duration: ${bulk_duration} seconds
Average time per domain: $( [ "$total_domains" -gt 0 ] && [ "$bulk_duration" -gt 0 ] && echo $((bulk_duration / total_domains)) || echo "N/A" ) seconds

Configuration:
- Parallel jobs: $parallel_jobs
- Threads per domain: $threads_per_domain
- Input file: $domain_list

Domain Statistics:
- Total domains: $total_domains
- Completed domains: $completed_count
- Failed domains: $failed_count
- Success rate: $( [ "$total_domains" -gt 0 ] && echo $(( completed_count * 100 / total_domains )) || echo "N/A" )%

Consolidated Results:
- Total subdomains found: $consolidated_subs
- Resolved subdomains: $consolidated_resolved
- Unique IP addresses: $consolidated_ips

Key Files:
- ALL_SUBDOMAINS_CONSOLIDATED.txt - All discovered subdomains
- ALL_RESOLVED_CONSOLIDATED.txt - All resolved subdomains
- ALL_IPS_CONSOLIDATED.txt - All unique IP addresses
- completed_domains.txt - Successfully processed domains
- failed_domains.txt - Failed domain processing

Failed Domains:
$(cat "$failed_domains" 2>/dev/null || echo "None")

Individual Results:
$(find "$main_output_dir" -name "SUMMARY_*.txt" -exec basename {} \; 2>/dev/null | sort || echo "None found")

Performance Metrics:
- Domains processed per minute: $( [ "$bulk_duration" -gt 0 ] && echo $(( completed_count * 60 / bulk_duration )) || echo "0" )
- Subdomains found per minute: $( [ "$bulk_duration" -gt 0 ] && echo $(( consolidated_subs * 60 / bulk_duration )) || echo "0" )
EOF

    # Create top statistics if we have results
    if [ "$consolidated_subs" -gt 0 ]; then
        echo "" >> "$main_output_dir/BULK_SUMMARY.txt"
        echo "Top 10 Domains by Subdomain Count:" >> "$main_output_dir/BULK_SUMMARY.txt"
        
        for result_dir in "$main_output_dir"/*-results; do
            if [ -d "$result_dir" ]; then
                local domain_name
                domain_name=$(basename "$result_dir" | sed 's/-results$//')
                local sub_count
                sub_count=$(find "$result_dir" -name "all_subdomains_*.txt" -type f -exec cat {} + 2>/dev/null | wc -l || echo "0")
                echo "$domain_name: $sub_count subdomains"
            fi
        done | sort -k2 -nr | head -10 >> "$main_output_dir/BULK_SUMMARY.txt"
    fi

    echo "[+] Bulk summary saved to: $main_output_dir/BULK_SUMMARY.txt"
    echo "[+] Consolidated results available in:"
    echo "    - $main_output_dir/ALL_SUBDOMAINS_CONSOLIDATED.txt"
    echo "    - $main_output_dir/ALL_RESOLVED_CONSOLIDATED.txt" 
    echo "    - $main_output_dir/ALL_IPS_CONSOLIDATED.txt"
    
    if [ $bulk_exit_code -eq 0 ]; then
        echo "[+] Bulk enumeration completed successfully"
    else
        echo "[!] Bulk enumeration completed with some failures"
        echo "[!] Check $main_output_dir/failed_domains.txt for failed domains"
    fi
    
    return $bulk_exit_code
}

# Export the functions so they're available to subshells
export -f subenum
export -f sublist

# Main execution check
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "[*] Subdomain Enumeration Script Loaded"
    echo "[*] Usage:"
    echo "    subenum <domain> [threads] <output_dir>  - Single domain enumeration"
    echo "    sublist <file> [jobs] [threads]          - Bulk domain enumeration"
    echo ""
    echo "[*] Examples:"
    echo "    # Source the script first:"
    echo "    source ./rocket_enum.sh"
    echo ""
    echo "    # Single domain:"
    echo "    subenum example.com 100 example-results"
    echo ""
    echo "    # Bulk domains:"
    echo "    sublist domains.txt 5 50"
    echo ""
    echo "    # Command-line execution:"
    echo "    ./rocket_enum.sh subenum example.com 100"
    echo ""
    echo "[!] SECURITY WARNING: Remove API keys before sharing this script"
    
    # Check if function was called directly
    if [ $# -gt 0 ]; then
        case "$1" in
            "subenum")
                shift
                # For direct command-line execution, create the output directory automatically
                domain_arg="$1"
                threads_arg="${2:-100}"
                output_dir_arg="${domain_arg}-results"
                subenum "$domain_arg" "$threads_arg" "$output_dir_arg"
                ;;
            "sublist")
                shift
                sublist "$@"
                ;;
            *)
                echo "[!] Unknown command: $1"
                echo "[!] Use 'subenum' or 'sublist'"
                exit 1
                ;;
        esac
    fi
fi