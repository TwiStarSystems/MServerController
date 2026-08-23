#!/bin/bash

# MServer Installation Script for Debian/Ubuntu
# This script installs, updates, and configures MServer (Python version)

set -e

# Configuration
INSTALL_DIR="/opt/mserver"
REPO_URL="https://github.com/TwiStarSystems/MServer.git"
SERVICE_NAME="mserver"
# Root-owned privileged host-control helper (see mserver-hostctl). Lives OUTSIDE
# the www-data-writable app dir so the panel can only invoke it via sudo, never
# rewrite it. The sudoers rule scopes www-data to just this one command.
HOSTCTL_DEST="/usr/local/sbin/mserver-hostctl"
SUDOERS_FILE="/etc/sudoers.d/mserver"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}==========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}→ $1${NC}"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root (use sudo)"
        exit 1
    fi
}

# Check Linux distribution
check_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO="$ID"
        VERSION_ID="${VERSION_ID:-unknown}"
        
        case "$DISTRO" in
            debian)
                DEBIAN_VERSION=$(echo "$VERSION_ID" | cut -d. -f1)
                if [ "$DEBIAN_VERSION" != "unknown" ] && [ "$DEBIAN_VERSION" -lt 11 ]; then
                    print_warning "This script is designed for Debian 11 or newer."
                    echo "Current version: $VERSION_ID"
                    read -p "Continue anyway? (y/n) " -n 1 -r
                    echo
                    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                        exit 1
                    fi
                fi
                ;;
            ubuntu)
                print_info "Detected Ubuntu $VERSION_ID"
                ;;
            *)
                print_warning "This system ($DISTRO) may not be fully supported."
                read -p "Continue anyway? (y/n) " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    exit 1
                fi
                ;;
        esac
    else
        print_warning "Cannot detect Linux distribution."
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Read the app version out of the version file. The file holds `version=X.Y.Z`
# (server.py's read_version_file also accepts a bare X.Y.Z), so strip the prefix.
read_installed_version() {
    local f="$INSTALL_DIR/version"
    [ -f "$f" ] || return 1
    sed -n 's/^[[:space:]]*\(version[[:space:]]*=[[:space:]]*\)\{0,1\}\([0-9][0-9.]*\)[[:space:]]*$/\2/p' "$f" | head -n1
}

# Generate a secure random 64-hex-char key
generate_secret_key() {
    # openssl and /dev/urandom are both available on a base Debian/Ubuntu system;
    # python3 may not be installed yet when this runs, so it is only the last resort.
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    elif [ -r /dev/urandom ]; then
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
    else
        python3 -c "import secrets; print(secrets.token_hex(32))"
    fi
}

# Read PORT out of the (authoritative) .env file into $SERVER_PORT, so the
# systemd service and post-install messages always match what's actually
# configured — even when PORT was customized in .env.example/.env rather than
# entered interactively (there is no port prompt anymore).
read_env_port() {
    local env_file="$INSTALL_DIR/.env"
    SERVER_PORT=""
    if [ -f "$env_file" ]; then
        SERVER_PORT=$(grep -E '^PORT=' "$env_file" | tail -n1 | cut -d= -f2-)
    fi
    SERVER_PORT="${SERVER_PORT:-3000}"

    if ! [[ "$SERVER_PORT" =~ ^[0-9]+$ ]] || [ "$SERVER_PORT" -lt 1 ] || [ "$SERVER_PORT" -gt 65535 ]; then
        print_error "Invalid PORT '$SERVER_PORT' in $env_file — must be an integer between 1 and 65535."
        exit 1
    fi
}

# Set (replace or append) a KEY=VALUE line in an env file, in place.
# awk's index()==1 match avoids sed metacharacter issues in keys/values.
set_env_key() {
    local file="$1" key="$2" value="$3" tmp
    tmp="$(mktemp)"
    awk -v k="$key" -v v="$value" '
        index($0, k"=") == 1 { print k"="v; found=1; next }
        { print }
        END { if (!found) print k"="v }
    ' "$file" > "$tmp"
    mv "$tmp" "$file"
}

# Abort with a clear error if a required KEY is missing from an env file.
require_env_key() {
    local file="$1" key="$2"
    if ! grep -qE "^${key}=" "$file"; then
        print_error "Required config key '${key}' is missing from ${file}"
        print_error "The .env.example template is incomplete — aborting install."
        exit 1
    fi
}

# Prepare environment configuration. Values are taken from the .env.example
# template (see create_env_file); this only generates the secret and pins the
# prod-safe overrides the installer owns. No interactive prompts.
prompt_env_config() {
    print_header "Environment Configuration"

    FLASK_ENV="production"
    # Secure cookies: the app runs HTTP behind a TLS-terminating reverse proxy
    # that forwards X-Forwarded-Proto=https. Override in .env only for direct HTTP.
    SESSION_COOKIE_SECURE="true"

    print_info "Generating secure secret key..."
    SECRET_KEY=$(generate_secret_key)
    print_success "Secret key generated"

    print_info "Other defaults are read from .env.example. Edit .env after install to tailor."
    echo ""
}

# Create .env from the canonical .env.example template, overriding only the
# values the installer owns (generated secret + prod-safe flags). The template
# is the single source of truth for every other key and its default.
create_env_file() {
    print_info "Creating .env file from template..."

    local script_dir template
    script_dir="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
    template="$script_dir/.env.example"

    if [ ! -f "$template" ]; then
        print_error "Configuration template not found: $template"
        print_error "Cannot generate .env without .env.example — aborting install."
        exit 1
    fi

    cp "$template" "$INSTALL_DIR/.env"

    # Override installer-owned values.
    set_env_key "$INSTALL_DIR/.env" SECRET_KEY "$SECRET_KEY"
    set_env_key "$INSTALL_DIR/.env" FLASK_ENV "$FLASK_ENV"
    set_env_key "$INSTALL_DIR/.env" SESSION_COOKIE_SECURE "$SESSION_COOKIE_SECURE"

    # Fail fast if the template was missing a must-have key.
    require_env_key "$INSTALL_DIR/.env" SECRET_KEY
    require_env_key "$INSTALL_DIR/.env" FLASK_ENV
    require_env_key "$INSTALL_DIR/.env" PORT

    # Never ship the placeholder secret.
    if grep -qE '^SECRET_KEY=your-random-secret-key-here$' "$INSTALL_DIR/.env"; then
        print_error "SECRET_KEY was not generated correctly — aborting install."
        exit 1
    fi

    # Set proper permissions on .env file
    chmod 600 "$INSTALL_DIR/.env"
    chown www-data:www-data "$INSTALL_DIR/.env"

    print_success ".env file created from template"
    echo "  Location: $INSTALL_DIR/.env"
    echo "  Permissions: 600 (owner read/write only)"
    echo "  Tailor ports, paths, JVM args and limits in .env, then restart the service."
    echo ""
}



# Install the newest available Java JRE (21+)
# Tries standard apt packages first (25 → 21), then falls back to Eclipse
# Temurin (Adoptium) — the official OpenJDK distribution for newer versions.
install_java() {
    JAVA_PKG=""

    print_info "Searching for latest Java in system repositories..."
    for version in 25 24 23 22 21; do
        if apt-cache show "openjdk-${version}-jre-headless" >/dev/null 2>&1; then
            JAVA_PKG="openjdk-${version}-jre-headless"
            break
        fi
    done

    if [ -n "$JAVA_PKG" ]; then
        print_info "Installing $JAVA_PKG from system packages..."
        apt-get install -y "$JAVA_PKG"
    else
        print_info "Java 21+ not found in system repos. Adding Eclipse Temurin (Adoptium) repository..."
        apt-get install -y wget apt-transport-https gnupg

        # Import Adoptium GPG key
        wget -qO /tmp/adoptium.gpg "https://packages.adoptium.net/artifactory/api/gpg/key/public"
        gpg --batch --dearmor -o /etc/apt/trusted.gpg.d/adoptium.gpg /tmp/adoptium.gpg
        rm -f /tmp/adoptium.gpg

        # Add Adoptium apt repository for the current distro codename
        DISTRO_CODENAME=$(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release)
        echo "deb https://packages.adoptium.net/artifactory/deb ${DISTRO_CODENAME} main" \
            | tee /etc/apt/sources.list.d/adoptium.list
        apt-get update

        # Try Temurin JRE packages newest first
        for version in 25 24 23 22 21; do
            if apt-cache show "temurin-${version}-jre" >/dev/null 2>&1; then
                JAVA_PKG="temurin-${version}-jre"
                break
            fi
        done

        if [ -n "$JAVA_PKG" ]; then
            print_info "Installing $JAVA_PKG from Eclipse Temurin..."
            apt-get install -y "$JAVA_PKG"
        else
            print_warning "Could not find Java 21+ via Temurin. Installing system default Java."
            apt-get install -y default-jre-headless
        fi
    fi

    # If multiple Java versions are installed, make the newest the system default
    if command -v update-java-alternatives >/dev/null 2>&1; then
        update-java-alternatives --set "$(update-java-alternatives --list | sort -t' ' -k3 -rV | head -1 | awk '{print $1}')" 2>/dev/null || true
    fi
}

# Install system dependencies
install_dependencies() {
    print_info "Updating system packages..."
    apt-get update
    apt-get upgrade -y

    print_info "Installing required packages..."
    # Core runtime tools. sudo is required by install_hostctl_helper (visudo) and
    # at runtime by the panel's `sudo mserver-hostctl` call — a minimal Debian
    # install does not ship it.
    apt-get install -y curl wget git unzip sudo

    # Python runtime + build tools needed to compile C extensions
    # (cryptography, Pillow/qrcode, eventlet all require headers at build time)
    apt-get install -y \
        python3 python3-pip python3-venv python3-dev \
        build-essential libffi-dev \
        libjpeg-dev libpng-dev zlib1g-dev

    install_java

    echo ""
    print_success "Dependencies installed"
    echo "  Python version: $(python3 --version)"
    echo "  pip version: $(pip3 --version 2>/dev/null || echo 'pip installed via venv')"
    echo "  Java version: $(java -version 2>&1 | head -n 1)"
}

# Install the root-owned host-control helper + its scoped sudoers rule. This is
# what lets the (non-root) panel run host updates: the operator supplies the root
# password per run, and sudo only ever permits this one fixed command.
install_hostctl_helper() {
    local src="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}/mserver-hostctl"
    if [ ! -f "$src" ]; then
        print_warning "mserver-hostctl not found at $src — skipping host-control helper."
        print_warning "Panel-driven OS updates will be unavailable until it is installed."
        return 0
    fi

    print_info "Installing host-control helper to $HOSTCTL_DEST..."
    install -o root -g root -m 0755 "$src" "$HOSTCTL_DEST"

    # Scoped sudoers rule: www-data may run ONLY the helper, authenticating with
    # the root password (rootpw) — www-data itself has no password. Validate with
    # visudo before installing so a bad rule can never lock out sudo.
    print_info "Installing sudoers rule ($SUDOERS_FILE)..."
    local tmp
    tmp="$(mktemp)"
    cat > "$tmp" <<EOF
# MServer — allow the panel (www-data) to run ONLY the host-control helper,
# authenticating with the root password. Managed by install.sh; do not edit.
Defaults:www-data rootpw
Defaults:www-data !requiretty
www-data ALL=(root) $HOSTCTL_DEST
EOF
    if visudo -cf "$tmp" >/dev/null 2>&1; then
        install -o root -g root -m 0440 "$tmp" "$SUDOERS_FILE"
        rm -f "$tmp"
        print_success "Host-control helper + sudoers rule installed"
        print_info "Panel OS updates require the root account to have a password set."
    else
        rm -f "$tmp"
        print_error "Generated sudoers rule failed validation — NOT installing it."
        print_warning "Panel-driven OS updates will be unavailable."
    fi
}

# Abort if the system python3 is older than MServer's minimum (3.10).
check_python_version() {
    local py_version major minor
    py_version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "0.0")
    major="${py_version%%.*}"
    minor="${py_version##*.}"

    if [ "$major" -lt 3 ] 2>/dev/null || { [ "$major" -eq 3 ] && [ "$minor" -lt 10 ]; }; then
        print_error "Python $py_version detected, but MServer requires Python 3.10 or newer."
        print_error "Install a newer python3 (e.g. via deadsnakes or a newer Debian/Ubuntu release) and re-run this script."
        exit 1
    fi

    print_success "Python $py_version meets the minimum requirement (3.10+)"
}

# Setup Python virtual environment and install packages
setup_python_env() {
    check_python_version

    print_info "Setting up Python virtual environment..."

    # Remove old venv if exists
    if [ -d "$INSTALL_DIR/venv" ]; then
        rm -rf "$INSTALL_DIR/venv"
    fi
    
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    
    print_info "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r "$INSTALL_DIR/requirements.txt"
    
    deactivate
    print_success "Python environment configured"
}

# Create necessary directories
create_directories() {
    print_info "Creating directories..."
    mkdir -p "$INSTALL_DIR/servers"
    mkdir -p "$INSTALL_DIR/backups"
    mkdir -p "$INSTALL_DIR/uploads"
    mkdir -p "$INSTALL_DIR/uploads/jobs"
    mkdir -p "$INSTALL_DIR/tools"
    mkdir -p "$INSTALL_DIR/configs"
    mkdir -p "$INSTALL_DIR/public/resourcepacks"
    mkdir -p "$INSTALL_DIR/serverexecutables"/{vanilla,paper,purpur,spigot,fabric,folia,forge,neoforge,bedrock}
    print_success "Directories created"
}

# Set proper permissions
set_permissions() {
    print_info "Setting permissions..."
    chown -R www-data:www-data "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    # Secure sensitive files
    if [ -f "$INSTALL_DIR/.env" ]; then
        chmod 600 "$INSTALL_DIR/.env"
    fi
    print_success "Permissions configured"
}

# Create systemd service
create_service() {
    print_info "Creating systemd service..."
    
    local exec_start="$INSTALL_DIR/venv/bin/python server.py --port ${SERVER_PORT:-3000}"
    local service_port="${SERVER_PORT:-3000}"
    
    cat > /etc/systemd/system/mserver.service <<EOF
[Unit]
Description=MServer - Minecraft Server Manager
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=$INSTALL_DIR
ExecStart=$exec_start
Restart=always
RestartSec=10
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=mserver
Environment=PORT=$service_port

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service created"
}

# Start services
start_services() {
    print_info "Starting services..."
    systemctl enable mserver
    systemctl start mserver
    
    sleep 2
    if systemctl is-active --quiet mserver; then
        print_success "MServer service is running"
        return 0
    else
        print_error "Service failed to start"
        return 1
    fi
}

# Restart services (for updates)
restart_services() {
    print_info "Restarting services..."
    
    if systemctl is-active --quiet mserver; then
        systemctl restart mserver
    else
        systemctl start mserver
    fi
    
    sleep 2
    if systemctl is-active --quiet mserver; then
        print_success "MServer service is running"
        return 0
    else
        print_error "Service failed to start"
        return 1
    fi
}

# Show completion message
show_completion() {
    local action="$1"
    echo ""
    print_header "${action} Complete!"
    echo "MServer is now running."
    echo ""
    
    # MServer serves plain HTTP; put it behind your reverse proxy for TLS.
    echo "Configuration:"
    echo "  Transport: HTTP on port ${SERVER_PORT:-3000} (place your reverse proxy in front for HTTPS)"
    echo ""
    echo "Access the web interface (direct / behind your proxy) at:"
    echo "  http://$(hostname -I | awk '{print $1}'):${SERVER_PORT:-3000}"
    echo "  or"
    echo "  http://localhost:${SERVER_PORT:-3000}"
    echo ""

    echo "First-run setup:"
    echo "  Open the web interface in a browser — you'll be prompted to create"
    echo "  the administrator account. No default password is created."
    echo ""

    echo "Service management commands:"
    echo "  Start:   sudo systemctl start mserver"
    echo "  Stop:    sudo systemctl stop mserver"
    echo "  Restart: sudo systemctl restart mserver"
    echo "  Status:  sudo systemctl status mserver"
    echo ""
    echo "Logs:"
    echo "  App logs: sudo journalctl -u mserver -f"
    echo ""
}

# Fresh installation
do_install() {
    print_header "Fresh Installation"
    
    check_distro

    # Ask the destructive question FIRST, before spending time on apt or
    # generating anything — answering "no" here aborts, so nothing should have
    # been installed or upgraded by that point.
    if [ -d "$INSTALL_DIR" ]; then
        print_warning "Directory $INSTALL_DIR already exists."
        print_warning "A fresh install DELETES it entirely — including msc.db (all users,"
        print_warning "servers, schedules, API keys), servers/ (every world) and backups/."
        print_warning "To keep that data, cancel and run: sudo $0 update"
        read -p "Remove and reinstall? This will DELETE all data! (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            # Stop service if running
            systemctl stop mserver 2>/dev/null || true
            systemctl disable mserver 2>/dev/null || true
            rm -rf "$INSTALL_DIR"
        else
            print_error "Installation cancelled."
            exit 1
        fi
    fi

    install_dependencies

    # Generate the secret / pin prod-safe env values. Runs after
    # install_dependencies so the tools it needs are guaranteed present.
    prompt_env_config
    
    # Determine source directory (where install.sh is located)
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    
    # Copy or clone files
    if [ -f "$SCRIPT_DIR/server.py" ]; then
        print_info "Copying files from source directory..."
        mkdir -p "$INSTALL_DIR"
        
        # Copy all application files
        cp "$SCRIPT_DIR/server.py" "$INSTALL_DIR/"
        cp "$SCRIPT_DIR/api_manager.py" "$INSTALL_DIR/"
        cp "$SCRIPT_DIR/db.py" "$INSTALL_DIR/"
        cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
        cp "$SCRIPT_DIR/version" "$INSTALL_DIR/" 2>/dev/null || true
        cp "$SCRIPT_DIR/.env.example" "$INSTALL_DIR/" 2>/dev/null || true

        # Copy directories
        if [ -d "$SCRIPT_DIR/public" ]; then
            cp -r "$SCRIPT_DIR/public" "$INSTALL_DIR/"
            print_success "Copied: public/"
        fi
        
        if [ -d "$SCRIPT_DIR/configs" ]; then
            cp -r "$SCRIPT_DIR/configs" "$INSTALL_DIR/"
            print_success "Copied: configs/"
        fi
        
        if [ -d "$SCRIPT_DIR/serverexecutables" ]; then
            cp -r "$SCRIPT_DIR/serverexecutables" "$INSTALL_DIR/"
            print_success "Copied: serverexecutables/"
        fi
        
        print_success "Application files copied"
    else
        print_info "Cloning from GitHub..."
        git clone "$REPO_URL" "$INSTALL_DIR"
        print_success "Repository cloned"
        # Files (including .env.example) now live in $INSTALL_DIR, not the
        # original invocation directory — repoint SCRIPT_DIR so create_env_file
        # (and anything else keyed off it) finds them.
        SCRIPT_DIR="$INSTALL_DIR"
    fi
    
    cd "$INSTALL_DIR"

    # Install the root-owned host-control helper + sudoers rule (enables the
    # panel's Updates tab and `install.sh os-update`).
    install_hostctl_helper

    # Create .env file with user configuration
    create_env_file
    read_env_port

    setup_python_env
    create_directories
    set_permissions
    create_service
    
    if start_services; then
        show_completion "Installation"
    else
        print_error "Installation completed with warnings"
        echo "Check logs with: sudo journalctl -u mserver -xe"
        exit 1
    fi
}

# Update existing installation (preserves all configs and data)
#   do_update             update the app layer only
#   do_update --with-os   update the app layer, then also patch the host OS/Java
do_update() {
    local with_os="false" arg
    for arg in "$@"; do
        case "$arg" in
            --with-os) with_os="true" ;;
            *) print_error "Unknown update option: $arg"; exit 1 ;;
        esac
    done

    print_header "Update Installation"

    # Check if installation exists
    if [ ! -d "$INSTALL_DIR" ]; then
        print_error "No existing installation found at $INSTALL_DIR"
        echo "Please run a fresh installation first."
        exit 1
    fi

    # Determine source directory (where install.sh is located)
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

    # Refuse early if the source and the install dir are the same directory: the
    # copy step below would `cp` each file onto itself, which fails — and by then
    # the service is stopped and the DB is stashed in /tmp. A plain-files install
    # has no git remote to pull from either, so there is nothing to update from.
    if [ "$SCRIPT_DIR" = "$INSTALL_DIR" ] && [ ! -d "$INSTALL_DIR/.git" ]; then
        print_error "Cannot update: this script is running from $INSTALL_DIR itself,"
        print_error "and that directory is not a git checkout — there is no source to update from."
        print_error "Run install.sh from a source checkout instead, e.g.:"
        print_error "  cd /root/MServer && sudo ./install.sh update"
        exit 1
    fi
    
    # Display what will be preserved
    print_info "Files and data to be PRESERVED during update:"
    echo "  • msc.db (SQLite database — users, servers, schedules, tasks, stats, API keys)"
    echo "  • settings.json (app settings)"
    echo "  • servers/* (all game server data)"
    echo "  • backups/* (all backups)"
    echo "  • uploads/* (uploaded files)"
    echo ""
    
    read -p "Continue with update? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Update cancelled."
        exit 0
    fi
    
    # Stop the service
    print_info "Stopping MServer service..."
    systemctl stop mserver 2>/dev/null || true
    sleep 2
    
    # List of critical files to preserve
    local preserve_files=(
        "msc.db"
        "settings.json"
        ".env"
    )
    
    # Create temporary backup directory
    local backup_dir="/tmp/mserver_update_backup_$$"
    mkdir -p "$backup_dir"
    print_info "Creating temporary backup of critical files..."
    
    for file in "${preserve_files[@]}"; do
        if [ -f "$INSTALL_DIR/$file" ]; then
            cp "$INSTALL_DIR/$file" "$backup_dir/"
            print_success "  Backed up: $file"
        fi
    done
    
    print_info "Source directory: $SCRIPT_DIR"

    # Update application files. Same-dir (git checkout at $INSTALL_DIR) falls
    # through to the git-pull branch — there is nothing to copy in that case.
    if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ] && [ -f "$SCRIPT_DIR/server.py" ]; then
        print_info "Updating application files from source directory..."
        
        # Copy core application files
        cp -f "$SCRIPT_DIR/server.py" "$INSTALL_DIR/"
        print_success "  Updated: server.py"
        
        cp -f "$SCRIPT_DIR/api_manager.py" "$INSTALL_DIR/"
        print_success "  Updated: api_manager.py"
        
        cp -f "$SCRIPT_DIR/db.py" "$INSTALL_DIR/"
        print_success "  Updated: db.py"
        
        cp -f "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
        print_success "  Updated: requirements.txt"
        
        # Update version file
        if [ -f "$SCRIPT_DIR/version" ]; then
            cp -f "$SCRIPT_DIR/version" "$INSTALL_DIR/"
            print_success "  Updated: version"
        fi

        # Refresh the .env.example reference template (does NOT touch live .env)
        if [ -f "$SCRIPT_DIR/.env.example" ]; then
            cp -f "$SCRIPT_DIR/.env.example" "$INSTALL_DIR/"
            print_success "  Updated: .env.example"
        fi

        # Update frontend files (THIS IS CRITICAL FOR YOUR CHANGES)
        if [ -d "$SCRIPT_DIR/public" ]; then
            print_info "Removing old frontend files..."
            rm -rf "$INSTALL_DIR/public"
            print_info "Copying new frontend files..."
            cp -rf "$SCRIPT_DIR/public" "$INSTALL_DIR/"
            # Verify the copy succeeded and show file count
            if [ -d "$INSTALL_DIR/public" ]; then
                local file_count=$(find "$INSTALL_DIR/public" -type f | wc -l)
                print_success "  Updated: public/ (frontend files) - $file_count files copied"
                # Verify critical files
                [ -f "$INSTALL_DIR/public/app.js" ] && print_success "    ✓ app.js updated" || print_warning "    ⚠ app.js not found!"
                [ -f "$INSTALL_DIR/public/settings.js" ] && print_success "    ✓ settings.js updated" || print_warning "    ⚠ settings.js not found!"
            else
                print_error "  Failed to copy public/ directory!"
            fi
        else
            print_warning "  Source public/ directory not found at $SCRIPT_DIR/public"
        fi
        
        # Update configs directory (templates only)
        if [ -d "$SCRIPT_DIR/configs" ]; then
            rm -rf "$INSTALL_DIR/configs"
            cp -r "$SCRIPT_DIR/configs" "$INSTALL_DIR/"
            print_success "  Updated: configs/ (templates)"
        fi
        
        # Update serverexecutables (new jar files etc)
        if [ -d "$SCRIPT_DIR/serverexecutables" ]; then
            # Merge, don't replace - preserve any custom executables
            cp -r "$SCRIPT_DIR/serverexecutables"/* "$INSTALL_DIR/serverexecutables/" 2>/dev/null || true
            print_success "  Updated: serverexecutables/"
        fi
        
        print_success "Application files updated from local source"
    else
        print_info "Updating from GitHub..."
        cd "$INSTALL_DIR"
        
        # Stash any local changes
        git stash 2>/dev/null || true
        
        # Pull latest changes
        if git pull origin main; then
            print_success "Application files updated from GitHub"
        else
            print_warning "Git pull had issues, trying reset..."
            git fetch origin main
            git reset --hard origin/main
            print_success "Application files updated from GitHub (hard reset)"
        fi
        # Updated files (including .env.example) now live in $INSTALL_DIR, not
        # the original invocation directory — repoint SCRIPT_DIR so
        # create_env_file (and anything else keyed off it) finds them.
        SCRIPT_DIR="$INSTALL_DIR"
    fi
    
    # Restore all critical files from backup
    print_info "Restoring critical files and data..."
    for file in "${preserve_files[@]}"; do
        if [ -f "$backup_dir/$file" ]; then
            cp "$backup_dir/$file" "$INSTALL_DIR/"
            print_success "  Restored: $file"
        fi
    done
    
    # Cleanup temporary backup
    rm -rf "$backup_dir"
    
    cd "$INSTALL_DIR"
    
    # Check if .env file exists, if not prompt for configuration
    if [ ! -f "$INSTALL_DIR/.env" ]; then
        print_warning ".env file not found - environment configuration required"
        echo "The application now requires environment variables to be configured."
        echo ""
        prompt_env_config
        create_env_file
    fi
    read_env_port

    # Update Python virtual environment
    print_info "Updating Python virtual environment..."
    setup_python_env
    
    # Ensure all required directories exist
    create_directories
    
    # Fix permissions
    set_permissions

    # Refresh the root-owned host-control helper + sudoers rule (so existing
    # installs gain the Updates tab / os-update capability on update).
    install_hostctl_helper

    # Update systemd service (in case of changes)
    print_info "Updating systemd service..."
    create_service
    
    # Restart services with new code
    if restart_services; then
        echo ""
        print_success "Update completed successfully!"
        echo ""
        echo "Summary:"
        echo "  ✓ Application files updated"
        echo "  ✓ Python dependencies updated"
        echo "  ✓ All configurations preserved"
        echo "  ✓ All user data preserved"
        echo "  ✓ Service restarted"
        echo ""
        print_warning "IMPORTANT: Clear your browser cache!"
        echo "  To see the updated frontend changes:"
        echo "  1. Press Ctrl+Shift+R (or Cmd+Shift+R on Mac) to hard refresh"
        echo "  2. Or clear browser cache completely"
        echo "  3. Or use Incognito/Private browsing mode"
        echo ""
        echo "  Updated timestamp: $(date)"
        echo ""

        # Optionally patch the host OS/Java too (one-stop "app + os" update).
        if [ "$with_os" = "true" ]; then
            do_os_update
        fi

        show_completion "Update"
    else
        print_error "Update completed with warnings"
        echo "Service failed to restart. Check logs with:"
        echo "  sudo journalctl -u mserver -xe"
        exit 1
    fi
}

# In-place OS / host update (host layer only — never touches msc.db, .env, or app
# data). Delegates the privileged work to the shared mserver-hostctl helper so the
# logic is identical whether run from here or triggered by the panel.
#   do_os_update            apply upgrades (no service restart)
#   do_os_update --check    dry run: refresh + report pending, apply nothing
#   do_os_update --restart  apply upgrades, then restart the mserver service
do_os_update() {
    local check_only="false" do_restart="false" arg
    for arg in "$@"; do
        case "$arg" in
            --check)   check_only="true" ;;
            --restart) do_restart="true" ;;
            *) print_error "Unknown os-update option: $arg"; exit 1 ;;
        esac
    done

    # Make sure the helper is installed (e.g. first os-update on an older install).
    if [ ! -x "$HOSTCTL_DEST" ]; then
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
        install_hostctl_helper
    fi
    if [ ! -x "$HOSTCTL_DEST" ]; then
        print_error "Host-control helper not available at $HOSTCTL_DEST — cannot continue."
        exit 1
    fi

    if [ "$check_only" = "true" ]; then
        print_header "OS Update — Check (dry run)"
        "$HOSTCTL_DEST" os-check
        return 0
    fi

    print_header "OS / Host Update"
    "$HOSTCTL_DEST" os-update

    if [ "$do_restart" = "true" ]; then
        restart_services
    else
        print_info "mserver service left running (pass --restart to bounce it)."
    fi
    echo ""
    print_success "OS update finished"
}

# Uninstall
do_uninstall() {
    print_header "Uninstall MServer"
    
    # Check if installation exists
    if [ ! -d "$INSTALL_DIR" ]; then
        print_warning "No installation found at $INSTALL_DIR"
        echo "Nothing to uninstall."
        exit 0
    fi
    
    echo "This will remove:"
    echo "  - The application at $INSTALL_DIR"
    echo "  - The systemd service"
    echo "  - The host-control helper ($HOSTCTL_DEST) and its sudoers rule"
    echo ""
    print_warning "All server data, backups, and configurations will be DELETED!"
    echo ""
    read -p "Are you sure you want to uninstall? (y/n) " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Uninstall cancelled."
        exit 0
    fi
    
    # Double-check for servers data
    if [ -d "$INSTALL_DIR/servers" ] && [ "$(ls -A "$INSTALL_DIR/servers" 2>/dev/null)" ]; then
        echo ""
        print_warning "Server data detected in $INSTALL_DIR/servers"
        read -p "This will DELETE all server worlds and data! Type 'DELETE' to confirm: " confirm
        if [ "$confirm" != "DELETE" ]; then
            echo "Uninstall cancelled."
            exit 0
        fi
    fi
    
    print_info "Stopping services..."
    systemctl stop mserver 2>/dev/null || true
    systemctl disable mserver 2>/dev/null || true
    
    print_info "Removing systemd service..."
    rm -f /etc/systemd/system/mserver.service
    systemctl daemon-reload
    
    print_info "Removing application files..."
    rm -rf "$INSTALL_DIR"

    # Drop the privileged helper and the sudoers rule that grants www-data access
    # to it — leaving these behind would keep a root-capable grant for an app that
    # is no longer installed.
    if [ -f "$SUDOERS_FILE" ]; then
        print_info "Removing sudoers rule ($SUDOERS_FILE)..."
        rm -f "$SUDOERS_FILE"
    fi
    if [ -f "$HOSTCTL_DEST" ]; then
        print_info "Removing host-control helper ($HOSTCTL_DEST)..."
        rm -f "$HOSTCTL_DEST"
    fi
    
    echo ""
    print_success "MServer has been uninstalled"
    echo ""
}

# Show status
do_status() {
    print_header "MServer Status"
    
    # Check if installed
    if [ -d "$INSTALL_DIR" ]; then
        print_success "Installation found at $INSTALL_DIR"
        
        # Show version if available
        if [ -f "$INSTALL_DIR/version" ]; then
            echo "  Version: $(read_installed_version)"
        fi
        
        echo "  Mode: HTTP (TLS handled by your external reverse proxy)"
    else
        print_warning "No installation found at $INSTALL_DIR"
        return
    fi
    
    echo ""
    
    # Check service status
    echo "Service Status:"
    if systemctl is-active --quiet mserver 2>/dev/null; then
        print_success "MServer service is running"
    else
        print_warning "MServer service is not running"
    fi
    
    if systemctl is-enabled --quiet mserver 2>/dev/null; then
        print_success "Service is enabled (starts on boot)"
    else
        print_warning "Service is not enabled"
    fi
    
    echo ""
    
    # Show config info if database exists
    if [ -f "$INSTALL_DIR/msc.db" ]; then
        SERVER_COUNT=$(python3 -c "import sqlite3; c=sqlite3.connect('$INSTALL_DIR/msc.db'); print(c.execute('SELECT COUNT(*) FROM servers').fetchone()[0])" 2>/dev/null || echo "0")
        echo "Configured servers: $SERVER_COUNT"
    fi
    
    # Show disk usage
    if [ -d "$INSTALL_DIR" ]; then
        echo ""
        echo "Disk Usage:"
        du -sh "$INSTALL_DIR" 2>/dev/null || true
        if [ -d "$INSTALL_DIR/servers" ]; then
            du -sh "$INSTALL_DIR/servers" 2>/dev/null || true
        fi
        if [ -d "$INSTALL_DIR/backups" ]; then
            du -sh "$INSTALL_DIR/backups" 2>/dev/null || true
        fi
    fi

    # Host OS / patch status (read-only, from the apt cache — run `os-update
    # --check` for a fresh network refresh).
    echo ""
    echo "Host OS Status:"
    if [ -x "$HOSTCTL_DEST" ]; then
        "$HOSTCTL_DEST" status || true
    else
        echo "  Kernel: $(uname -r)"
        if [ -f /var/run/reboot-required ]; then
            print_warning "Reboot required (/var/run/reboot-required present)"
        fi
        echo "  (host-control helper not installed — run install/update to enable OS updates)"
    fi

    echo ""
}

# Show help/usage
show_usage() {
    echo "MServer Installation Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  install            Fresh installation (default if no option given)"
    echo "  update             Update the app layer only (preserves data)"
    echo "  update --with-os   Update the app layer, then also patch the host OS/Java"
    echo "  os-update          Patch the host OS + Java only (no app/data changes)"
    echo "  os-update --check  Dry run: report pending OS updates, apply nothing"
    echo "  os-update --restart  Patch the host, then restart the mserver service"
    echo "  status             Show installation + host OS status"
    echo "  uninstall          Remove MServer completely"
    echo "  help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0 install             # Fresh installation"
    echo "  sudo $0 update              # Update the app to the latest version"
    echo "  sudo $0 update --with-os    # Update app + patch the host OS"
    echo "  sudo $0 os-update --check   # See what OS updates are pending"
    echo "  $0 status                   # Check installation + host status"
    echo ""
}

# Interactive menu
show_menu() {
    print_header "MServer Installation Script"
    
    # Check if already installed
    if [ -d "$INSTALL_DIR" ]; then
        print_info "Existing installation detected at $INSTALL_DIR"
        if [ -f "$INSTALL_DIR/version" ]; then
            echo "  Version: $(read_installed_version)"
        fi
        echo ""
    fi
    
    echo "Please select an option:"
    echo ""
    echo "  1) Fresh Install       - Complete new installation"
    echo "  2) Update (App only)   - Update MServer app (preserves data)"
    echo "  3) Update (App + OS)   - Update the app, then patch the host OS/Java"
    echo "  4) OS Update           - Patch the host OS + Java only (no app changes)"
    echo "  5) Status              - Show installation + host OS status"
    echo "  6) Uninstall           - Remove MServer"
    echo "  7) Exit"
    echo ""
    read -p "Enter your choice [1-7]: " choice

    case $choice in
        1) check_root; do_install ;;
        2) check_root; do_update ;;
        3) check_root; do_update --with-os ;;
        4) check_root; do_os_update ;;
        5) do_status ;;
        6) check_root; do_uninstall ;;
        7) echo "Goodbye!"; exit 0 ;;
        *) print_error "Invalid option"; exit 1 ;;
    esac
}

# Main entry point
main() {
    case "${1:-}" in
        install)
            check_root
            do_install
            ;;
        update)
            check_root
            shift
            do_update "$@"
            ;;
        os-update|os_update)
            check_root
            shift
            do_os_update "$@"
            ;;
        status)
            do_status
            ;;
        uninstall|remove)
            check_root
            do_uninstall
            ;;
        help|-h|--help)
            show_usage
            ;;
        "")
            # No argument - show interactive menu
            show_menu
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main
main "$@"
