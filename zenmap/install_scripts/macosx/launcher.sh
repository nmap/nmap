#!/bin/zsh
set -euo pipefail

readonly LOGFILE="$HOME/.script_log"

# Log errors to a file
log_error() {
    local message="$1"
    echo "$(date) [ERROR]: $message" >> "$LOGFILE"
    echo "ERROR: $message" 1>&2
}

# Validate input
validate_input() {
    if (( $# == 0 )); then
        log_error "No input provided."
        exit 1
    fi
}

# Verify environment variable
verify_env_var() {
    local var_name="$1"
    if [[ -z "${(P)var_name}" ]]; then
        log_error "Environment variable $var_name is not set"
        exit 1
    fi
}

# Setup environment variables
setup_environment() {
    # Get various directory paths
    local name bundle bundle_contents bundle_res bundle_lib bundle_bin bundle_data bundle_etc
    name=$(basename "$0")
    bundle=$(dirname "$(dirname "$(dirname "$0")")")
    bundle_contents="$bundle/Contents"
    bundle_res="$bundle_contents/Resources"
    bundle_lib="$bundle_res/lib"
    bundle_bin="$bundle_res/bin"
    bundle_data="$bundle_res/share"
    bundle_etc="$bundle_res/etc"

    # Export necessary environment variables and verify they are set
    export DYLD_LIBRARY_PATH="$bundle_lib" \
           XDG_CONFIG_DIRS="$bundle_etc/xdg" \
           XDG_DATA_DIRS="$bundle_data" \
           GTK_DATA_PREFIX="$bundle_res" \
           GTK_EXE_PREFIX="$bundle_res" \
           GTK_PATH="$bundle_res" \
           GTK2_RC_FILES="$bundle_etc/gtk-2.0/gtkrc" \
           GTK_IM_MODULE_FILE="$bundle_etc/gtk-2.0/gtk.immodules" \
           GDK_PIXBUF_MODULE_FILE="$bundle_lib/gdk-pixbuf-2.0/2.10.0/loaders.cache" \
           PANGO_LIBDIR="$bundle_lib" \
           PANGO_SYSCONFDIR="$bundle_etc"

    verify_env_var "DYLD_LIBRARY_PATH"
    # Add remaining environment variables with the same pattern...
}

# Setup locale
setup_locale() {
    local lang
    if [ -z ${lang+x} ]; then 
        lang=$(defaults read /Library/Preferences/.GlobalPreferences AppleLocale 2>/dev/null || log_error "Unable to read AppleLocale.")
        export LANG="${lang}.UTF-8"
        verify_env_var "LANG"
    fi
}

# Setup charset
setup_charset() {
    local bundle_lib="$1"
    if [ -f "$bundle_lib/charset.alias" ]; then
        export CHARSETALIASDIR="$bundle_lib"
        verify_env_var "CHARSETALIASDIR"
    fi
}

# Include environment file
include_env_file() {
    local bundle_res="$1"
    if [ -f "$bundle_res/environment.sh" ]; then
        # Only source if the owner is the current user and no others have write permissions
        if [[ "$(stat -f '%Su' "$bundle_res/environment.sh")" == "$(whoami)" ]] && [[ ! $(stat -f '%A' "$bundle_res/environment.sh") =~ .[26789]. ]]; then
            source "$bundle_res/environment.sh" || log_error "Unable to source environment.sh."
        else
            log_error "environment.sh file has insecure permissions. It should be owned by the user and not writable by others."
            exit 1
        fi
    fi
}

# Strip arguments added by OS
strip_os_args() {
    if /bin/expr "x$1" = "x-psn_.*" > /dev/null; then
        shift 1
    fi
}

# Run Python command
run_python_command() {
    local python="$1"
    local bundle_bin="$2"
    "$python" -c $'import os\nif os.getuid()!=os.geteuid():os.setuid(os.geteuid())\n'"os.execl(\"$python\",\"$python\",\"$bundle_bin/zenmap\")" || log_error "Unable to run Python command."
}

# Main function
main() {
    validate_input "$@"
    setup_environment
    setup_locale
    setup_charset "$bundle_lib"
    include_env_file "$bundle_res"
    strip_os_args "$@"
    run_python_command "$PYTHON" "$bundle_bin"
}

# Run main with all arguments
main "$@"
