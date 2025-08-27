#!/bin/bash

# Script for hashing a password and encrypting/decrypting a file in-place.
# It uses Python's passlib for hashing and OpenSSL for encryption.

# --- DEPENDENCY CHECK FUNCTION ---
# Checks if the 'passlib' Python library is installed. If not, it attempts
# to install it for the current user using pip.
function _check_and_install_passlib() {
  # Check if passlib is installed by trying to import it silently.
  if ! python -c "import passlib" &> /dev/null; then
    echo "🐍 'passlib' library not found. Attempting to install for the current user..."
    
    # Check if pip is available before trying to use it.
    if ! command -v pip &> /dev/null; then
        echo "❌ [FAIL]: 'pip' command not found. Please install pip to automatically install dependencies." >&2
        return 1
    fi

    # Install the library for the current user only (--user).
    if pip install --user passlib; then
      echo "✅ 'passlib' installed successfully."
    else
      echo "❌ [FAIL]: Failed to install 'passlib'. Please install it manually using 'pip install passlib'." >&2
      return 1
    fi
  fi
  return 0
}
readonly -f _check_and_install_passlib

# --- HASHING FUNCTION ---
# Hashes a given string using SHA512-Crypt with 5000 rounds.
# This function requires Python 3 and the 'passlib' library.
# Arguments:
#   $1: The string (password) to hash.
function _cellar_sha512() {
  # Ensure input text is provided.
  local in_text=${1:-}
  if [[ -z "$in_text" ]]; then
    echo "Error: No text provided for hashing." >&2
    return 1
  fi

  # Python 3 script to perform the hashing. Note the print() function syntax.
  local script="from passlib.hash import sha512_crypt; print(sha512_crypt.using(rounds=5000).hash(\"$in_text\"))"

  # Execute the Python script.
  python -c "$script"
}
readonly -f _cellar_sha512

# --- ENCRYPTION FUNCTION ---
# Encrypts a file in-place using a password with OpenSSL (AES-256-CBC).
# Arguments:
#   $1: The password for encryption.
#   $2: The path to the file to encrypt.
function _cellar_encrypt_file() {
  local password=$1
  local file=$2
  local tmpfile="${file}.tmp"

  # Check if the input file exists.
  if [[ ! -f "$file" ]]; then
    echo "❌ [FAIL]: Input file not found: $file" >&2
    return 1
  fi

  # Use OpenSSL to encrypt the file to a temporary location.
  if openssl enc -aes-256-cbc -salt -pbkdf2 -in "$file" -out "$tmpfile" -pass pass:"$password"; then
    # On success, replace the original file with the encrypted version.
    mv "$tmpfile" "$file"
    echo "✅ [SUCCESS]: File '$file' encrypted in-place."
  else
    # On failure, remove the temporary file to clean up.
    rm -f "$tmpfile"
    echo "❌ [FAIL]: Encryption failed." >&2
    return 1
  fi
}
readonly -f _cellar_encrypt_file

# --- DECRYPTION FUNCTION ---
# Decrypts a file in-place using a password with OpenSSL.
# Arguments:
#   $1: The password for decryption.
#   $2: The path to the file to decrypt.
function _cellar_decrypt_file() {
    local password=$1
    local file=$2
    local tmpfile="${file}.tmp"

    if [[ ! -f "$file" ]]; then
        echo "❌ [FAIL]: Input file not found: $file" >&2
        return 1
    fi

    # Use OpenSSL to decrypt the file to a temporary location.
    if openssl enc -d -aes-256-cbc -pbkdf2 -in "$file" -out "$tmpfile" -pass pass:"$password"; then
        # On success, replace the encrypted file with the decrypted version.
        mv "$tmpfile" "$file"
        echo "✅ [SUCCESS]: File '$file' decrypted in-place."
    else
        # On failure, remove the temporary file to clean up.
        rm -f "$tmpfile"
        echo "❌ [FAIL]: Decryption failed. Check your password or the file's integrity." >&2
        return 1
    fi
}
readonly -f _cellar_decrypt_file


# --- USAGE INSTRUCTIONS ---
# Displays how to use the script.
function _cellar_usage() {
cat << EOF
cellar 2.1 -- a script to hash a password and encrypt or decrypt a file in-place.

Usage: cellar <MODE> [OPTIONS]

Mode (required, must be the first argument):
  -e                    Encrypt mode: Hashes password and encrypts a file.
  -d                    Decrypt mode: Decrypts a file.
  -?                    Display this help message.

Options:
  -p "your password"    (Required) The password for the operation.
  -i /path/to/file      (Required) The file to encrypt/decrypt in-place.

Example (Encrypt):
  cellar -e -p "mysecret" -i data.txt

Example (Decrypt):
  cellar -d -p "mysecret" -i data.txt
EOF
}
readonly -f _cellar_usage

# --- MAIN FUNCTION ---
# Parses command-line options and orchestrates the hashing and encryption/decryption.
function cellar() {
  local password=""
  local infile=""
  local mode=""
  OPTIND=1 # FIX: Reset getopts index to ensure reliable parsing.

  # First, determine the mode (-e or -d) for more robust parsing.
  # The mode flag must be the first argument.
  case "$1" in
    -e)
      mode="encrypt"
      shift # Consume the -e flag so getopts doesn't see it
      ;;
    -d)
      mode="decrypt"
      shift # Consume the -d flag
      ;;
    -\?|--help)
      _cellar_usage
      return 0
      ;;
  esac

  # Now, parse the remaining options.
  while getopts ":p:i:" opt; do
    case $opt in
      p ) password="$OPTARG" ;;
      i ) infile="$OPTARG" ;;
      \? )
        echo "Error: Unknown option '-$OPTARG' provided." >&2
        _cellar_usage
        return 1
        ;;
      :  )
        echo "Error: Option '-$OPTARG' requires an argument." >&2
        _cellar_usage
        return 1
        ;;
    esac
  done

  # Validate that a mode and all required arguments were provided.
  if [[ -z "$mode" || -z "$password" || -z "$infile" ]]; then
    echo "Error: Missing required mode or arguments." >&2
    _cellar_usage
    return 1
  fi

  if [[ "$mode" == "encrypt" ]]; then
    # --- Step 1: Check for and install dependencies if needed ---
    if ! _check_and_install_passlib; then
      # The check function will print an error, so we just exit.
      return 1
    fi

    # --- Step 2: Hash the password and print it ---
    echo "--- Generating Hash ---"
    local generated_hash
    generated_hash=$(_cellar_sha512 "$password")
    if [[ -n "$generated_hash" ]]; then
      echo "Password Hash: $generated_hash"
      echo "" # Add a newline for better formatting.
    else
      echo "❌ [FAIL]: Could not generate hash." >&2
      return 1
    fi

    # --- Step 3: Encrypt the file with the original password ---
    echo "--- Encrypting File ---"
    _cellar_encrypt_file "$password" "$infile"
  elif [[ "$mode" == "decrypt" ]]; then
    # --- Decrypt the file ---
    echo "--- Decrypting File ---"
    _cellar_decrypt_file "$password" "$infile"
  fi
}
readonly -f cellar

# Execute the main function with all command-line arguments.
cellar "$@"