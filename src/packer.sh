#!/bin/bash

# XOR Packer - Script d'automatisation
# Usage: ./packer.sh <command> [options]

set -e  # Arrêter en cas d'erreur

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables globales
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STUB_GENERATOR="$SCRIPT_DIR/stub_generate"
TEMP_DIR="/tmp/xor_packer_$$"

# Fonction d'aide
show_help() {
    echo -e "${BLUE}=== XOR PACKER - Script d'automatisation ===${NC}"
    echo ""
    echo -e "${YELLOW}Usage:${NC}"
    echo "  $0 pack <executable> [output_name]     - Pack an executable with XOR encryption"
    echo "  $0 build                               - Build the stub generator"
    echo "  $0 clean                               - Clean generated files"
    echo "  $0 test <executable>                   - Quick test pack/unpack"
    echo "  $0 help                                - Show this help"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  $0 build                               # Build the packer"
    echo "  $0 pack /bin/ls my_packed_ls           # Pack 'ls' command"
    echo "  $0 pack ./my_program                   # Pack with auto-generated name"
    echo "  $0 test ./test_program                 # Quick test"
    echo ""
}

# Fonction de logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier si un fichier existe
check_file() {
    if [[ ! -f "$1" ]]; then
        log_error "File not found: $1"
        exit 1
    fi
}

# Vérifier si le générateur de stub existe
check_generator() {
    if [[ ! -f "$STUB_GENERATOR" ]]; then
        log_warn "Stub generator not found. Building it..."
        build_generator
    fi
}

# Construire le générateur de stub
build_generator() {
    log_info "Building XOR stub generator..."
    
    if [[ ! -f "$SCRIPT_DIR/stub_generate.c" ]]; then
        log_error "Source file stub_generate.c not found in $SCRIPT_DIR"
        exit 1
    fi
    
    cd "$SCRIPT_DIR"
    gcc -o stub_generate stub_generate.c
    
    if [[ $? -eq 0 ]]; then
        log_info "Stub generator built successfully: $STUB_GENERATOR"
    else
        log_error "Failed to build stub generator"
        exit 1
    fi
}

# Packer un exécutable
pack_executable() {
    local input_file="$1"
    local output_name="$2"
    
    # Vérifications
    check_file "$input_file"
    check_generator
    
    # Générer le nom de sortie si non spécifié
    if [[ -z "$output_name" ]]; then
        local basename_input=$(basename "$input_file")
        output_name="packed_${basename_input}"
    fi
    
    local stub_file="${output_name}.c"
    
    log_info "Packing executable: $input_file"
    log_info "Output name: $output_name"
    log_info "Stub file: $stub_file"
    
    # Créer le répertoire temporaire
    mkdir -p "$TEMP_DIR"
    
    # Générer le stub
    log_info "Generating XOR encrypted stub..."
    "$STUB_GENERATOR" "$input_file" "$stub_file"
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to generate stub"
        cleanup
        exit 1
    fi
    
    # Compiler le stub
    log_info "Compiling packed executable..."
    gcc -o "$output_name" "$stub_file"
    
    if [[ $? -eq 0 ]]; then
        # Informations sur les fichiers
        local original_size=$(stat -f%z "$input_file" 2>/dev/null || stat -c%s "$input_file" 2>/dev/null || echo "unknown")
        local packed_size=$(stat -f%z "$output_name" 2>/dev/null || stat -c%s "$output_name" 2>/dev/null || echo "unknown")
        local stub_size=$(stat -f%z "$stub_file" 2>/dev/null || stat -c%s "$stub_file" 2>/dev/null || echo "unknown")
        
        echo ""
        log_info "Packing completed successfully!"
        echo -e "${BLUE}=== PACKING SUMMARY ===${NC}"
        echo -e "Original file:     $input_file (${original_size} bytes)"
        echo -e "Packed executable: $output_name (${packed_size} bytes)"
        echo -e "Stub source:       $stub_file (${stub_size} bytes)"
        echo ""
        echo -e "${YELLOW}To run the packed executable:${NC}"
        echo -e "  ./$output_name"
        echo ""
        echo -e "${YELLOW}To clean up stub source:${NC}"
        echo -e "  rm $stub_file"
    else
        log_error "Failed to compile packed executable"
        exit 1
    fi
}

# Test rapide
quick_test() {
    local test_file="$1"
    
    check_file "$test_file"
    
    log_info "Starting quick test with: $test_file"
    
    # Créer un nom temporaire
    local test_output="test_packed_$(basename "$test_file")_$$"
    
    # Packer
    pack_executable "$test_file" "$test_output"
    
    # Tester l'exécution
    log_info "Testing packed executable..."
    echo -e "${BLUE}=== ORIGINAL EXECUTION ===${NC}"
    "$test_file"
    
    echo ""
    echo -e "${BLUE}=== PACKED EXECUTION ===${NC}"
    "./$test_output"
    
    # Nettoyage
    log_info "Cleaning up test files..."
    rm -f "$test_output" "${test_output}.c"
    
    log_info "Quick test completed successfully!"
}

# Nettoyage
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}

clean_files() {
    log_info "Cleaning generated files..."
    
    # Nettoyer les fichiers générés
    rm -f "$SCRIPT_DIR"/*.c
    rm -f "$SCRIPT_DIR"/packed_*
    rm -f "$SCRIPT_DIR"/test_packed_*
    
    log_info "Cleanup completed"
}

# Gestionnaire de signaux pour le nettoyage
trap cleanup EXIT INT TERM

# Menu principal
main() {
    case "${1:-help}" in
        "build")
            build_generator
            ;;
        "pack")
            if [[ -z "$2" ]]; then
                log_error "Usage: $0 pack <executable> [output_name]"
                exit 1
            fi
            pack_executable "$2" "$3"
            ;;
        "test")
            if [[ -z "$2" ]]; then
                log_error "Usage: $0 test <executable>"
                exit 1
            fi
            quick_test "$2"
            ;;
        "clean")
            clean_files
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            log_error "Unknown command: $1"
            show_help
            exit 1
            ;;
    esac
}

# Point d'entrée
main "$@"