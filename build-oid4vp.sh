#!/bin/bash

# Build and Deploy OID4VP Components
# This script compiles OID4VP modules and deploys them to WSO2 IS dropins directory

set -e

# Configuration
DROPINS_DIR="/Users/udeepa/Desktop/VC/IS-Packs/v3/wso2is-7.2-7.1-SNAPSHOT/repository/components/dropins"
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPONENTS_DIR="$PROJECT_ROOT/components"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

MODULES=(
    ""  # index 0 - unused
    "org.wso2.carbon.identity.openid4vc.presentation.common"
    "org.wso2.carbon.identity.openid4vc.presentation.management"
    "org.wso2.carbon.identity.openid4vc.presentation.did"
    "org.wso2.carbon.identity.openid4vc.presentation.verification"
    "org.wso2.carbon.identity.openid4vc.presentation.authenticator"
)

# Global test setting
SKIP_TESTS=true

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ ${NC}$1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_coverage() {
    echo -e "${YELLOW}📊 Test Coverage Summary:${NC}"
    echo -e "$1"
}

# Function to print header
print_header() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to display modules
display_modules() {
    echo ""
    print_info "Available OID4VP Components:"
    echo ""
    echo "  [1] ${MODULES[1]}"
    echo "  [2] ${MODULES[2]}"
    echo "  [3] ${MODULES[3]}"
    echo "  [4] ${MODULES[4]}"
    echo "  [5] ${MODULES[5]}"
    echo "  [6] All components"
    echo "  [7] Deploy existing JARs (without compiling)"
    echo "  [0] Exit"
    echo ""
}

# Function to check if JAR exists for a module
check_jar_exists() {
    local module_name=$1
    local jar_path=$(get_jar_path "$module_name")
    
    if [ -n "$jar_path" ] && [ -f "$jar_path" ]; then
        return 0
    else
        return 1
    fi
}

# Function to list available JARs
list_available_jars() {
    local available_jars=()
    
    for i in {1..5}; do
        module_name="${MODULES[$i]}"
        if check_jar_exists "$module_name"; then
            available_jars+=("$module_name")
        fi
    done
    
    echo "${available_jars[@]}"
}

# Function to deploy existing JARs
deploy_existing_jars() {
    print_header "Deploy Existing JARs"
    
    local available_jars=($(list_available_jars))
    
    if [ ${#available_jars[@]} -eq 0 ]; then
        print_warning "No compiled JARs found. Please compile components first."
        return 1
    fi
    
    print_info "Available JARs:"
    echo ""
    for i in "${!available_jars[@]}"; do
        local module="${available_jars[$i]}"
        local jar_path=$(get_jar_path "$module")
        local jar_name=$(basename "$jar_path")
        echo "  [$(($i + 1))] $jar_name"
    done
    echo "  [A] Deploy all available JARs"
    echo "  [0] Cancel"
    echo ""
    
    read -p "Select option: " deploy_choice
    
    case $deploy_choice in
        0)
            print_info "Cancelled"
            return 0
            ;;
        [Aa])
            print_info "Deploying all available JARs..."
            for module in "${available_jars[@]}"; do
                deploy_jar "$module"
            done
            print_success "All available JARs deployed!"
            ;;
        [1-9])
            local index=$(($deploy_choice - 1))
            if [ $index -lt ${#available_jars[@]} ]; then
                local module="${available_jars[$index]}"
                deploy_jar "$module"
            else
                print_error "Invalid selection"
            fi
            ;;
        *)
            print_error "Invalid selection"
            ;;
    esac
}

# Function to compile a module
compile_module() {
    local module_name=$1
    local module_path="$COMPONENTS_DIR/$module_name"
    
    if [ ! -d "$module_path" ]; then
        print_error "Module directory not found: $module_path"
        return 1
    fi
    
    print_info "Compiling: $module_name"
    cd "$module_path"
    
    local mvn_cmd="mvn clean install"
    if [ "$SKIP_TESTS" = true ]; then
        mvn_cmd="$mvn_cmd -DskipTests"
    fi

    if $mvn_cmd; then
        print_success "Successfully compiled: $module_name"
        if [ "$SKIP_TESTS" = false ]; then
            show_coverage "$module_name"
        fi
        return 0
    else
        print_error "Failed to compile: $module_name"
        return 1
    fi
}

# Function to extract and show coverage
show_coverage() {
    local module_name=$1
    local csv_path="$COMPONENTS_DIR/$module_name/target/site/jacoco/jacoco.csv"
    
    if [ ! -f "$csv_path" ]; then
        print_warning "No coverage report found for $module_name"
        return
    fi
    
    # Calculate coverage from CSV
    # Columns: 4=INSTRUCTION_MISSED, 5=INSTRUCTION_COVERED
    local missed=$(awk -F, 'NR>1 {sum+=$4} END {print sum}' "$csv_path")
    local covered=$(awk -F, 'NR>1 {sum+=$5} END {print sum}' "$csv_path")
    local total=$((missed + covered))
    
    if [ $total -eq 0 ]; then
        print_warning "No instruction data found in coverage report."
        return
    fi
    
    # Using awk for precision
    local percentage=$(awk "BEGIN {printf \"%.2f\", ($covered/$total)*100}")
    
    print_coverage "  Component: $module_name"
    echo "  Total Instructions: $total"
    echo "  Covered: $covered"
    echo "  Missed: $missed"
    echo "  Coverage: $percentage%"
    echo ""
}

# Function to get jar file path
get_jar_path() {
    local module_name=$1
    local jar_file="$COMPONENTS_DIR/$module_name/target/$module_name-*.jar"
    
    # Find the jar file (excluding sources and javadoc jars)
    local found_jar=$(find "$COMPONENTS_DIR/$module_name/target" -name "$module_name-*.jar" ! -name "*-sources.jar" ! -name "*-javadoc.jar" 2>/dev/null | head -1)
    
    if [ -n "$found_jar" ]; then
        echo "$found_jar"
        return 0
    else
        return 1
    fi
}

# Function to deploy jar to dropins
deploy_jar() {
    local module_name=$1
    local jar_path=$(get_jar_path "$module_name")
    
    if [ -z "$jar_path" ]; then
        print_error "JAR file not found for: $module_name"
        return 1
    fi
    
    if [ ! -f "$jar_path" ]; then
        print_error "JAR file does not exist: $jar_path"
        return 1
    fi
    
    if [ ! -d "$DROPINS_DIR" ]; then
        print_error "Dropins directory not found: $DROPINS_DIR"
        return 1
    fi
    
    # Remove old version of the jar from dropins
    rm -f "$DROPINS_DIR/$module_name-"*.jar
    
    # Specific cleanup for the renamed component if we are deploying presentation.management
    if [ "$module_name" == "org.wso2.carbon.identity.openid4vc.presentation.management" ]; then
        rm -f "$DROPINS_DIR/org.wso2.carbon.identity.openid4vc.presentation.definition-"*.jar
    fi
    
    # Copy new jar
    cp "$jar_path" "$DROPINS_DIR/"
    
    local jar_name=$(basename "$jar_path")
    print_success "Deployed: $jar_name → dropins"
    return 0
}

# Main menu
main_menu() {
    print_header "OID4VP Component Builder & Deployer"
    
    echo -e "${YELLOW}Build Configuration:${NC}"
    read -p "  Build with tests? (y/n) [default: n]: " run_tests
    if [[ $run_tests =~ ^[Yy]$ ]]; then
        SKIP_TESTS=false
        print_info "Tests enabled"
    else
        SKIP_TESTS=true
        print_info "Tests disabled (skipping)"
    fi

    display_modules
    
    read -p "Select component(s) to compile [0-6]: " choice
    
    case $choice in
        0)
            print_info "Exiting..."
            exit 0
            ;;
        1|2|3|4|5)
            selected_module="${MODULES[$choice]}"
            print_header "Compiling: $selected_module"
            
            if compile_module "$selected_module"; then
                echo ""
                read -p "Deploy to dropins? (y/n): " deploy_choice
                if [[ $deploy_choice =~ ^[Yy]$ ]]; then
                    deploy_jar "$selected_module"
                fi
            fi
            ;;
        6)
            print_header "Compiling All OID4VP Components"
            
            compiled_modules=()
            failed_modules=()
            
            for key in {1..5}; do
                module_name="${MODULES[$key]}"
                if compile_module "$module_name"; then
                    compiled_modules+=("$module_name")
                else
                    failed_modules+=("$module_name")
                fi
                echo ""
            done
            
            # Summary
            echo ""
            print_header "Compilation Summary"
            
            if [ ${#compiled_modules[@]} -gt 0 ]; then
                print_success "Successfully compiled ${#compiled_modules[@]} module(s):"
                for module in "${compiled_modules[@]}"; do
                    echo "  ✓ $module"
                done
            fi
            
            if [ ${#failed_modules[@]} -gt 0 ]; then
                print_error "Failed to compile ${#failed_modules[@]} module(s):"
                for module in "${failed_modules[@]}"; do
                    echo "  ✗ $module"
                done
            fi
            
            # Deployment options
            if [ ${#compiled_modules[@]} -gt 0 ]; then
                echo ""
                echo "Deployment Options:"
                echo "  [1] Deploy all compiled modules"
                echo "  [2] Deploy selectively"
                echo "  [0] Skip deployment"
                echo ""
                read -p "Select option: " deploy_option
                
                case $deploy_option in
                    1)
                        print_header "Deploying All Compiled Modules"
                        for module in "${compiled_modules[@]}"; do
                            deploy_jar "$module"
                        done
                        print_success "All modules deployed!"
                        ;;
                    2)
                        print_header "Selective Deployment"
                        for module in "${compiled_modules[@]}"; do
                            read -p "Deploy $module? (y/n): " choice
                            if [[ $choice =~ ^[Yy]$ ]]; then
                                deploy_jar "$module"
                            fi
                        done
                        ;;
                    *)
                        print_info "Skipping deployment"
                        ;;
                esac
            fi
            ;;
        7)
            deploy_existing_jars
            ;;
        *)
            print_error "Invalid selection"
            exit 1
            ;;
    esac
    
    echo ""
    print_success "Done!"
    echo ""
}

# Run main menu
cd "$PROJECT_ROOT"
main_menu