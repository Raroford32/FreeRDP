#!/bin/bash

# RDP NLA Brute Force Tool - Build Script
# Optimized for Ubuntu environment

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing system dependencies..."
    
    if ! command_exists apt-get; then
        print_error "This script is designed for Ubuntu/Debian systems with apt-get"
        exit 1
    fi
    
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        cmake \
        git \
        pkg-config \
        libssl-dev \
        libx11-dev \
        libxext-dev \
        libxinerama-dev \
        libxcursor-dev \
        libxdamage-dev \
        libxv-dev \
        libxkbfile-dev \
        libasound2-dev \
        libcups2-dev \
        libxml2 \
        libxml2-dev \
        libxrandr-dev \
        libgstreamer1.0-dev \
        libgstreamer-plugins-base1.0-dev \
        libxi-dev \
        libglib2.0-dev \
        libgdk-pixbuf2.0-dev \
        libgtk-3-dev \
        libxss1 \
        libjpeg-dev \
        libpng-dev \
        libavutil-dev \
        libavcodec-dev \
        libusb-1.0-0-dev \
        uuid-dev \
        libpcsclite-dev \
        libpulse-dev \
        libwayland-dev \
        libxkbcommon-dev \
        wayland-protocols \
        libfreerdp-dev \
        libwinpr-dev \
        || {
            print_warning "Some packages failed to install, trying alternative approach..."
        }
    
    print_success "Dependencies installed"
}

# Function to build FreeRDP from source if needed
build_freerdp() {
    print_status "Building FreeRDP from source..."
    
    if [ ! -d "build" ]; then
        mkdir build
    fi
    
    cd build
    
    cmake \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DWITH_WAYLAND=OFF \
        -DWITH_X11=OFF \
        -DWITH_FFMPEG=OFF \
        -DWITH_DSP_FFMPEG=OFF \
        -DWITH_CUPS=OFF \
        -DWITH_PULSE=OFF \
        -DWITH_ALSA=OFF \
        -DWITH_PCSC=OFF \
        -DWITH_JPEGXR=OFF \
        -DWITH_OPENH264=OFF \
        -DBUILD_TESTING=OFF \
        -DWITH_SAMPLE=OFF \
        -DWITH_KRB5=OFF \
        -DWITH_GSSAPI=OFF \
        -DWITH_WINPR_TOOLS=OFF \
        -DWITH_MANPAGES=OFF \
        -DWITH_CLIENT=OFF \
        -DWITH_SERVER=OFF \
        ..
    
    make -j$(nproc)
    cd ..
    
    print_success "FreeRDP built successfully"
}

# Function to build the brute force tool
build_tool() {
    print_status "Building RDP brute force tool..."
    
    # Compiler flags for maximum optimization
    CFLAGS="-std=c11 -Wall -Wextra -O3 -march=native -mtune=native -funroll-loops -DWITH_OPENSSL"
    
    # Try different library combinations
    INCLUDE_PATHS="-I./include -I./winpr/include"
    
    # Check if system FreeRDP is available
    if pkg-config --exists freerdp3; then
        print_status "Using system FreeRDP 3.x"
        INCLUDES=$(pkg-config --cflags freerdp3 winpr3)
        LIBS=$(pkg-config --libs freerdp3 winpr3)
        LIBS="$LIBS -lpthread -lm"
    elif pkg-config --exists freerdp2; then
        print_status "Using system FreeRDP 2.x"
        INCLUDES=$(pkg-config --cflags freerdp2 winpr2)
        LIBS=$(pkg-config --libs freerdp2 winpr2)
        LIBS="$LIBS -lpthread -lm"
    elif [ -d "build" ]; then
        print_status "Using locally built FreeRDP"
        INCLUDES="$INCLUDE_PATHS"
        LIBS="-L./build/libfreerdp -L./build/winpr/libwinpr -lfreerdp3 -lwinpr3 -lpthread -lssl -lcrypto -lm"
    else
        print_status "Trying with standard library paths"
        INCLUDES="$INCLUDE_PATHS -I/usr/include/freerdp3 -I/usr/include/winpr3 -I/usr/local/include/freerdp3 -I/usr/local/include/winpr3"
        LIBS="-lfreerdp3 -lwinpr3 -lfreerdp-client3 -lpthread -lssl -lcrypto -lm"
    fi
    
    # Compile the tool
    gcc $CFLAGS $INCLUDES rdp_brute.c -o rdp-brute $LIBS
    
    if [ $? -eq 0 ]; then
        print_success "RDP brute force tool built successfully!"
        ls -la rdp-brute
    else
        print_error "Failed to build the tool"
        return 1
    fi
}

# Function to create sample files
create_samples() {
    print_status "Creating sample input files..."
    
    cat > ips.txt << EOF
192.168.1.10
192.168.1.11
192.168.1.12
10.0.0.1
10.0.0.2
EOF

    cat > users.txt << EOF
administrator
admin
user
guest
test
demo
operator
service
EOF

    cat > passwords.txt << EOF
password
123456
admin
password123

12345
qwerty
abc123
Password1
admin123
root
toor
EOF

    print_success "Sample files created: ips.txt, users.txt, passwords.txt"
}

# Function to run tests
run_test() {
    print_status "Running test..."
    
    if [ ! -f "rdp-brute" ]; then
        print_error "rdp-brute executable not found. Build first."
        return 1
    fi
    
    if [ ! -f "ips.txt" ] || [ ! -f "users.txt" ] || [ ! -f "passwords.txt" ]; then
        create_samples
    fi
    
    # Run a quick test with limited combinations
    timeout 30 ./rdp-brute -i ips.txt -u users.txt -p passwords.txt -o test_results.txt -t 5 -v || true
    
    if [ -f "test_results.txt" ]; then
        print_success "Test completed. Results in test_results.txt"
        echo "Results preview:"
        head -20 test_results.txt
    else
        print_warning "Test completed but no results file found"
    fi
}

# Function to show usage
show_usage() {
    echo "RDP NLA Brute Force Tool - Build Script"
    echo "======================================="
    echo "Usage: $0 [option]"
    echo ""
    echo "Options:"
    echo "  deps      - Install system dependencies"
    echo "  build     - Build the tool"
    echo "  full      - Install deps and build (default)"
    echo "  local     - Build FreeRDP from source and build tool"
    echo "  samples   - Create sample input files"
    echo "  test      - Run a test"
    echo "  clean     - Clean build files"
    echo "  install   - Install to /usr/local/bin"
    echo "  help      - Show this help"
    echo ""
    echo "Examples:"
    echo "  $0              # Full build (install deps + build)"
    echo "  $0 build        # Just build the tool"
    echo "  $0 local        # Build FreeRDP locally first"
    echo "  $0 test         # Run test after building"
}

# Function to install the tool
install_tool() {
    if [ ! -f "rdp-brute" ]; then
        print_error "rdp-brute executable not found. Build first."
        return 1
    fi
    
    print_status "Installing rdp-brute to /usr/local/bin..."
    sudo cp rdp-brute /usr/local/bin/
    sudo chmod +x /usr/local/bin/rdp-brute
    print_success "rdp-brute installed to /usr/local/bin/"
}

# Function to clean build files
clean_build() {
    print_status "Cleaning build files..."
    rm -f rdp-brute *.o
    rm -rf build
    rm -f test_results.txt
    print_success "Build files cleaned"
}

# Main script logic
case "$1" in
    "deps")
        install_dependencies
        ;;
    "build")
        build_tool
        ;;
    "local")
        install_dependencies
        build_freerdp
        build_tool
        ;;
    "samples")
        create_samples
        ;;
    "test")
        run_test
        ;;
    "clean")
        clean_build
        ;;
    "install")
        install_tool
        ;;
    "help")
        show_usage
        ;;
    "")
        # Default: full build
        print_status "Starting full build process..."
        install_dependencies
        build_tool
        create_samples
        print_success "Build process completed!"
        echo ""
        echo "Usage: ./rdp-brute -i ips.txt -u users.txt -p passwords.txt -o results.txt"
        echo "Run './rdp-brute -h' for more options"
        ;;
    *)
        print_error "Unknown option: $1"
        show_usage
        exit 1
        ;;
esac