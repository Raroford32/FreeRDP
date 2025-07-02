# RDP NLA Brute Force Tool Makefile
# Optimized for Ubuntu environment

CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O3 -march=native -mtune=native -funroll-loops
LDFLAGS = -lfreerdp3 -lwinpr3 -lfreerdp-client3 -lpthread -lssl -lcrypto -lm

# Include directories
INCLUDES = -I./include -I./winpr/include -I/usr/include/freerdp3 -I/usr/include/winpr3

# Source files
SRCDIR = .
SOURCES = rdp_brute.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = rdp-brute

# Default target
all: $(TARGET)

# Build target
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files
%.o: $(SRCDIR)/%.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Install FreeRDP dependencies
deps:
	@echo "Installing FreeRDP dependencies..."
	sudo apt-get update
	sudo apt-get install -y \
		build-essential \
		cmake \
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
		wayland-protocols

# Build FreeRDP from source
build-freerdp:
	@echo "Building FreeRDP from source..."
	mkdir -p build
	cd build && cmake \
		-DCMAKE_BUILD_TYPE=Release \
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
		..
	cd build && make -j$(shell nproc)
	@echo "FreeRDP built successfully"

# Build with local FreeRDP
build-local: build-freerdp
	@echo "Building rdp-brute with local FreeRDP..."
	$(CC) $(CFLAGS) \
		-I./include -I./winpr/include \
		-L./build/libfreerdp -L./build/winpr/libwinpr \
		$(SOURCES) -o $(TARGET) \
		-lfreerdp3 -lwinpr3 -lpthread -lssl -lcrypto -lm
	@echo "Build complete with local FreeRDP"

# Clean build files
clean:
	@echo "Cleaning build files..."
	rm -f $(OBJECTS) $(TARGET)
	rm -rf build

# Create sample input files
samples:
	@echo "Creating sample input files..."
	echo "192.168.1.10" > ips.txt
	echo "192.168.1.11" >> ips.txt
	echo "192.168.1.12" >> ips.txt
	echo "administrator" > users.txt
	echo "admin" >> users.txt
	echo "user" >> users.txt
	echo "guest" >> users.txt
	echo "password" > passwords.txt
	echo "123456" >> passwords.txt
	echo "admin" >> passwords.txt
	echo "password123" >> passwords.txt
	echo "" >> passwords.txt
	@echo "Sample files created: ips.txt, users.txt, passwords.txt"

# Test build
test: $(TARGET) samples
	@echo "Running test..."
	./$(TARGET) -i ips.txt -u users.txt -p passwords.txt -o test_results.txt -t 5
	@echo "Test completed. Check test_results.txt"

# Install to system
install: $(TARGET)
	@echo "Installing $(TARGET)..."
	sudo cp $(TARGET) /usr/local/bin/
	sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "$(TARGET) installed to /usr/local/bin/"

# Uninstall from system  
uninstall:
	@echo "Uninstalling $(TARGET)..."
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "$(TARGET) uninstalled"

# Show help
help:
	@echo "RDP NLA Brute Force Tool - Makefile Help"
	@echo "========================================"
	@echo "Targets:"
	@echo "  all          - Build the tool (default)"
	@echo "  deps         - Install system dependencies" 
	@echo "  build-freerdp- Build FreeRDP from source"
	@echo "  build-local  - Build with local FreeRDP"
	@echo "  samples      - Create sample input files"
	@echo "  test         - Build and run a test"
	@echo "  install      - Install to /usr/local/bin"
	@echo "  uninstall    - Remove from /usr/local/bin"
	@echo "  clean        - Remove build files"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Usage after building:"
	@echo "  ./rdp-brute -i ips.txt -u users.txt -p passwords.txt -o results.txt"

.PHONY: all deps build-freerdp build-local clean samples test install uninstall help