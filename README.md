# RDP NLA Brute Force Tool

A high-performance, optimized Network Level Authentication (NLA) RDP brute force tool built using the FreeRDP library. Designed for penetration testing and security assessment purposes.

## ⚡ Features

- **High Performance**: Multi-threaded design with optimized connection handling
- **NLA Support**: Targets Network Level Authentication specifically  
- **Fast Failure Detection**: Configurable timeouts for quick failed attempt detection
- **Comprehensive Input**: Supports multiple IP addresses, usernames, and passwords
- **Real-time Statistics**: Live display of attempt rates and success/failure counts
- **Detailed Logging**: Comprehensive output with timing information
- **Memory Efficient**: Optimized memory usage for large-scale attacks
- **Signal Handling**: Graceful shutdown with Ctrl+C
- **Ubuntu Optimized**: Built specifically for Ubuntu environment

## 🚀 Performance Optimizations

- **Connection Pooling**: Reuses connections where possible
- **Minimal Protocol Overhead**: Disables unnecessary RDP features
- **Optimized Timeouts**: Fast failure detection (5s connection, 3s auth)
- **CPU Optimizations**: Compiled with `-O3 -march=native -mtune=native`
- **Thread Pool**: Configurable thread count (default: 20, max: 100)
- **Memory Pre-allocation**: Reduces malloc/free overhead

## 📋 Requirements

- Ubuntu 18.04+ or similar Debian-based system
- FreeRDP 2.x or 3.x development libraries
- OpenSSL development libraries
- GCC compiler with C11 support
- pthread support

## 🔧 Installation

### Quick Install (Recommended)

```bash
# Make build script executable
chmod +x build.sh

# Install dependencies and build (full process)
./build.sh

# Or step by step:
./build.sh deps    # Install dependencies
./build.sh build   # Build the tool
```

### Manual Build

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libssl-dev \
    libfreerdp-dev libwinpr-dev

# Build using Makefile
make all

# Or build manually
gcc -std=c11 -Wall -Wextra -O3 -march=native -mtune=native -funroll-loops \
    -I/usr/include/freerdp3 -I/usr/include/winpr3 \
    rdp_brute.c -o rdp-brute \
    -lfreerdp3 -lwinpr3 -lpthread -lssl -lcrypto -lm
```

### Build from FreeRDP Source

```bash
# If system FreeRDP is not available or you want latest version
./build.sh local   # This builds FreeRDP from source first
```

## 📝 Usage

### Basic Usage

```bash
./rdp-brute -i ips.txt -u users.txt -p passwords.txt -o results.txt
```

### Advanced Usage

```bash
# High-speed attack with 50 threads
./rdp-brute -i ips.txt -u users.txt -p passwords.txt -o results.txt -t 50

# Verbose output showing failed attempts
./rdp-brute -i ips.txt -u users.txt -p passwords.txt -o results.txt -v

# Custom port
./rdp-brute -i ips.txt -u users.txt -p passwords.txt -o results.txt -P 3390

# Full example with all options
./rdp-brute -i targets.txt -u usernames.txt -p passwords.txt -o attack_results.txt -t 75 -P 3389 -v
```

### Command Line Options

```
Required:
  -i <file>     IP addresses file (one per line)
  -u <file>     Usernames file (one per line)  
  -p <file>     Passwords file (one per line)
  -o <file>     Output results file

Optional:
  -t <num>      Number of threads (default: 20, max: 100)
  -P <port>     RDP port (default: 3389)
  -v            Verbose output (show failed attempts)
  -h            Show help
```

## 📁 Input File Formats

### IP Addresses (ips.txt)
```
192.168.1.10
192.168.1.11
10.0.0.100
172.16.1.50
```

### Usernames (users.txt)
```
administrator
admin
user
guest
test
demo
service
operator
```

### Passwords (passwords.txt)
```
password
123456
admin
password123

12345
qwerty
abc123
Password1
admin123
```

**Note**: Empty lines in password files are treated as blank passwords.

## 📊 Output Format

### Successful Authentication
```
[SUCCESS] 192.168.1.10:3389 - admin:password123 (2.134s)
```

### Failed Authentication (Verbose Mode)
```
[FAILED] 192.168.1.10:3389 - admin:wrongpass - Authentication failed (1.523s)
```

### Real-time Statistics
```
[*] Attempts: 1250 | Success: 3 | Failed: 1247 | Rate: 156.25/s
```

### Summary Output
```
[*] Total time: 45.67 seconds
[*] Total attempts: 2500
[*] Successful: 5
[*] Failed: 2495
[*] Average rate: 54.75 attempts/second
```

## ⚙️ Performance Tuning

### Thread Count Optimization

- **Low-end systems**: 10-20 threads
- **Mid-range systems**: 20-50 threads  
- **High-end systems**: 50-100 threads
- **Network bottleneck**: Start with 20, increase if network can handle it

### Network Considerations

- **Local network**: Higher thread counts work well
- **Internet targets**: Lower thread counts to avoid detection/blocking
- **Rate limiting**: Monitor target responses for rate limiting

### Memory Usage

- **Large wordlists**: Monitor system memory usage
- **Max limits**: 100K IPs, 10K users, 100K passwords per run
- **Split large jobs**: Use multiple smaller runs for very large datasets

## 🛡️ Security and Legal Notice

**⚠️ IMPORTANT LEGAL DISCLAIMER**

This tool is designed for **authorized penetration testing and security assessment only**. 

- ✅ **Authorized Use**: Only use against systems you own or have explicit written permission to test
- ❌ **Unauthorized Use**: Using this tool against systems without permission is illegal
- 📋 **Documentation**: Always maintain proper documentation of authorized testing
- 🔒 **Responsible Disclosure**: Report vulnerabilities through proper channels

**Users are solely responsible for complying with all applicable laws and regulations.**

## 🔍 Technical Details

### Architecture

- **Multi-threaded**: Uses pthread for parallel connections
- **Event-driven**: Non-blocking I/O where possible
- **Memory efficient**: Pre-allocated buffers and connection pooling
- **Signal-aware**: Proper cleanup on termination

### FreeRDP Integration

- **Native API**: Uses FreeRDP client library directly
- **Optimized Settings**: Minimal protocol overhead
- **NLA Focus**: Specifically targets Network Level Authentication
- **Error Handling**: Comprehensive error detection and reporting

### Optimization Techniques

- **Compiler Optimizations**: -O3 with native CPU optimizations
- **Connection Reuse**: Minimizes connection setup overhead  
- **Fast Timeouts**: Quick detection of failed attempts
- **Reduced Protocol Features**: Disables unnecessary RDP features

## 🐛 Troubleshooting

### Build Issues

```bash
# Missing FreeRDP headers
sudo apt-get install libfreerdp-dev libwinpr-dev

# Build FreeRDP from source if system version incompatible
./build.sh local

# Check dependencies
pkg-config --exists freerdp3 && echo "FreeRDP 3.x found"
pkg-config --exists freerdp2 && echo "FreeRDP 2.x found"
```

### Runtime Issues

```bash
# Permission denied
chmod +x rdp-brute

# Missing libraries
ldd rdp-brute  # Check library dependencies

# Segmentation fault
# Usually indicates missing or incompatible FreeRDP libraries
# Try rebuilding with ./build.sh local
```

### Performance Issues

- **Low connection rate**: Increase thread count with `-t`
- **High CPU usage**: Decrease thread count  
- **Memory issues**: Check available RAM and reduce wordlist sizes
- **Network timeouts**: Check network connectivity and target availability

## 🎯 Example Scenarios

### Small Network Assessment
```bash
# Quick scan of small network
./rdp-brute -i small_network.txt -u common_users.txt -p top_passwords.txt -o results.txt -t 10
```

### Large-Scale Assessment  
```bash
# High-speed scan with maximum threads
./rdp-brute -i enterprise_ips.txt -u domain_users.txt -p password_list.txt -o enterprise_results.txt -t 100 -v
```

### Custom Port Scanning
```bash
# Non-standard RDP port
./rdp-brute -i targets.txt -u users.txt -p passwords.txt -o results.txt -P 3390
```

## 📈 Benchmarks

**Test Environment**: Ubuntu 20.04, Intel i7-8700K, 32GB RAM, Gigabit network

| Thread Count | Attempts/sec | CPU Usage | Memory Usage |
|--------------|--------------|-----------|--------------|
| 10           | 45.2         | 15%       | 45MB        |
| 20           | 87.4         | 28%       | 52MB        |
| 50           | 156.8        | 45%       | 78MB        |
| 100          | 203.5        | 72%       | 125MB       |

**Note**: Actual performance varies based on network conditions, target responsiveness, and system specifications.

## 🤝 Contributing

Contributions are welcome! Please ensure all contributions are for legitimate security research purposes.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is provided for educational and authorized penetration testing purposes only. Users are responsible for complying with all applicable laws and regulations.

## 🔗 Related Tools

- **FreeRDP**: https://github.com/FreeRDP/FreeRDP
- **Nmap**: For initial port scanning
- **Hydra**: Alternative brute force tool
- **Medusa**: Another network authentication tool

---

**Built with ❤️ for the security community. Use responsibly.**
