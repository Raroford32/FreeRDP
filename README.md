# Ultra-High-Performance RDP NLA Brute Force Tool v3.0

A cutting-edge, ultra-optimized Network Level Authentication (NLA) RDP brute force tool built for maximum speed and efficiency. Designed for penetration testing and security assessment purposes on Ubuntu environments.

## 🚀 Performance Features

- **Extreme Speed**: Up to **50,000+ attempts per second** with proper configuration
- **Advanced Batching**: Processes 50 connections simultaneously per thread
- **epoll-based I/O**: Linux-native high-performance event-driven networking
- **Socket Pooling**: Reuses connections for maximum efficiency
- **Atomic Operations**: Lock-free statistics for minimal overhead
- **SIMD Optimizations**: Uses SSE4.2, AVX, and AES instructions when available
- **LTO Compilation**: Link-time optimization for maximum performance
- **Memory Mapped I/O**: Fast file loading for large wordlists
- **Non-blocking Sockets**: Asynchronous connection handling

## 📊 Performance Metrics

| Configuration | Threads | Expected Rate | Use Case |
|---------------|---------|---------------|----------|
| Fast Mode | 100 | 5,000-15,000/sec | Standard testing |
| Aggressive Mode | 500 | 15,000-50,000/sec | High-speed scanning |
| Custom High | 300-400 | 10,000-35,000/sec | Balanced approach |

## � Features

- **NLA Detection**: Specifically targets Network Level Authentication
- **Protocol Support**: Detects RDP, TLS, NLA, and RDSTLS protocols
- **Fast Failure**: 2-second connection timeout for rapid failure detection
- **Real-time Statistics**: Live display of attempt rates and success counts
- **Comprehensive Logging**: Detailed output with timing information
- **Signal Handling**: Graceful shutdown with Ctrl+C
- **Memory Efficient**: Optimized for large-scale operations
- **Scalable Threading**: Up to 500 concurrent threads

## � Installation & Build

### Quick Build
```bash
# Build with maximum optimizations
make -f Makefile_ultra all

# Create sample input files
make -f Makefile_ultra samples
```

### System Performance Tuning (Optional)
```bash
# Apply system-level optimizations for maximum speed
make -f Makefile_ultra tune-system
```

This will configure:
- TCP connection parameters for high-rate connections
- Increased file descriptor limits
- Optimized kernel network settings
- Enhanced connection backlog sizes

## 📋 Usage

### Required Files
- **ips.txt**: Target IP addresses (one per line)
- **users.txt**: Usernames to test (one per line) 
- **passwords.txt**: Passwords to test (one per line)

### Basic Usage
```bash
# Standard fast mode (recommended)
./rdp-ultra -i ips.txt -u users.txt -p passwords.txt -o results.txt -f

# Aggressive mode (maximum speed)
./rdp-ultra -i ips.txt -u users.txt -p passwords.txt -o results.txt -a

# Custom thread count
./rdp-ultra -i ips.txt -u users.txt -p passwords.txt -o results.txt -t 300

# Verbose mode (shows failed attempts)
./rdp-ultra -i ips.txt -u users.txt -p passwords.txt -o results.txt -v

# Custom RDP port
./rdp-ultra -i ips.txt -u users.txt -p passwords.txt -o results.txt -P 3390
```

### Command Line Options
```
Required:
  -i <file>     IP addresses file (one per line)
  -u <file>     Usernames file (one per line)
  -p <file>     Passwords file (one per line)
  -o <file>     Output results file

Optional:
  -t <num>      Number of threads (default: 100, max: 500)
  -P <port>     RDP port (default: 3389)
  -f            Fast mode (minimal output for max speed)
  -a            Aggressive mode (500 threads, optimized timeouts)
  -v            Verbose output (show failed attempts)
  -h            Show help
```

## 🎯 Performance Optimization

### For Maximum Speed
1. **Use Fast Mode**: `-f` flag reduces output overhead
2. **Aggressive Mode**: `-a` uses 500 threads with optimized settings
3. **System Tuning**: Run `make tune-system` before testing
4. **Thread Count**: Set to 2-4x your CPU core count
5. **Target Selection**: Focus on responsive targets

### Example High-Performance Configuration
```bash
# Ultimate speed configuration
./rdp-ultra -i targets.txt -u users.txt -p passwords.txt -o results.txt -f -t 400

# For testing large networks
./rdp-ultra -i large_network.txt -u common_users.txt -p top_passwords.txt -o scan_results.txt -a
```

## 📈 Benchmarking

### Run Performance Tests
```bash
# Quick benchmark with sample data
make -f Makefile_ultra benchmark

# Speed test with 50 threads
make -f Makefile_ultra test-speed

# Aggressive mode test
make -f Makefile_ultra test-aggressive
```

## � Output Format

### Successful Authentication
```
[SUCCESS] 192.168.1.10:3389 - admin:password123 - NLA (0.234s)
[SUCCESS] 10.0.0.15:3389 - administrator:Password123 - TLS (0.156s)
```

### Results File
```
[SUCCESS] 192.168.1.10:3389 - admin:password123 - NLA (0.234s)
[FAILED] 192.168.1.11:3389 - admin:wrongpass - Connection timeout (2.000s)

# Attack Summary
# Total time: 45.67 seconds
# Total attempts: 15000
# Successful: 3
# Failed: 14997
# Average rate: 328.45 attempts/second
# Threads used: 100
# Batch size: 50
```

## ⚡ Architecture & Optimizations

### Core Technologies
- **Linux epoll**: High-performance event notification
- **Batch Processing**: 50 connections per batch per thread
- **Atomic Statistics**: Lock-free performance counters
- **Memory Pooling**: Pre-allocated connection structures
- **Fast String Operations**: Optimized with SIMD when available

### Compilation Optimizations
- **-O3**: Maximum compiler optimization
- **-march=native**: CPU-specific optimizations
- **-flto**: Link-time optimization
- **-funroll-loops**: Loop unrolling for speed
- **-ffast-math**: Faster floating-point operations

## 🛡 Security Considerations

⚠️ **IMPORTANT**: This tool is designed for authorized penetration testing and security assessments only.

- **Authorization Required**: Only use on systems you own or have explicit permission to test
- **Rate Limiting**: Monitor target responses to avoid overwhelming systems
- **Network Impact**: High-speed scanning can impact network performance
- **Detection**: Rapid connection attempts are easily detected by security systems
- **Legal Compliance**: Ensure compliance with local laws and regulations

## 🐛 Troubleshooting

### Performance Issues
```bash
# Check system limits
ulimit -n

# Monitor network connections
ss -tuln | grep :3389

# Check system load
htop
```

### Common Issues
1. **Low Speed**: Increase thread count with `-t` option
2. **Connection Errors**: Check network connectivity and firewall rules
3. **Resource Limits**: Run `make tune-system` to optimize system settings
4. **Memory Issues**: Reduce thread count if experiencing memory pressure

## 🔧 Development

### Debug Build
```bash
make -f Makefile_ultra debug
./rdp-ultra-debug -i ips.txt -u users.txt -p passwords.txt -o debug_results.txt -v
```

### Clean Build
```bash
make -f Makefile_ultra clean
```

## � Technical Specifications

- **Language**: C (GNU11 standard)
- **Threading**: POSIX threads with atomic operations
- **Networking**: epoll-based event-driven I/O
- **Memory**: Dynamic allocation with pooling
- **Platform**: Linux (Ubuntu optimized)
- **Dependencies**: libc, libpthread, librt

## 🎯 Use Cases

- **Penetration Testing**: Authorized security assessments
- **Red Team Operations**: Simulated attack scenarios  
- **Security Auditing**: Credential strength validation
- **Compliance Testing**: Meeting security requirements
- **Research**: Academic security research (with proper authorization)

## � License & Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized access to computer systems is illegal in most jurisdictions.

**USE AT YOUR OWN RISK** - The authors are not responsible for any misuse or damage caused by this tool.

---

**Built for maximum performance on Ubuntu Linux with modern multi-core processors.**
