# Sacre-Loader / Sacre-Inject

Sacre is a suite of security tools designed to harden Linux binaries using a "Policy-as-Data" approach. It allows developers to define fine-grained security policies (syscall whitelists and namespace isolation), inject them directly into ELF binaries, and enforce them at runtime.

## Core Components

### 1. `sacre-inject`
The **Injector** is responsible for taking a security policy (in `.ini` format) and embedding it into a target ELF binary.
*   **Mechanism:** It creates a custom, non-allocatable ELF section named `.sandbox`.
*   **Integrity:** The policy becomes part of the binary's metadata, ensuring it travels with the executable.

### 2. `sacre-loader`
The **Enforcer** is the runtime component that launches the hardened binary.
*   **Parsing:** It extracts the binary policy from the `.sandbox` section of the executable.
*   **Isolation:**
    *   **Namespaces:** Creates isolated `PID`, `Mount`, and `UTS` namespaces to prevent the target from seeing or interfering with the host system.
    *   **Seccomp:** Applies a strict syscall whitelist. Any syscall not explicitly allowed results in the process being terminated (`SIGSYS`).
*   **Security:** Sets `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation.

## Getting Started

### Prerequisites
*   Linux (Kernel support for Namespaces and Seccomp)
*   CMake 3.10+
*   Ninja
*   C++17 Compiler (GCC/Clang)

### Building

```bash
mkdir build && cd build
cmake -G Ninja ..
ninja
```

### Usage

#### 1. Define a Policy (`policy.ini`)
```ini
[syscalls]
read=allow
write=allow
openat=allow
fstat=allow
close=allow
exit_group=allow

[namespaces]
mount=true
pid=true
uts=true
```

#### 2. Inject the Policy
```bash
./sacre-inject my_app policy.ini
```

#### 3. Run with Enforcement
```bash
./sacre-loader my_app
```

## Policy Format

The policy uses a binary format for efficiency and security, but can be defined using simple `.ini` files:

*   **[syscalls]**: List of syscall names to allow.
*   **[namespaces]**: Boolean flags to enable isolation for specific Linux namespaces.

## Security Features

*   **Fail-Closed:** `sacre-loader` will refuse to run binaries that do not contain a valid `.sandbox` section.
*   **No-Stdlib Support:** Can sandbox minimal, statically-linked binaries.
*   **Namespace Isolation:** Prevents lateral movement and information leaks via the `/proc` or `/sys` filesystems.
*   **Shell Injection Resistant:** Uses safe process spawning mechanisms (`execv`) instead of shell-mediated calls.

## Development

### Running Tests
The project includes comprehensive unit and integration tests.
```bash
cd build
ctest --output-on-failure
```

### Code Quality
The project follows the Google C++ Style Guide and uses `clang-tidy` for linting.
*   **Auto-fix:** Run `ninja fix-style` in the build directory to automatically apply formatting and linter fixes.
