# Sacre Bleu Suite

Sacre Bleu is a suite of security tools designed to harden Linux binaries using a "Policy-as-Data" approach. It allows developers to define fine-grained security policies (syscall whitelists and namespace isolation), inject them directly into ELF binaries, and enforce them at runtime.

## Core Components

### 1. `gen`
The **Generator** uses dynamic analysis (via `ptrace`) to observe a target application and generate a baseline security policy.
*   **Mechanism:** Intercepts syscalls during execution and deduplicates them.
*   **Output:** Creates a `.ini` policy file with detected syscalls and recommended namespace filters.

### 2. `injector`
The **Injector** is responsible for taking a security policy (in `.ini` format) and embedding it into a target ELF binary.
*   **Mechanism:** It creates a custom, non-allocatable ELF section named `.sandbox`.
*   **Integrity:** The policy becomes part of the binary's metadata, ensuring it travels with the executable.

### 3. `loader`
The **Enforcer** is the runtime component that launches the hardened binary.
*   **Parsing:** It extracts the binary policy from the `.sandbox` section of the executable.
*   **Isolation:**
    *   **Namespaces:** Creates isolated namespaces (e.g., `User`, `Net`, `PID`, `Mount`) based on the policy.
    *   **Seccomp:** Applies a strict syscall whitelist. Any syscall not explicitly allowed results in the process being terminated (`SIGSYS`).
*   **Security:** Sets `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation.

## Getting Started

### Prerequisites
*   Linux (Kernel support for Namespaces and Seccomp)
*   `libseccomp-dev`
*   CMake 3.15+
*   Ninja
*   C++17 Compiler (GCC/Clang)

### Building

```bash
mkdir build && cd build
cmake -G Ninja ..
ninja
```

### Usage

#### 1. Generate a Policy
Run your application through the generator to see what it needs:
```bash
./gen policy.ini ./my_app arg1 arg2
```

#### 2. Review and Customize (`policy.ini`)
```ini
[namespaces]
user = true
net = true
# pid = true
# mount = true

[seccomp]
allow = read, write, openat, fstat, close, exit_group
```

#### 3. Inject the Policy
```bash
./injector policy.ini ./my_app
```

#### 4. Run with Enforcement
```bash
./loader ./my_app
```

## Security Features

*   **Fail-Closed:** `loader` will refuse to run binaries that do not contain a valid `.sandbox` section.
*   **No-Stdlib Support:** Can sandbox minimal, statically-linked binaries.
*   **Namespace Isolation:** Prevents lateral movement and information leaks.
*   **Shell Injection Resistant:** Uses safe process spawning mechanisms (`execv`).

## Development

### Running Tests
```bash
cd build
ctest --output-on-failure
```

### Code Quality
The project follows the Google C++ Style Guide and uses `clang-tidy` for linting.
*   **Auto-fix:** Run `ninja fix-style` in the build directory.
