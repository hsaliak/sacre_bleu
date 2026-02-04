# SacreBleu Suite

SacreBleu is a suite of security tools designed to harden Linux binaries using a "Policy-as-Data" approach. It allows developers to define fine-grained security policies (syscall whitelists and filesystem restrictions via Landlock), inject them directly into ELF binaries, and enforce them at runtime.

## Core Components

### 1. `gen` (Generator)
The **Generator** uses dynamic analysis (via `ptrace`) to observe a target application's execution and generate a baseline security policy.
*   **Mechanism:** Intercepts syscalls during execution and deduplicates them.
*   **Filtering:** Automatically filters out "Critical Syscalls" (see below) that are handled by the loader's default allow-list.
*   **Output:** Creates an `.ini` policy file with detected syscalls and template sections for Landlock.

### 2. `injector` (Injector)
The **Injector** takes a security policy (in `.ini` format) and embeds it into a target ELF binary.
*   **Mechanism:** It serializes the policy into a custom, non-allocatable ELF section named `.sandbox`.
*   **Integrity:** The policy becomes part of the binary's metadata, ensuring it travels with the executable.

### 3. `loader` (Enforcer)
The **Enforcer** is the runtime component that launches the hardened binary.
*   **Parsing:** It extracts the binary policy from the `.sandbox` section of the provided executable.
*   **Isolation:**
    *   **Landlock:** Restricts filesystem access (Read-Only/Read-Write) to specified paths.
    *   **Seccomp:** Applies a strict syscall whitelist.
*   **Security:** Sets `PR_SET_NO_NEW_PRIVS` to prevent privilege escalation.

## Getting Started

### Prerequisites
*   Linux (Kernel 5.13+ for Landlock)
*   `libseccomp-dev`
*   CMake 3.15+
*   Ninja
*   C++17 Compiler (GCC/Clang)

### Building & Installation

```bash
mkdir build && cd build
cmake -G Ninja ..
ninja
ninja install
```

**Note:** If you don't have root privileges, the installer will automatically attempt to install to `~/bin`. Ensure `~/bin` is in your `$PATH`. You can also manually specify a prefix:
```bash
cmake -DCMAKE_INSTALL_PREFIX=/custom/path ..
```

## Usage Workflow

### 1. Generate a Policy
Run your application through the generator to see what it needs. The generator will run the application and trace its syscalls.
```bash
./build/gen policy.ini ./my_app [arg1] [arg2]
```

### 2. Review and Customize (`policy.ini`)
Open the generated `policy.ini` and add filesystem paths.

```ini
[landlock]
# Read-only access to libraries and config
ro = /usr/lib, /lib64, /etc/ld.so.cache
# Read-write access to temporary files
rw = /tmp

[seccomp]
# List of allowed syscalls (names)
allow = uname, getcwd, brk
```

### 3. Inject the Policy
Combine the policy and the binary into a new, hardened executable:
```bash
./build/injector policy.ini ./my_app ./my_app_hardened
```

### 4. Run with Enforcement
Launch the hardened binary using the loader:
```bash
./build/loader ./my_app_hardened [args...]
```

## Policy Details

### Critical Syscalls
The loader automatically allows a set of 48 "Critical Syscalls" necessary for basic process operation (e.g., `execve`, `exit`, `read`, `write`, `mmap`, `rt_sigaction`). These are defined in `src/common/policy.cpp` and are intentionally omitted from generated `.ini` files to keep policies concise.

### Landlock Path Resolution
Landlock rules apply to the specific filesystem objects identified by the paths in the policy. 
> **Note:** Currently, paths should be absolute. Future versions will support `realpath()` resolution for improved robustness against symlinks.

## Security Features
*   **Fail-Closed:** `loader` will refuse to run binaries that do not contain a valid `.sandbox` section.
*   **Policy Integrity:** Policies are embedded in the ELF binary, making them harder to tamper with than external config files.
*   **Defense in Depth:** Combines Seccomp (syscalls) and Landlock (filesystem).

## Development

### Running Tests
```bash
cd build
./policy_test
../tests/integration_test.sh ./injector ./loader ./minimal_target ../tests/integration_policy.ini
```

### Code Quality
The project follows the Google C++ Style Guide and uses `clang-tidy` for linting.
*   **Auto-fix:** Run `ninja fix-style` in the build directory.
