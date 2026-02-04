# PRD: Sacre Blue Suite

## 1. Executive Summary

The **Sacre Bleu** suite provides an automated workflow to harden Linux binaries. It uses dynamic analysis to discover a program's requirements, embeds those requirements directly into the ELF binary as a custom metadata section, and provides a secure loader to enforce those restrictions at runtime using **seccomp** and **Namespaces**.

---

## 2. Tool Overviews

### A. `gen` (The Tracer)

**Purpose:** Observe a target application and generate a security policy based on its actual behavior.

* **Mechanism:** Uses `ptrace(PTRACE_SYSCALL)` to intercept syscalls.
* **Requirements:**
* Capture every unique syscall made during a training run.
* **Output:** An `.ini` file defining the "allow-list."
* **Example Output (`policy.ini`):**
```ini
[namespaces]
user = true
net = true

[seccomp]
allow = read, write, openat
```

### B. `injector` (The Injector)

**Purpose:** Permanently attach the generated policy to the executable.

* **Mechanism:** Wrapper around `objcopy`.
* **Requirements:**
* Take an existing ELF binary and the `.ini` policy file as input. 
* Resolve syscall names to architecture-specific numbers via `libseccomp`.
* Create a new, non-allocatable section named `.sandbox`.
* **Action:** `objcopy --add-section .sandbox=policy.blob --set-section-flags .sandbox=noload input_bin output_bin`.

### C. `loader` (The Enforcer)

**Purpose:** The entry point that parses the `.sandbox` section and locks down the environment before execution.

* **Mechanism:** Extracts the section and applies the filter via `libseccomp`.
* **Execution Flow:**
1. **Read:** Locate the `.sandbox` section in the target binary.
2. **Parse:** Convert the binary settings back into the architecture-specific syscall numbers.
3. **Restrict:** Initialize seccomp in `SCMP_ACT_KILL` mode. Add "Allow" rules for everything in the policy.
4. **No New Privs:** Call `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
5. **Namespaces:** Unshare requested namespaces.
6. **Exec:** Call `execve()` to replace the loader process with the sandboxed target.

---

## 3. Technical Requirements & Architecture

### Portability Layer

To ensure the suite works on x86_64, ARM, and RISC-V:
* The suite uses `libseccomp` to translate between syscall names and numbers.

### Security Guarantees

* **Inheritance:** `PR_SET_NO_NEW_PRIVS` ensures seccomp filters are inherited.
* **Integrity:** `loader` refuses to run binaries without a valid `.sandbox` section (Fail-Closed).

---

## 4. User Workflow (The "Sacre" Cycle)

1. **Discovery:** Developer runs `./gen policy.ini ./my_app`.
2. **Review:** Developer inspects `policy.ini`.
3. **Hardening:** Developer runs `./injector policy.ini ./my_app`.
4. **Execution:** The user runs `./loader ./my_app`.
