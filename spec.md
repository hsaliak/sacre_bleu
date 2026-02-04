# PRD: Sacre Blue Suite

## 1. Executive Summary

The **Sacre Bleu** suite provides an automated workflow to harden Linux binaries. It uses dynamic analysis to discover a program's requirements, embeds those requirements directly into the ELF binary as a custom metadata section, and provides a secure loader to enforce those restrictions at runtime using **seccomp** **Landlock** and  **Namespaces**.

---

## 2. Tool Overviews

### A. `sacre-gen` (The Tracer)

**Purpose:** Observe a target application and generate a security policy based on its actual behavior.

* **Mechanism:** Uses `ptrace` to intercept syscalls or `LD_PRELOAD` for high-level monitoring.
* **Requirements:**
* Capture every unique syscall made during a training run.
* **Output:** An `.ini` file defining the "allow-list."
* **Example Output (`policy.ini`):**
```ini
[syscalls]
read=allow # _NR_read
write=allow # _NR_write
openat=allow # _NR_openat

[metadata]
version=1.0
name=my_app_profile

```





### B. `sacre-inject` (The Injector)

**Purpose:** Permanently attach the generated policy to the executable.

* **Mechanism:** Wrapper around `objcopy` or a custom ELF parser (like LIEF).
* **Requirements:**
* Take an existing ELF binary and the `.ini` policy file as input. Pack it efficiently into the .sandbox header
* Resolve syscall numbers to their `_NR_` string names (e.g., `_NR_read`) to portably apply the policy.
* Create a new, non-allocatable section named `.sandbox`.
* **Action:** `objcopy --add-section .sandbox=policy.ini --set-section-flags .sandbox=noload input_bin output_bin`.
* Verify the section was added successfully using `readelf`.



### C. `bleu-loader` (The Enforcer)

**Purpose:** The entry point that parses the `.sandbox` section and locks down the environment before execution.

* **Mechanism:** Uses `libelf` to read the section and `libseccomp` to apply the filter.
* **Execution Flow:**
1. **Read:** Locate the `.sandbox` section in the target binary.
2. **Parse:** Convert the efficiently packed settings back into the architecture-specific syscall numbers.
3. **Restrict:** Initialize seccomp in `SCMP_ACT_KILL` mode. Add "Allow" rules for everything in the policy.
4. **No New Privs:** Call `prctl(PR_SET_NO_NEW_PRIVS, 1)` to prevent the child from escalating privileges.
5. **Exec:** Call `execve()` to replace the loader process with the sandboxed target.


### Testing
Create test suites for unit testing the 3 programs. This Test suite can be written in gtest or in python.
Create a test suite that tests the whole workflow
 -- Positive: take a binary, patch it, load it and it works. 
 -- Negative: take a binary, patch it, stub out one or two features,  load it and ensure it fails. 


---

## 3. Technical Requirements & Architecture

### Portability Layer

To ensure the suite works on x86_64, ARM, and RISC-V:

* The suite must maintain a lookup table (use  `libseccomp`’s internal mapping) that translates `_NR_` strings to the current CPU's syscall table.

### Security Guarantees

* **Inheritance:** The loader must ensure all child processes created by the target are subject to the same `.sandbox` rules.
* **Integrity:** `bleu-loader` should ideally check if the `.sandbox` section exists; if a binary is missing its section, the loader should refuse to run it (Fail-Closed).

---

## 4. User Workflow (The "Sacre" Cycle)

1. **Discovery:** Developer runs `sacre-gen ./my_app`.
2. **Review:** Developer inspects `policy.ini` to ensure no "dangerous" syscalls (like `_NR_mount`) were captured by accident.
3. **Hardening:** Developer runs `sacre-inject ./my_app policy.ini`.
4. **Deployment:** The hardened binary is distributed.
5. **Execution:** The user runs `bleu-loader ./my_app`.

---

