# Project Style and Configuration

This document outlines the coding standards and tool configurations for this project.

## Core Principles

- **Base Style**: [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html).
- **C++ Standard**: C++17.
- **Exceptions**: Disabled (`-fno-exceptions`). Code must use alternative error handling strategies (e.g., `std::optional`, status codes).
- **RTTI**: Enabled (default), but use with caution.

## Tooling

### Build System
- **Generator**: CMake + Ninja.
- **Warnings**: Enforced with `-Wall -Wextra -Werror`.

### Static Analysis (Clang-Tidy)
Clang-Tidy is integrated into the build process and all warnings are treated as errors.

#### Enabled Modules:
- `bugprone-*`: Catch common logic errors.
- `performance-*`: Identify potential performance bottlenecks.
- `google-*`: Enforce Google-specific style rules.
- `modernize-*`: Promote modern C++17 features.
- `cppcoreguidelines-*`: Selected checks from the C++ Core Guidelines.

#### Specific Deviations/Refinements:
To remain consistent with Google Style and project constraints, the following `cppcoreguidelines` checks are **disabled**:
- `cppcoreguidelines-pro-type-reinterpret-cast`: Google allows `reinterpret_cast` when necessary.
- `cppcoreguidelines-pro-type-const-cast`: Google allows `const_cast` in specific scenarios.
- `cppcoreguidelines-pro-type-static-cast-downcast`: Google allows static downcasting in performance-critical code.
- `cppcoreguidelines-owning-memory`: Avoids dependency on GSL-specific types like `gsl::owner`.
- `cppcoreguidelines-pro-bounds-*`: Disabled for pointer arithmetic and array-to-pointer decay to facilitate easier interaction with legacy/C APIs.
- `cppcoreguidelines-special-member-functions`: Relaxed to match Google's preference for simplicity in class definitions unless complex ownership is involved.

## Formatting
Code formatting follows the Google C++ style. Run `clang-format` before committing.
