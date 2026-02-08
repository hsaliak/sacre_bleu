#include "src/injector/injector.h"

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include "src/common/file_closer.h"
#include "src/common/policy.h"

namespace sacre::inject {

namespace {
bool SafeExecute(const std::vector<std::string>& args) {
  pid_t const pid = fork();
  if (pid == 0) {
    std::vector<char*> c_args;
    c_args.reserve(args.size() + 1);
    for (const auto& arg : args) {
      c_args.push_back(const_cast<char*>(arg.c_str()));
    }
    c_args.push_back(nullptr);
    execvp(c_args[0], c_args.data());
    _exit(1);
  } else if (pid > 0) {
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
  }
  return false;
}
}  // namespace

Result<Args> ParseArgs(int argc, char** argv) {
  Args args;
  std::vector<std::string> positional;

  for (int i = 1; i < argc; ++i) {
    std::string const arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      args.show_help = true;
      return Result<Args>::Success(args);
    }
    if (arg == "--extract" || arg == "-e") {
      args.extract_mode = true;
      continue;
    }
    if (arg.empty()) {
      continue;
    }
    if (arg[0] == '-') {
      return Result<Args>::Failure("Unknown option");
    }
    positional.push_back(arg);
  }

  if (args.extract_mode) {
    if (positional.empty() || positional.size() > 2) {
      return Result<Args>::Failure("Extract mode requires 1 or 2 arguments");
    }
    args.elf_path = positional[0];
    if (positional.size() == 2) {
      args.output_path = positional[1];
    }
    return Result<Args>::Success(args);
  }

  if (positional.size() != 3) {
    return Result<Args>::Failure("Injection mode requires 3 arguments");
  }

  args.ini_path = positional[0];
  args.source_path = positional[1];
  args.target_path = positional[2];
  return Result<Args>::Success(args);
}

Result<bool> RunInjection(const Args& args) {
  // 1. Read INI
  std::ifstream ini_file(args.ini_path);
  if (!ini_file.is_open()) {
    return Result<bool>::Failure("Could not open policy file");
  }
  std::stringstream ini_stream;
  ini_stream << ini_file.rdbuf();
  std::string const ini_content = ini_stream.str();

  // 2. Parse INI
  auto parse_result = sacre::policy::ParseIni(ini_content);
  if (!parse_result.success) {
    return Result<bool>::Failure(parse_result.error_message);
  }

  // 3. Serialize to Binary
  auto serialize_result = sacre::policy::Serialize(parse_result.value);
  if (!serialize_result.success) {
    return Result<bool>::Failure(serialize_result.error_message);
  }

  // 4. Write blob to temporary file
  constexpr size_t kBlobPathSize = 24;
  std::array<char, kBlobPathSize> blob_path = {"/tmp/sacre_policyXXXXXX"};
  FileCloser const policy_fd(mkstemp(blob_path.data()));
  if (!policy_fd.is_valid()) {
    return Result<bool>::Failure("Failed to create temporary file");
  }

  if (write(policy_fd.get(), serialize_result.value.data(),
            serialize_result.value.size()) !=
      static_cast<ssize_t>(serialize_result.value.size())) {
    unlink(blob_path.data());
    return Result<bool>::Failure("Failed to write to temporary file");
  }

  // 5. Call objcopy to inject section
  SafeExecute({"objcopy", "--remove-section=.sandbox", args.source_path, args.target_path});
  
  bool const success = SafeExecute({"objcopy", "--add-section", 
                              ".sandbox=" + std::string(blob_path.data()), 
                              args.target_path});
  unlink(blob_path.data());

  if (!success) {
    return Result<bool>::Failure("objcopy failed");
  }

  return Result<bool>::Success(true);
}

Result<bool> RunExtraction(const Args& args) {
  // 1. Create a temporary file for the dumped section
  constexpr size_t kDumpPathSize = 24;
  std::array<char, kDumpPathSize> dump_path = {"/tmp/sacre_dumpXXXXXX"};
  int const fd = mkstemp(dump_path.data());
  if (fd == -1) {
    return Result<bool>::Failure("Failed to create temporary file for dumping");
  }
  close(fd);

  // 2. Call objcopy to dump section
  bool const success = SafeExecute({"objcopy", "--dump-section", 
                                   ".sandbox=" + std::string(dump_path.data()), 
                                   args.elf_path});
  
  if (!success) {
    unlink(dump_path.data());
    return Result<bool>::Failure("Failed to extract .sandbox section (it might not exist)");
  }

  // Check if file exists and is not empty
  std::ifstream dump_file(dump_path.data(), std::ios::binary | std::ios::ate);
  if (!dump_file.is_open()) {
    unlink(dump_path.data());
    return Result<bool>::Failure("Failed to open dumped section");
  }
  
  std::streamsize const size = dump_file.tellg();
  if (size <= 0) {
    unlink(dump_path.data());
    return Result<bool>::Failure("No policy found in .sandbox section (section is empty)");
  }

  dump_file.seekg(0, std::ios::beg);
  std::vector<uint8_t> buffer(size);
  if (!dump_file.read(reinterpret_cast<char*>(buffer.data()), size)) {
    unlink(dump_path.data());
    return Result<bool>::Failure("Failed to read dumped section");
  }
  unlink(dump_path.data());

  // 3. Deserialize
  auto deserialize_result = sacre::policy::Deserialize(buffer.data(), buffer.size());
  if (!deserialize_result.success) {
    return Result<bool>::Failure("Failed to deserialize policy");
  }

  // 4. Convert to INI format and write to output or stdout
  std::stringstream ss;
  const auto& policy = deserialize_result.value;
  
  ss << "[seccomp]\n";
  ss << "allow = ";
  for (size_t i = 0; i < policy.allowed_syscalls.size(); ++i) {
    ss << policy.allowed_syscalls[i] << (i == policy.allowed_syscalls.size() - 1 ? "" : ", ");
  }
  ss << "\n\n";

  ss << "[landlock]\n";
  ss << "ro = ";
  for (size_t i = 0; i < policy.ro_paths.size(); ++i) {
    ss << policy.ro_paths[i] << (i == policy.ro_paths.size() - 1 ? "" : ", ");
  }
  ss << "\n";
  ss << "rw = ";
  for (size_t i = 0; i < policy.rw_paths.size(); ++i) {
    ss << policy.rw_paths[i] << (i == policy.rw_paths.size() - 1 ? "" : ", ");
  }
  ss << "\n";

  if (args.output_path.empty()) {
    std::cout << ss.str();
  } else {
    std::ofstream out_file(args.output_path);
    if (!out_file.is_open()) {
      return Result<bool>::Failure("Could not open output file");
    }
    out_file << ss.str();
  }

  return Result<bool>::Success(true);
}

} // namespace sacre::inject
