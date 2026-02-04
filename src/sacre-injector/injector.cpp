#include "src/sacre-injector/injector.h"

#include <array>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <cstring>
#include <unistd.h>
#include <sys/wait.h>

#include "src/common/policy.h"
#include "src/common/file_closer.h"

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
    if (arg.empty()) {
      continue;
    }
    if (arg[0] == '-') {
      return Result<Args>::Failure("Unknown option");
    }
    positional.push_back(arg);
  }

  if (positional.size() != 2) {
    return Result<Args>::Failure("Wrong number of arguments");
  }

  args.ini_path = positional[0];
  args.target_path = positional[1];
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
  SafeExecute({"objcopy", "--remove-section=.sacre_policy", args.target_path});
  
  bool const success = SafeExecute({"objcopy", "--add-section", 
                              ".sacre_policy=" + std::string(blob_path.data()), 
                              args.target_path});
  unlink(blob_path.data());

  if (!success) {
    return Result<bool>::Failure("objcopy failed");
  }

  return Result<bool>::Success(true);
}

} // namespace sacre::inject
