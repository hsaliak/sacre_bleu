#include <iostream>
#include "src/injector/injector.h"

int main(int argc, char** argv) {
  auto args_result = sacre::inject::ParseArgs(argc, argv);
  if (!args_result.success) {
    std::cerr << "Error: " << args_result.error_message << '\n';
    std::cerr << "Usage:" << '\n';
    std::cerr << "  Injection: inject <policy.ini> <source_binary> <target_binary>" << '\n';
    std::cerr << "  Extraction: inject --extract <elf_path> [output_path]" << '\n';
    return 1;
  }

  const auto& args = args_result.value;
  if (args.show_help) {
    std::cout << "Usage:" << '\n';
    std::cout << "  Injection: inject <policy.ini> <source_binary> <target_binary>" << '\n';
    std::cout << "  Extraction: inject --extract <elf_path> [output_path]" << '\n';
    std::cout << "Options:" << '\n';
    std::cout << "  -h, --help       Show this help message" << '\n';
    std::cout << "  -e, --extract    Extract policy from an ELF file" << '\n';
    return 0;
  }

  if (args.extract_mode) {
    auto run_result = sacre::inject::RunExtraction(args);
    if (!run_result.success) {
      std::cerr << "Error: " << run_result.error_message << '\n';
      return 1;
    }
    if (!args.output_path.empty()) {
      std::cout << "Successfully extracted policy to " << args.output_path << '\n';
    }
    return 0;
  }

  auto run_result = sacre::inject::RunInjection(args);
  if (!run_result.success) {
    std::cerr << "Error: " << run_result.error_message << '\n';
    return 1;
  }

  std::cout << "Successfully injected policy into " << args.target_path << '\n';
  return 0;
}
