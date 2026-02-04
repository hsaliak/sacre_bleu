#include <iostream>
#include "src/inject/injector.h"

int main(int argc, char** argv) {
  auto args_result = sacre::inject::ParseArgs(argc, argv);
  if (!args_result.success) {
    std::cerr << "Error: " << args_result.error_message << '\n';
    std::cerr << "Usage: sacre-inject <policy.ini> <target_binary>" << '\n';
    return 1;
  }

  const auto& args = args_result.value;
  if (args.show_help) {
    std::cout << "Usage: sacre-inject <policy.ini> <target_binary>" << '\n';
    std::cout << "Options:" << '\n';
    std::cout << "  -h, --help    Show this help message" << '\n';
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
