#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include "src/injector/injector.h"

using namespace sacre::inject;

void TestParseArgsValid() {
  const char* argv[] = {"injector", "policy.ini", "source", "target"};
  auto result = ParseArgs(4, const_cast<char**>(argv));
  assert(result.success);
  assert(result.value.ini_path == "policy.ini");
  assert(result.value.source_path == "source");
  assert(result.value.target_path == "target");
  assert(!result.value.show_help);
  std::cout << "TestParseArgsValid passed!" << std::endl;
}

void TestParseArgsHelp() {
  const char* argv[] = {"injector", "--help"};
  auto result = ParseArgs(2, const_cast<char**>(argv));
  assert(result.success);
  assert(result.value.show_help);
  
  const char* argv2[] = {"injector", "-h"};
  auto result2 = ParseArgs(2, const_cast<char**>(argv2));
  assert(result2.success);
  assert(result2.value.show_help);
  std::cout << "TestParseArgsHelp passed!" << std::endl;
}

void TestParseArgsInvalid() {
  const char* argv[] = {"injector", "too", "many", "positional", "args"};
  auto result = ParseArgs(5, const_cast<char**>(argv));
  assert(!result.success);
  assert(std::strcmp(result.error_message, "Wrong number of arguments") == 0);

  const char* argv2[] = {"injector", "--unknown"};
  auto result2 = ParseArgs(2, const_cast<char**>(argv2));
  assert(!result2.success);
  assert(std::strcmp(result2.error_message, "Unknown option") == 0);
  std::cout << "TestParseArgsInvalid passed!" << std::endl;
}

int main() {
  TestParseArgsValid();
  TestParseArgsHelp();
  TestParseArgsInvalid();
  std::cout << "All injector tests passed!" << std::endl;
  return 0;
}
