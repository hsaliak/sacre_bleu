#include "src/common/policy.h"
#include <iostream>
#include <cassert>
#include <string_view>

using namespace sacre::policy;

void TestIniParsing() {
    std::string_view ini = R"(
[namespaces]
pid = true
net = 1
mount = yes
ipc = false

[seccomp]
allow = read, write, open, close
)";

    auto result = ParseIni(ini);
    assert(result.success);
    assert(result.value.namespaces & static_cast<uint32_t>(NamespaceType::kPid));
    assert(result.value.namespaces & static_cast<uint32_t>(NamespaceType::kNet));
    assert(result.value.namespaces & static_cast<uint32_t>(NamespaceType::kMount));
    assert(!(result.value.namespaces & static_cast<uint32_t>(NamespaceType::kIpc)));

    assert(result.value.allowed_syscalls.size() == 4);
    assert(result.value.allowed_syscalls[0] == "read");
    assert(result.value.allowed_syscalls[1] == "write");
    assert(result.value.allowed_syscalls[2] == "open");
    assert(result.value.allowed_syscalls[3] == "close");

    std::cout << "TestIniParsing passed!" << std::endl;
}

void TestSerialization() {
    Policy p;
    p.namespaces = static_cast<uint32_t>(NamespaceType::kPid) | static_cast<uint32_t>(NamespaceType::kNet);
    p.allowed_syscalls = {"read", "write"};

    auto ser = Serialize(p);
    assert(ser.success);
    
    auto deser = Deserialize(ser.value.data(), ser.value.size());
    assert(deser.success);
    assert(deser.value.namespaces == p.namespaces);
    assert(deser.value.allowed_syscalls.size() == 2);
    assert(deser.value.allowed_syscalls[0] == "read");
    assert(deser.value.allowed_syscalls[1] == "write");

    std::cout << "TestSerialization passed!" << std::endl;
}

int main() {
    TestIniParsing();
    TestSerialization();
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
