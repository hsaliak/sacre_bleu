#include "src/common/policy.h"
#include <iostream>
#include <cassert>
#include <string_view>

using namespace sacre::policy;

void TestIniParsing() {
    std::string_view ini = R"(
[landlock]
ro = /usr/lib, /etc/ld.so.cache
rw = /tmp

[seccomp]
allow = read, write, open, close
)";

    auto result = ParseIni(ini);
    assert(result.success);

    assert(result.value.allowed_syscalls.size() == 4);
    assert(result.value.allowed_syscalls[0] == "read");

    assert(result.value.ro_paths.size() == 2);
    assert(result.value.ro_paths[0] == "/usr/lib");
    assert(result.value.ro_paths[1] == "/etc/ld.so.cache");

    assert(result.value.rw_paths.size() == 1);
    assert(result.value.rw_paths[0] == "/tmp");

    std::cout << "TestIniParsing passed!" << std::endl;
}

void TestSerialization() {
    Policy p;
    p.allowed_syscalls = {"read", "write"};
    p.ro_paths = {"/usr/lib"};
    p.rw_paths = {"/tmp", "/var/log"};

    auto ser = Serialize(p);
    assert(ser.success);
    
    auto deser = Deserialize(ser.value.data(), ser.value.size());
    assert(deser.success);
    assert(deser.value.allowed_syscalls.size() == 2);
    assert(deser.value.allowed_syscalls[0] == "read");
    assert(deser.value.allowed_syscalls[1] == "write");

    assert(deser.value.ro_paths.size() == 1);
    assert(deser.value.ro_paths[0] == "/usr/lib");

    assert(deser.value.rw_paths.size() == 2);
    assert(deser.value.rw_paths[0] == "/tmp");
    assert(deser.value.rw_paths[1] == "/var/log");

    std::cout << "TestSerialization passed!" << std::endl;
}

int main() {
    TestIniParsing();
    TestSerialization();
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
