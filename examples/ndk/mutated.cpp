#include "auto_reverse/machine_helpers.hpp"

extern "C" __attribute__((visibility("default")))
std::uint64_t add_seven(std::uint64_t x) {
    return auto_reverse::machine::add<std::uint64_t>(x, 8);
}
