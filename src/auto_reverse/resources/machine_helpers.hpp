#ifndef AUTO_REVERSE_MACHINE_HELPERS_HPP
#define AUTO_REVERSE_MACHINE_HELPERS_HPP

// M0 helpers preserve ARM integer bit patterns without signed overflow,
// out-of-range shifts, division UB, or pointer type punning.  These helpers do
// not certify the lifetime, provenance, permissions or ABI of caller objects.
// Byte-memory conversion accepts an actual fixed-size byte object, not a
// fabricated pointer.  The static verifier still compares compiled bytes.

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <type_traits>

namespace auto_reverse::machine {

inline constexpr char helper_version[] = "arm64-m0-unsigned-bits-1";

template <typename U>
inline constexpr unsigned bits = std::numeric_limits<U>::digits;

template <typename U>
constexpr void require_word() noexcept {
    static_assert(std::is_integral_v<U> && std::is_unsigned_v<U>);
    static_assert(bits<U> == 32 || bits<U> == 64);
}

template <typename U>
constexpr U add(U lhs, U rhs) noexcept {
    require_word<U>();
    return static_cast<U>(lhs + rhs);
}

template <typename U>
constexpr U sub(U lhs, U rhs) noexcept {
    require_word<U>();
    return static_cast<U>(lhs - rhs);
}

template <typename U>
constexpr U mul(U lhs, U rhs) noexcept {
    require_word<U>();
    return static_cast<U>(lhs * rhs);
}

template <typename U>
constexpr U lsl(U value, U amount) noexcept {
    require_word<U>();
    const unsigned shift = static_cast<unsigned>(amount & (bits<U> - 1));
    return static_cast<U>(value << shift);
}

template <typename U>
constexpr U lsr(U value, U amount) noexcept {
    require_word<U>();
    const unsigned shift = static_cast<unsigned>(amount & (bits<U> - 1));
    return static_cast<U>(value >> shift);
}

template <typename U>
constexpr U asr(U value, U amount) noexcept {
    require_word<U>();
    const unsigned shift = static_cast<unsigned>(amount & (bits<U> - 1));
    if (shift == 0) return value;
    const U sign = static_cast<U>(U{1} << (bits<U> - 1));
    const U fill = (value & sign) != 0
        ? static_cast<U>(~U{0} << (bits<U> - shift)) : U{0};
    return static_cast<U>((value >> shift) | fill);
}

template <typename U>
constexpr U ror(U value, U amount) noexcept {
    require_word<U>();
    const unsigned shift = static_cast<unsigned>(amount & (bits<U> - 1));
    if (shift == 0) return value;
    return static_cast<U>((value >> shift) | (value << (bits<U> - shift)));
}

template <typename U>
constexpr U udiv(U dividend, U divisor) noexcept {
    require_word<U>();
    return divisor == U{0} ? U{0} : static_cast<U>(dividend / divisor);
}

template <typename U>
constexpr U sdiv_bits(U dividend, U divisor) noexcept {
    require_word<U>();
    if (divisor == U{0}) return U{0};
    const U sign = static_cast<U>(U{1} << (bits<U> - 1));
    const bool dividend_negative = (dividend & sign) != 0;
    const bool divisor_negative = (divisor & sign) != 0;
    const U numerator = dividend_negative ? sub(U{0}, dividend) : dividend;
    const U denominator = divisor_negative ? sub(U{0}, divisor) : divisor;
    const U magnitude = static_cast<U>(numerator / denominator);
    return dividend_negative != divisor_negative ? sub(U{0}, magnitude) : magnitude;
}

constexpr std::uint64_t write_w(std::uint32_t bits32) noexcept {
    return static_cast<std::uint64_t>(bits32);
}

template <typename U>
constexpr U load_le(const std::array<std::uint8_t, sizeof(U)>& bytes) noexcept {
    require_word<U>();
    U result{0};
    for (std::size_t i = 0; i < bytes.size(); ++i)
        result = static_cast<U>(result | (static_cast<U>(bytes[i]) << (8 * i)));
    return result;
}

template <typename U>
constexpr std::array<std::uint8_t, sizeof(U)> store_le(U value) noexcept {
    require_word<U>();
    std::array<std::uint8_t, sizeof(U)> result{};
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = static_cast<std::uint8_t>(value >> (8 * i));
    return result;
}

static_assert(add<std::uint64_t>(UINT64_MAX, 1) == 0);
static_assert(lsl<std::uint32_t>(1, 32) == 1);
static_assert(lsr<std::uint64_t>(1, 64) == 1);
static_assert(asr<std::uint64_t>(UINT64_C(0x8000000000000000), 63) == UINT64_MAX);
static_assert(ror<std::uint32_t>(1, 1) == UINT32_C(0x80000000));
static_assert(ror<std::uint64_t>(1, 64) == 1);
static_assert(udiv<std::uint64_t>(7, 0) == 0);
static_assert(sdiv_bits<std::uint64_t>(UINT64_C(0x8000000000000000), UINT64_MAX)
    == UINT64_C(0x8000000000000000));
static_assert(sdiv_bits<std::uint32_t>(UINT32_C(0xfffffff9), 3) == UINT32_C(0xfffffffe));
static_assert(write_w(UINT32_MAX) == UINT64_C(0xffffffff));
static_assert(load_le<std::uint64_t>(store_le<std::uint64_t>(UINT64_C(0x123456789abcdef0)))
    == UINT64_C(0x123456789abcdef0));

} // namespace auto_reverse::machine

#endif
