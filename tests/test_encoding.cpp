#include "lokimq/hex.h"
#include "lokimq/base32z.h"
#include "lokimq/base64.h"
#include "common.h"

using namespace std::literals;

const std::string pk = "\xf1\x6b\xa5\x59\x10\x39\xf0\x89\xb4\x2a\x83\x41\x75\x09\x30\x94\x07\x4d\x0d\x93\x7a\x79\xe5\x3e\x5c\xe7\x30\xf9\x46\xe1\x4b\x88";
const std::string pk_hex = "f16ba5591039f089b42a834175093094074d0d937a79e53e5ce730f946e14b88";
const std::string pk_b32z = "6fi4kseo88aeupbkopyzknjo1odw4dcuxjh6kx1hhhax1tzbjqry";
const std::string pk_b64 = "8WulWRA58Im0KoNBdQkwlAdNDZN6eeU+XOcw+UbhS4g=";

TEST_CASE("hex encoding/decoding", "[encoding][decoding][hex]") {
    REQUIRE( lokimq::to_hex("\xff\x42\x12\x34") == "ff421234"s );
    std::vector<uint8_t> chars{{1, 10, 100, 254}};
    std::array<uint8_t, 8> out;
    std::array<uint8_t, 8> expected{{'0', '1', '0', 'a', '6', '4', 'f', 'e'}};
    lokimq::to_hex(chars.begin(), chars.end(), out.begin());
    REQUIRE( out == expected );

    REQUIRE( lokimq::to_hex(chars.begin(), chars.end()) == "010a64fe" );

    REQUIRE( lokimq::from_hex("12345678ffEDbca9") == "\x12\x34\x56\x78\xff\xed\xbc\xa9"s );

    REQUIRE( lokimq::is_hex("1234567890abcdefABCDEF1234567890abcdefABCDEF") );
    REQUIRE_FALSE( lokimq::is_hex("1234567890abcdefABCDEF1234567890aGcdefABCDEF") );
    REQUIRE_FALSE( lokimq::is_hex("1234567890abcdefABCDEF1234567890agcdefABCDEF") );
    REQUIRE_FALSE( lokimq::is_hex("\x11\xff") );

    REQUIRE( lokimq::from_hex(pk_hex) == pk );
    REQUIRE( lokimq::to_hex(pk) == pk_hex );

    REQUIRE( lokimq::from_hex(pk_hex.begin(), pk_hex.end()) == pk );

    std::vector<std::byte> bytes{{std::byte{0xff}, std::byte{0x42}, std::byte{0x12}, std::byte{0x34}}};
    std::basic_string_view<std::byte> b{bytes.data(), bytes.size()};
    REQUIRE( lokimq::to_hex(b) == "ff421234"s );

    bytes.resize(8);
    bytes[0] = std::byte{'f'}; bytes[1] = std::byte{'f'}; bytes[2] = std::byte{'4'}; bytes[3] = std::byte{'2'};
    bytes[4] = std::byte{'1'}; bytes[5] = std::byte{'2'}; bytes[6] = std::byte{'3'}; bytes[7] = std::byte{'4'};
    std::basic_string_view<std::byte> hex_bytes{bytes.data(), bytes.size()};
    REQUIRE( lokimq::is_hex(hex_bytes) );
    REQUIRE( lokimq::from_hex(hex_bytes) == "\xff\x42\x12\x34" );
}

TEST_CASE("base32z encoding/decoding", "[encoding][decoding][base32z]") {
    REQUIRE( lokimq::to_base32z("\0\0\0\0\0"s) == "yyyyyyyy" );
    REQUIRE( lokimq::to_base32z("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"sv)
            == "yrtwk3hjixg66yjdeiuauk6p7hy1gtm8tgih55abrpnsxnpm3zzo");

    REQUIRE( lokimq::from_base32z("yrtwk3hjixg66yjdeiuauk6p7hy1gtm8tgih55abrpnsxnpm3zzo")
            == "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"sv);

    REQUIRE( lokimq::from_base32z("YRTWK3HJIXG66YJDEIUAUK6P7HY1GTM8TGIH55ABRPNSXNPM3ZZO")
            == "\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef"sv);

    auto five_nulls = lokimq::from_base32z("yyyyyyyy");
    REQUIRE( five_nulls.size() == 5 );
    REQUIRE( five_nulls == "\0\0\0\0\0"s );

    // 00000 00001 00010 00011 00100 00101 00110 00111
    // ==
    // 00000000 01000100 00110010 00010100 11000111
    REQUIRE( lokimq::from_base32z("ybndrfg8") == "\x00\x44\x32\x14\xc7"s );

    // Special case 1: 7 base32z digits with 3 trailing 0 bits -> 4 bytes (the trailing 0s are dropped)
    // 00000 00001 00010 00011 00100 00101 11000
    // ==
    // 00000000 01000100 00110010 00010111
    REQUIRE( lokimq::from_base32z("ybndrfa") == "\x00\x44\x32\x17"s );

    // Round-trip it:
    REQUIRE( lokimq::from_base32z(lokimq::to_base32z("\x00\x44\x32\x17"sv)) == "\x00\x44\x32\x17"sv );
    REQUIRE( lokimq::to_base32z(lokimq::from_base32z("ybndrfa")) == "ybndrfa" );

    // Special case 2: 7 base32z digits with 3 trailing bits 010; we just ignore the trailing stuff,
    // as if it was specified as 0.  (The last digit here is 11010 instead of 11000).
    REQUIRE( lokimq::from_base32z("ybndrf4") == "\x00\x44\x32\x17"s );
    // This one won't round-trip to the same value since it has ignored garbage bytes at the end
    REQUIRE( lokimq::to_base32z(lokimq::from_base32z("ybndrf4"s)) == "ybndrfa" );

    REQUIRE( lokimq::to_base32z(pk) == pk_b32z );
    REQUIRE( lokimq::to_base32z(pk.begin(), pk.end()) == pk_b32z );
    REQUIRE( lokimq::from_base32z(pk_b32z) == pk );
    REQUIRE( lokimq::from_base32z(pk_b32z.begin(), pk_b32z.end()) == pk );

    std::string pk_b32z_again, pk_again;
    lokimq::to_base32z(pk.begin(), pk.end(), std::back_inserter(pk_b32z_again));
    lokimq::from_base32z(pk_b32z.begin(), pk_b32z.end(), std::back_inserter(pk_again));
    REQUIRE( pk_b32z_again == pk_b32z );
    REQUIRE( pk_again == pk );

    std::vector<std::byte> bytes{{std::byte{0}, std::byte{255}}};
    std::basic_string_view<std::byte> b{bytes.data(), bytes.size()};
    REQUIRE( lokimq::to_base32z(b) == "yd9o" );

    bytes.resize(4);
    bytes[0] = std::byte{'y'}; bytes[1] = std::byte{'d'}; bytes[2] = std::byte{'9'}; bytes[3] = std::byte{'o'};
    std::basic_string_view<std::byte> b32_bytes{bytes.data(), bytes.size()};
    REQUIRE( lokimq::is_base32z(b32_bytes) );
    REQUIRE( lokimq::from_base32z(b32_bytes) == "\x00\xff"sv );
}

TEST_CASE("base64 encoding/decoding", "[encoding][decoding][base64]") {
    // 00000000 00000000 00000000 -> 000000 000000 000000 000000
    REQUIRE( lokimq::to_base64("\0\0\0"s) == "AAAA" );
    // 00000001 00000002 00000003 -> 000000 010000 000200 000003
    REQUIRE( lokimq::to_base64("\x01\x02\x03"s) == "AQID" );
    REQUIRE( lokimq::to_base64("\0\0\0\0"s) == "AAAAAA==" );
    // 00000000 00000000 00000000  11111111 ->
    // 000000 000000 000000 000000 111111 110000 (pad) (pad)
    REQUIRE( lokimq::to_base64("a")   == "YQ==" );
    REQUIRE( lokimq::to_base64("ab")  == "YWI=" );
    REQUIRE( lokimq::to_base64("abc") == "YWJj" );
    REQUIRE( lokimq::to_base64("abcd")   == "YWJjZA==" );
    REQUIRE( lokimq::to_base64("abcde")  == "YWJjZGU=" );
    REQUIRE( lokimq::to_base64("abcdef") == "YWJjZGVm" );

    REQUIRE( lokimq::to_base64("\0\0\0\xff"s) == "AAAA/w==" );
    REQUIRE( lokimq::to_base64("\0\0\0\xff\xff"s) == "AAAA//8=" );
    REQUIRE( lokimq::to_base64("\0\0\0\xff\xff\xff"s) == "AAAA////" );
    REQUIRE( lokimq::to_base64(
            "Man is distinguished, not only by his reason, but by this singular passion from other "
            "animals, which is a lust of the mind, that by a perseverance of delight in the "
            "continued and indefatigable generation of knowledge, exceeds the short vehemence of "
            "any carnal pleasure.")
            ==
            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
            "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg"
            "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu"
            "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo"
            "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=" );

    REQUIRE( lokimq::from_base64("A+/A") == "\x03\xef\xc0" );
    REQUIRE( lokimq::from_base64("YWJj") == "abc" );
    REQUIRE( lokimq::from_base64("YWJjZA==") == "abcd" );
    REQUIRE( lokimq::from_base64("YWJjZA") == "abcd" );
    REQUIRE( lokimq::from_base64("YWJjZB") == "abcd" ); // ignore superfluous bits
    REQUIRE( lokimq::from_base64("YWJjZB") == "abcd" ); // ignore superfluous bits
    REQUIRE( lokimq::from_base64("YWJj+") == "abc" ); // ignore superfluous bits
    REQUIRE( lokimq::from_base64("YWJjZGU=") == "abcde" );
    REQUIRE( lokimq::from_base64("YWJjZGU") == "abcde" );
    REQUIRE( lokimq::from_base64("YWJjZGVm") == "abcdef" );

    REQUIRE( lokimq::is_base64("YWJjZGVm") );
    REQUIRE( lokimq::is_base64("YWJjZGU") );
    REQUIRE( lokimq::is_base64("YWJjZGU=") );
    REQUIRE( lokimq::is_base64("YWJjZA==") );
    REQUIRE( lokimq::is_base64("YWJjZA") );
    REQUIRE( lokimq::is_base64("YWJjZB") ); // not really valid, but we explicitly accept it

    REQUIRE_FALSE( lokimq::is_base64("YWJjZ=") ); // invalid padding (padding can only be 4th or 3rd+4th of a 4-char block)
    REQUIRE_FALSE( lokimq::is_base64("YWJj=") );
    REQUIRE_FALSE( lokimq::is_base64("YWJj=A") );
    REQUIRE_FALSE( lokimq::is_base64("YWJjA===") );
    REQUIRE_FALSE( lokimq::is_base64("YWJ[") );
    REQUIRE_FALSE( lokimq::is_base64("YWJ.") );
    REQUIRE_FALSE( lokimq::is_base64("_YWJ") );

    REQUIRE( lokimq::from_base64(
            "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
            "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg"
            "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu"
            "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo"
            "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=" )
            ==
            "Man is distinguished, not only by his reason, but by this singular passion from other "
            "animals, which is a lust of the mind, that by a perseverance of delight in the "
            "continued and indefatigable generation of knowledge, exceeds the short vehemence of "
            "any carnal pleasure.");

    REQUIRE( lokimq::to_base64(pk) == pk_b64 );
    REQUIRE( lokimq::to_base64(pk.begin(), pk.end()) == pk_b64 );
    REQUIRE( lokimq::from_base64(pk_b64) == pk );
    REQUIRE( lokimq::from_base64(pk_b64.begin(), pk_b64.end()) == pk );

    std::string pk_b64_again, pk_again;
    lokimq::to_base64(pk.begin(), pk.end(), std::back_inserter(pk_b64_again));
    lokimq::from_base64(pk_b64.begin(), pk_b64.end(), std::back_inserter(pk_again));
    REQUIRE( pk_b64_again == pk_b64 );
    REQUIRE( pk_again == pk );

    std::vector<std::byte> bytes{{std::byte{0}, std::byte{255}}};
    std::basic_string_view<std::byte> b{bytes.data(), bytes.size()};
    REQUIRE( lokimq::to_base64(b) == "AP8=" );

    bytes.resize(4);
    bytes[0] = std::byte{'/'}; bytes[1] = std::byte{'w'}; bytes[2] = std::byte{'A'}; bytes[3] = std::byte{'='};
    std::basic_string_view<std::byte> b64_bytes{bytes.data(), bytes.size()};
    REQUIRE( lokimq::is_base64(b64_bytes) );
    REQUIRE( lokimq::from_base64(b64_bytes) == "\xff\x00"sv );
}
