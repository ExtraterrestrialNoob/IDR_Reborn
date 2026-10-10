#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "idr/pe/image.hpp"

namespace idr::pe::test_detail {

inline void put_u16(std::vector<std::byte>& v, size_t off, uint16_t x) {
    v[off] = static_cast<std::byte>(x & 0xFFu);
    v[off + 1] = static_cast<std::byte>((x >> 8) & 0xFFu);
}

inline void put_u32(std::vector<std::byte>& v, size_t off, uint32_t x) {
    for (int i = 0; i < 4; ++i) {
        v[off + i] = static_cast<std::byte>((x >> (8 * i)) & 0xFFu);
    }
}

inline void put_u64(std::vector<std::byte>& v, size_t off, uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        v[off + i] = static_cast<std::byte>((x >> (8 * i)) & 0xFFull);
    }
}

}  // namespace idr::pe::test_detail

// Builds a syntactically valid PE image with a single `.text` section and zeroed
// data directories. Produces either PE32 or PE32+ depending on `arch`.
inline std::vector<std::byte> make_minimal_pe(idr::pe::Arch arch, uint64_t image_base = 0x400000) {
    using namespace idr::pe::test_detail;

    const bool is64 = (arch == idr::pe::Arch::x64);
    const size_t opt_size = is64 ? 240u : 224u;
    const size_t nt_off = 0x40;        // e_lfanew -> NT headers
    const size_t file_off = nt_off + 4;   // after "PE\0\0"
    const size_t opt_off = file_off + 20; // after IMAGE_FILE_HEADER
    const size_t sec_off = opt_off + opt_size;

    const uint32_t file_align = 0x200;
    const uint32_t section_align = 0x1000;
    const uint32_t headers_size = file_align;
    const uint32_t text_raw_offset = 0x200;
    const uint32_t text_raw_size = 0x200;
    const uint32_t text_va = 0x1000;
    const uint32_t text_vsize = 0x1000;

    std::vector<std::byte> b(headers_size + text_raw_size, std::byte{0});

    // DOS header: 'MZ' and e_lfanew.
    b[0] = std::byte{'M'};
    b[1] = std::byte{'Z'};
    put_u32(b, 0x3C, static_cast<uint32_t>(nt_off));

    // NT signature "PE\0\0".
    b[file_off - 4] = std::byte{'P'};
    b[file_off - 3] = std::byte{'E'};

    // IMAGE_FILE_HEADER.
    put_u16(b, file_off + 0x00, is64 ? 0x8664 : 0x014C);  // Machine
    put_u16(b, file_off + 0x02, 1);                        // NumberOfSections
    put_u16(b, file_off + 0x10, static_cast<uint16_t>(opt_size));  // SizeOfOptionalHeader
    put_u16(b, file_off + 0x12, 0x0022);                   // Characteristics

    // Optional header.
    put_u16(b, opt_off + 0x00, is64 ? 0x20B : 0x10B);      // Magic
    put_u32(b, opt_off + 0x10, text_va);                   // AddressOfEntryPoint
    if (is64) {
        put_u64(b, opt_off + 0x18, image_base);            // ImageBase
    } else {
        put_u32(b, opt_off + 0x1C, static_cast<uint32_t>(image_base));
    }
    put_u32(b, opt_off + 0x20, section_align);             // SectionAlignment
    put_u32(b, opt_off + 0x24, file_align);                // FileAlignment
    put_u32(b, opt_off + 0x38, 0x2000);                    // SizeOfImage
    put_u32(b, opt_off + 0x3C, headers_size);              // SizeOfHeaders
    if (is64) {
        put_u32(b, opt_off + 0x6C, 16);                    // NumberOfRvaAndSizes
    } else {
        put_u32(b, opt_off + 0x5C, 16);
    }

    // Single `.text` section header.
    const char name[] = ".text";
    std::memcpy(b.data() + sec_off, name, sizeof(name) - 1);
    put_u32(b, sec_off + 0x08, text_vsize);      // VirtualSize
    put_u32(b, sec_off + 0x0C, text_va);         // VirtualAddress
    put_u32(b, sec_off + 0x10, text_raw_size);   // SizeOfRawData
    put_u32(b, sec_off + 0x14, text_raw_offset); // PointerToRawData
    put_u32(b, sec_off + 0x24, 0x60000020);      // Characteristics (code/exec/read)

    return b;
}
