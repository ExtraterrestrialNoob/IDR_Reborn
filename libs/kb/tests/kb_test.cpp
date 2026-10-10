#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "idr/kb/knowledge_base.hpp"

namespace fs = std::filesystem;
using idr::kb::ArgRecord;
using idr::kb::KnowledgeBase;
using idr::kb::KbData;
using idr::kb::ModuleRecord;
using idr::kb::ProcRecord;
using idr::kb::TypeRecord;

namespace {

KbData make_sample_kb() {
    KbData kb;
    kb.format_version = 3;
    kb.vendor = "IDR Reborn";
    kb.compiler_version = 7;
    kb.compiler_id = "Delphi 7";
    kb.pointer_size = 4;

    ModuleRecord mod;
    mod.id = 1;
    mod.name = "System";
    mod.filename = "System.dcu";
    mod.uses_ids = {0xFFFF, 2};
    kb.modules.push_back(std::move(mod));

    ProcRecord proc;
    proc.module_id = 1;
    proc.name = "StringCopy";
    proc.embedded = false;
    proc.dump_type = 'C';
    proc.method_kind = 'F';
    proc.call_kind = 3;
    proc.vproc = 0;
    proc.result_type = "PChar";
    proc.dump = {std::byte{0x55}, std::byte{0x8B}, std::byte{0xEC},
                 std::byte{0xC2}, std::byte{0x08}, std::byte{0x00}};
    proc.relocs = {std::byte{0x00}, std::byte{0x00}, std::byte{0xFF},
                   std::byte{0x00}, std::byte{0x00}, std::byte{0x00}};
    proc.fixups = {0x00000004, 0x00000008};

    ArgRecord a1;
    a1.tag = 0x22;
    a1.in_register = false;
    a1.reg_index = 8;
    a1.size = 4;
    a1.name = "Dest";
    a1.type = "PChar";
    proc.args.push_back(a1);

    ArgRecord a2;
    a2.tag = 0x21;
    a2.in_register = true;
    a2.reg_index = 0;
    a2.size = 4;
    a2.name = "Count";
    a2.type = "Integer";
    proc.args.push_back(a2);

    kb.procs.push_back(std::move(proc));

    TypeRecord type;
    type.module_id = 1;
    type.name = "TMyClass";
    type.kind = 'F';
    type.vmt_count = 1;
    type.decl = "TMyClass = class(TObject)";
    type.dump = {std::byte{0x01}, std::byte{0x02}};
    type.relocs = {std::byte{0x00}, std::byte{0x00}};
    type.fields = {std::byte{0x01}, std::byte{0x00}};
    type.props = {std::byte{0x00}, std::byte{0x00}};
    type.methods = {std::byte{0x01}, std::byte{0x00}};
    kb.types.push_back(std::move(type));

    return kb;
}

fs::path temp_path(const std::string& name) {
    return fs::temp_directory_path() / ("idr_kb_" + name + ".bin");
}

void write_bytes(const fs::path& path, const std::vector<std::byte>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

// A minimal 293-byte v2 header with kbVer == 2.
std::vector<std::byte> make_v2_header_bytes() {
    std::vector<std::byte> bytes(293, std::byte{0});
    const char* sig = "IDR Knowledge Base File";
    for (size_t i = 0; i < 23; ++i) {
        bytes[i] = static_cast<std::byte>(sig[i]);
    }
    // isMSIL(24)=0, delphiVer(25..28)=0, crc(29..32)=0, description(33..288)=0.
    bytes[289] = std::byte{2};  // kbVer (little-endian u32) = 2
    return bytes;
}

}  // namespace

TEST(KbV3, round_trips_dump_and_args_byte_exact) {
    KbData kb = make_sample_kb();
    auto path = temp_path("roundtrip");
    auto written = idr::kb::write_v3(path, kb);
    ASSERT_TRUE(written.has_value()) << written.message();

    auto opened = KnowledgeBase::open(path);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    EXPECT_EQ(opened.value().format_version(), 3u);

    const auto& data = opened.value().data();
    ASSERT_EQ(data.procs.size(), 1u);
    const auto& proc = data.procs[0];
    EXPECT_EQ(proc.name, "StringCopy");
    EXPECT_EQ(proc.dump, kb.procs[0].dump);
    EXPECT_EQ(proc.relocs, kb.procs[0].relocs);
    EXPECT_EQ(proc.fixups, kb.procs[0].fixups);
    ASSERT_EQ(proc.args.size(), kb.procs[0].args.size());
    for (size_t i = 0; i < proc.args.size(); ++i) {
        EXPECT_EQ(proc.args[i].tag, kb.procs[0].args[i].tag);
        EXPECT_EQ(proc.args[i].in_register, kb.procs[0].args[i].in_register);
        EXPECT_EQ(proc.args[i].reg_index, kb.procs[0].args[i].reg_index);
        EXPECT_EQ(proc.args[i].size, kb.procs[0].args[i].size);
        EXPECT_EQ(proc.args[i].name, kb.procs[0].args[i].name);
        EXPECT_EQ(proc.args[i].type, kb.procs[0].args[i].type);
    }

    fs::remove(path);
}

TEST(KbV3, find_proc_resolves_by_name) {
    KbData kb = make_sample_kb();
    auto path = temp_path("findproc");
    ASSERT_TRUE(idr::kb::write_v3(path, kb).has_value());

    auto opened = KnowledgeBase::open(path);
    ASSERT_TRUE(opened.has_value());

    auto idx = opened.value().find_proc("StringCopy");
    ASSERT_TRUE(idx.has_value());
    EXPECT_EQ(opened.value().data().procs[*idx].name, "StringCopy");
    EXPECT_EQ(opened.value().find_proc("Missing"), std::nullopt);

    auto mod_idx = opened.value().find_proc(1, "StringCopy");
    ASSERT_TRUE(mod_idx.has_value());
    EXPECT_EQ(*mod_idx, *idx);
    EXPECT_EQ(opened.value().find_proc(2, "StringCopy"), std::nullopt);

    fs::remove(path);
}

TEST(KbV3, rejects_unknown_magic) {
    auto path = temp_path("badmagic");
    std::vector<std::byte> bytes(16, std::byte{'X'});
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::bad_magic);

    fs::remove(path);
}

TEST(KbV3, rejects_unsupported_version) {
    auto path = temp_path("badversion");
    std::vector<std::byte> bytes;
    for (char c : std::string("IDRKB")) {
        bytes.push_back(static_cast<std::byte>(c));
    }
    // formatVersion = 99 (little-endian)
    for (unsigned int b : {99u, 0u, 0u, 0u}) {
        bytes.push_back(static_cast<std::byte>(b));
    }
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::unsupported_version);

    fs::remove(path);
}

TEST(KbLegacyV2, opens_v2_kb_bin) {
    // Prefer the in-repo syskb2014.bin (a real v2 KB); fall back to kb2014.bin,
    // and skip only if neither is present.
    const fs::path sys_fixture = fs::path(IDR_REPO_ROOT) / "syskb2014.bin";
    const fs::path kb_fixture = fs::path(IDR_REPO_ROOT) / "kb2014.bin";
    const fs::path fixture = fs::exists(sys_fixture) ? sys_fixture : kb_fixture;
    if (!fs::exists(fixture)) {
        GTEST_SKIP() << "no v2 KB fixture present";
    }

    auto opened = KnowledgeBase::open(fixture);
    ASSERT_TRUE(opened.has_value()) << opened.message();
    EXPECT_EQ(opened.value().format_version(), 2u);
    EXPECT_GT(opened.value().data().procs.size(), 1000u);

    // A known proc resolves, and its args map locflags -> in_register and
    // Ndx -> reg_index (the regression net for the v2 ARGINFO layout).
    auto idx = opened.value().find_proc("InterlockedExchange");
    ASSERT_TRUE(idx.has_value());
    const auto& proc = opened.value().data().procs[*idx];
    EXPECT_EQ(proc.name, "InterlockedExchange");
    EXPECT_EQ(proc.result_type, "System.Integer");
    ASSERT_EQ(proc.args.size(), 2u);
    EXPECT_EQ(proc.args[0].name, "Target");
    EXPECT_EQ(proc.args[1].name, "Value");
    EXPECT_EQ(proc.args[0].reg_index, 8);
    EXPECT_EQ(proc.args[1].reg_index, 12);
    EXPECT_FALSE(proc.args[0].in_register);
    EXPECT_FALSE(proc.args[1].in_register);

    // The register flag must actually be parsed (not left at its default):
    // the KB should contain at least one register-passed argument.
    bool saw_register_arg = false;
    for (const auto& p : opened.value().data().procs) {
        for (const auto& a : p.args) {
            if (a.in_register) {
                saw_register_arg = true;
                break;
            }
        }
        if (saw_register_arg) break;
    }
    EXPECT_TRUE(saw_register_arg);
}

TEST(KbLegacyV2, rejects_out_of_range_sections_offset) {
    auto bytes = make_v2_header_bytes();
    bytes.resize(300, std::byte{0});
    // Tail sections offset points past EOF (must be rejected, not read).
    bytes[296] = std::byte{0xFF};
    bytes[297] = std::byte{0xFF};
    bytes[298] = std::byte{0xFF};
    bytes[299] = std::byte{0xFF};

    auto path = temp_path("badoffset");
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::truncated);

    fs::remove(path);
}

TEST(KbLegacyV2, rejects_huge_section_count_without_allocating) {
    // A crafted count must be rejected by the byte-bounded guard before it
    // drives reserve(); otherwise reserve(INT32_MAX * 16 bytes) would throw
    // std::length_error/bad_alloc across the open() boundary.
    auto bytes = make_v2_header_bytes();
    bytes.resize(320, std::byte{0});
    const uint32_t sections_offset = 300;  // points at the modules table header
    // count = INT32_MAX (positive), maxsize = 0.
    bytes[sections_offset + 0] = std::byte{0xFF};
    bytes[sections_offset + 1] = std::byte{0xFF};
    bytes[sections_offset + 2] = std::byte{0xFF};
    bytes[sections_offset + 3] = std::byte{0x7F};
    // Tail sections offset (last 4 bytes), little-endian.
    for (int i = 0; i < 4; ++i) {
        bytes[316 + i] =
            std::byte{static_cast<uint8_t>((sections_offset >> (8 * i)) & 0xFF)};
    }

    auto path = temp_path("hugecount");
    write_bytes(path, bytes);

    auto opened = KnowledgeBase::open(path);
    ASSERT_FALSE(opened.has_value());
    EXPECT_EQ(opened.error(), idr::ErrorCode::truncated);

    fs::remove(path);
}
