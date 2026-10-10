#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <vector>

#include "idr/common/error.hpp"
#include "idr/kb/knowledge_base.hpp"
#include "idr/pe/image.hpp"
#include "idr/target/target_profile.hpp"
#include "pe_builder.hpp"

namespace fs = std::filesystem;
using idr::ErrorCode;
using idr::kb::KnowledgeBase;
using idr::pe::Arch;
using idr::pe::PeFile;
using idr::target::TargetProfile;
using idr::target::Vendor;
using idr::target::vmt_layout_for;

namespace {

constexpr uint32_t kTextRva = 0x1000;
constexpr size_t kTextRawOffset = 0x200;  // must match pe_builder.hpp
constexpr uint32_t kDefaultImageBase = 0x400000;

// Writes a 32-bit little-endian word at flattened `.text` position `pos`.
void plant_u32(std::vector<std::byte>& pe, uint32_t pos, uint32_t value) {
    idr::pe::test_detail::put_u32(pe, kTextRawOffset + pos, value);
}

// Plants the >=2010 "extended init table" pattern that the IsExtendedInitTab
// equivalent recognizes: at flattened position `i` a word equal to
// Pos2Adr(i) + 20, preceded by a unit count of 1 and followed by a single
// {init = 0, finalize = 0} entry.
void plant_extended_init_table(std::vector<std::byte>& pe, uint32_t image_base,
                               uint32_t i = 0x10) {
    plant_u32(pe, i - 4, 1);
    plant_u32(pe, i, image_base + kTextRva + i + 20);
}

fs::path no_kb_dir() {
    return fs::temp_directory_path() / "idr_target_no_such_kb_dir";
}

}  // namespace

// --- VMT layouts (ported verbatim from SetVmtConsts, Main.cpp:2004) --------

TEST(VmtLayout, ported_constants_match_set_vmt_consts) {
    EXPECT_EQ(vmt_layout_for(7).type_info, -0x3C);
    EXPECT_EQ(vmt_layout_for(2009).type_info, -0x48);
    EXPECT_EQ(vmt_layout_for(2009).class_name, -0x38);
    EXPECT_EQ(vmt_layout_for(2010).self_ptr, -0x58);
}

TEST(VmtLayout, delphi_2_has_no_interface_or_safecall_fields) {
    const auto l = vmt_layout_for(2);
    EXPECT_EQ(l.self_ptr, -0x34);
    EXPECT_EQ(l.init_table, -0x30);
    EXPECT_EQ(l.type_info, -0x2C);
    EXPECT_EQ(l.field_table, -0x28);
    EXPECT_EQ(l.class_name, -0x1C);
    EXPECT_EQ(l.instance_size, -0x18);
    EXPECT_EQ(l.parent, -0x14);
    EXPECT_EQ(l.default_handler, -0x10);
    EXPECT_EQ(l.new_instance, -0xC);
    EXPECT_EQ(l.free_instance, -8);
    EXPECT_EQ(l.destroy, -4);
    EXPECT_EQ(l.intf_table, 0);
    EXPECT_EQ(l.auto_table, 0);
    EXPECT_EQ(l.safe_call, 0);
}

TEST(VmtLayout, delphi_3_adds_interface_and_safecall_fields) {
    const auto l = vmt_layout_for(3);
    EXPECT_EQ(l.self_ptr, -0x40);
    EXPECT_EQ(l.intf_table, -0x3C);
    EXPECT_EQ(l.auto_table, -0x38);
    EXPECT_EQ(l.init_table, -0x34);
    EXPECT_EQ(l.type_info, -0x30);
    EXPECT_EQ(l.class_name, -0x20);
    EXPECT_EQ(l.instance_size, -0x1C);
    EXPECT_EQ(l.safe_call, -0x14);
    EXPECT_EQ(l.default_handler, -0x10);
    EXPECT_EQ(l.destroy, -4);
    EXPECT_EQ(l.after_construction, 0);
    EXPECT_EQ(l.before_destruction, 0);
    EXPECT_EQ(l.dispatch, 0);
}

TEST(VmtLayout, delphi_4_through_2007_share_a_layout) {
    for (int v : {4, 5, 6, 7, 2005, 2006, 2007}) {
        const auto l = vmt_layout_for(v);
        EXPECT_EQ(l.self_ptr, -0x4C) << v;
        EXPECT_EQ(l.intf_table, -0x48) << v;
        EXPECT_EQ(l.auto_table, -0x44) << v;
        EXPECT_EQ(l.init_table, -0x40) << v;
        EXPECT_EQ(l.type_info, -0x3C) << v;
        EXPECT_EQ(l.class_name, -0x2C) << v;
        EXPECT_EQ(l.instance_size, -0x28) << v;
        EXPECT_EQ(l.after_construction, -0x1C) << v;
        EXPECT_EQ(l.dispatch, -0x14) << v;
        EXPECT_EQ(l.destroy, -4) << v;
    }
}

TEST(VmtLayout, 2009_and_2010_share_a_layout) {
    for (int v : {2009, 2010}) {
        const auto l = vmt_layout_for(v);
        EXPECT_EQ(l.self_ptr, -0x58) << v;
        EXPECT_EQ(l.instance_size, -0x34) << v;
        EXPECT_EQ(l.parent, -0x30) << v;
        EXPECT_EQ(l.safe_call, -0x20) << v;
        EXPECT_EQ(l.dispatch, -0x14) << v;
        EXPECT_EQ(l.destroy, -4) << v;
    }
}

TEST(VmtLayout, 2011_through_2014_share_the_2009_layout) {
    for (int v : {2011, 2012, 2013, 2014}) {
        const auto l = vmt_layout_for(v);
        EXPECT_EQ(l.self_ptr, vmt_layout_for(2009).self_ptr) << v;
        EXPECT_EQ(l.class_name, vmt_layout_for(2009).class_name) << v;
        EXPECT_EQ(l.destroy, -4) << v;
    }
}

TEST(VmtLayout, unknown_version_is_all_zero) {
    const auto l = vmt_layout_for(1234);
    EXPECT_EQ(l.self_ptr, 0);
    EXPECT_EQ(l.class_name, 0);
    EXPECT_EQ(l.destroy, 0);
}

// --- TargetProfile factory -------------------------------------------------

TEST(TargetProfile, of_pe32plus_reports_x64_and_8_byte_pointers) {
    const auto p = TargetProfile::of(Vendor::embarcadero, 2014, Arch::x64);
    EXPECT_EQ(p.vendor(), Vendor::embarcadero);
    EXPECT_EQ(p.version(), 2014);
    EXPECT_EQ(p.arch(), Arch::x64);
    EXPECT_EQ(p.pointer_size(), 8u);
    EXPECT_EQ(p.kb_file_name(), "kb2014.bin");
}

TEST(TargetProfile, of_pe32_reports_x86_and_4_byte_pointers) {
    const auto p = TargetProfile::of(Vendor::embarcadero, 7, Arch::x86);
    EXPECT_EQ(p.version(), 7);
    EXPECT_EQ(p.arch(), Arch::x86);
    EXPECT_EQ(p.pointer_size(), 4u);
    EXPECT_EQ(p.kb_file_name(), "kb7.bin");
    EXPECT_EQ(p.vmt().type_info, vmt_layout_for(7).type_info);
}

TEST(TargetProfile, of_carries_the_vendor) {
    EXPECT_EQ(TargetProfile::of(Vendor::fpc, 7, Arch::x86).vendor(), Vendor::fpc);
    EXPECT_EQ(TargetProfile::of(Vendor::unknown, 0, Arch::unknown).vendor(),
              Vendor::unknown);
}

TEST(TargetProfile, kb_file_name_formats_the_version) {
    EXPECT_EQ(TargetProfile::of(Vendor::embarcadero, 2, Arch::x86).kb_file_name(),
              "kb2.bin");
    EXPECT_EQ(TargetProfile::of(Vendor::embarcadero, 2005, Arch::x64).kb_file_name(),
              "kb2005.bin");
    EXPECT_EQ(TargetProfile::of(Vendor::embarcadero, 2014, Arch::x86).kb_file_name(),
              "kb2014.bin");
}

// --- Detection (GetDelphiVersion, Main.cpp:1525) ---------------------------

TEST(TargetDetect, plain_non_delphi_image_is_unsupported) {
    auto bytes = make_minimal_pe(Arch::x86);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto detected = TargetProfile::detect(pe.value(), no_kb_dir());
    ASSERT_FALSE(detected.has_value());
    EXPECT_EQ(detected.error(), ErrorCode::unsupported_version);
}

TEST(TargetDetect, extended_init_table_falls_back_to_2010) {
    auto bytes = make_minimal_pe(Arch::x86, kDefaultImageBase);
    plant_extended_init_table(bytes, kDefaultImageBase);
    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());

    auto detected = TargetProfile::detect(pe.value(), no_kb_dir());
    ASSERT_TRUE(detected.has_value()) << detected.message();
    EXPECT_EQ(detected.value().vendor(), Vendor::embarcadero);
    EXPECT_EQ(detected.value().version(), 2010);
    EXPECT_EQ(detected.value().arch(), Arch::x86);
    EXPECT_EQ(detected.value().pointer_size(), 4u);
    EXPECT_EQ(detected.value().kb_file_name(), "kb2010.bin");
}

TEST(TargetDetect, real_syskb2014_fingerprint_detects_2014) {
    const fs::path sys_kb_dir = fs::path(IDR_REPO_ROOT);
    const fs::path kb_file = sys_kb_dir / "syskb2014.bin";
    if (!fs::exists(kb_file)) {
        GTEST_SKIP() << "no syskb2014.bin fixture";
    }

    auto kb = KnowledgeBase::open(kb_file);
    ASSERT_TRUE(kb.has_value()) << kb.message();

    std::optional<uint16_t> sys_id;
    for (const auto& m : kb.value().data().modules) {
        if (m.name == "System") {
            sys_id = m.id;
            break;
        }
    }
    ASSERT_TRUE(sys_id.has_value()) << "no System module in syskb2014.bin";
    auto idx = kb.value().find_proc(*sys_id, "StringCopy");
    ASSERT_TRUE(idx.has_value()) << "no System.StringCopy in syskb2014.bin";
    const auto& dump = kb.value().data().procs[*idx].dump;
    ASSERT_FALSE(dump.empty());

    const uint32_t image_base = kDefaultImageBase;
    auto bytes = make_minimal_pe(Arch::x86, image_base);
    plant_extended_init_table(bytes, image_base);

    const size_t at = kTextRawOffset + 0x40;
    if (at + dump.size() > bytes.size()) {
        GTEST_SKIP() << "StringCopy fingerprint too large for the builder's .text";
    }
    std::copy(dump.begin(), dump.end(), bytes.begin() + at);

    auto pe = PeFile::parse(bytes);
    ASSERT_TRUE(pe.has_value());
    auto detected = TargetProfile::detect(pe.value(), sys_kb_dir);
    ASSERT_TRUE(detected.has_value()) << detected.message();
    EXPECT_EQ(detected.value().version(), 2014);
    EXPECT_EQ(detected.value().arch(), Arch::x86);
}
