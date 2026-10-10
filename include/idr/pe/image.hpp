#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "idr/common/error.hpp"
#include "idr/common/result.hpp"

namespace idr::pe {

enum class Arch { unknown, x86, x64 };

struct Section {
    std::string name;
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
};

class PeFile {
public:
    static Result<PeFile> parse(Bytes bytes);

    Arch arch() const { return arch_; }
    bool is_64() const { return arch_ == Arch::x64; }
    uint64_t image_base() const { return image_base_; }
    uint32_t entry_point_rva() const { return entry_point_rva_; }
    const std::vector<Section>& sections() const { return sections_; }

    std::optional<uint32_t> rva_to_offset(uint32_t rva) const;
    Result<Bytes> at_rva(uint32_t rva, size_t size) const;

private:
    Arch arch_ = Arch::unknown;
    uint64_t image_base_ = 0;
    uint32_t entry_point_rva_ = 0;
    std::vector<Section> sections_;
    Bytes buffer_;
};

}  // namespace idr::pe
