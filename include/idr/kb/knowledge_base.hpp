#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string_view>

#include "idr/common/result.hpp"
#include "idr/kb/records.hpp"

namespace idr::kb {

class KnowledgeBase {
public:
    static Result<KnowledgeBase> open(std::filesystem::path path);

    uint32_t format_version() const { return data_.format_version; }
    const KbData& data() const { return data_; }

    // Index of the first procedure whose name matches (case-sensitive), or
    // nullopt when absent.
    std::optional<size_t> find_proc(std::string_view name) const;

    // Index of the first procedure in the given module whose name matches.
    std::optional<size_t> find_proc(uint16_t module_id, std::string_view name) const;

private:
    KbData data_;
};

// Serialize `data` in the self-describing v3 format.
Result<void> write_v3(std::filesystem::path path, const KbData& data);

}  // namespace idr::kb
