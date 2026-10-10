#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace idr::kb {

// A single procedure argument.
struct ArgRecord {
    uint8_t tag = 0;        // 0x21 "val", 0x22 "var" (legacy convention)
    bool in_register = false;
    int32_t reg_index = 0;  // register number / stack offset
    uint32_t size = 0;
    std::string name;
    std::string type;
};

struct ProcRecord {
    uint16_t module_id = 0;
    std::string name;
    bool embedded = false;
    char dump_type = 0;      // 'C' code, 'D' data
    char method_kind = 0;    // 'M','P','F','C','D'
    uint8_t call_kind = 0;   // 1 cdecl, 2 pascal, 3 stdcall, 4 safecall
    int32_t vproc = 0;
    std::string result_type;
    std::vector<std::byte> dump;
    std::vector<std::byte> relocs;
    std::vector<uint32_t> fixups;
    std::vector<ArgRecord> args;
};

struct ConstRecord {
    uint16_t module_id = 0;
    std::string name;
    char type = 0;           // 'C','P','V'
    std::string type_def;
    std::string value;
    std::vector<std::byte> dump;
    std::vector<std::byte> relocs;
};

struct TypeRecord {
    uint16_t module_id = 0;
    std::string name;
    uint8_t kind = 0;
    uint16_t vmt_count = 0;
    std::string decl;
    std::vector<std::byte> dump;
    std::vector<std::byte> relocs;
    std::vector<std::byte> fields;
    std::vector<std::byte> props;
    std::vector<std::byte> methods;
};

struct ModuleRecord {
    uint16_t id = 0;
    std::string name;
    std::string filename;
    std::vector<uint16_t> uses_ids;
};

struct KbData {
    uint32_t format_version = 0;
    std::string vendor;
    int32_t compiler_version = 0;
    std::string compiler_id;
    uint8_t pointer_size = 0;
    std::vector<ModuleRecord> modules;
    std::vector<ConstRecord> consts;
    std::vector<TypeRecord> types;
    std::vector<ProcRecord> procs;
};

}  // namespace idr::kb
