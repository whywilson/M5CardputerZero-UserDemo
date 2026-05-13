#pragma once

#include "nfc_models.hpp"
#include "hal/hal_paths.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace nfc_app {

class NfcStorage {
public:
    std::string root_dir() const
    {
        return std::string(hal_path_data_dir()) + "/nfc_data";
    }

    std::string records_dir() const
    {
        return root_dir() + "/records";
    }

    std::string emulator_config_path() const
    {
        return root_dir() + "/emulator_config.json";
    }

    std::string mifare_keys_path() const
    {
        return root_dir() + "/mifare_keys.json";
    }

    bool ensure_layout() const
    {
        return ensure_dir(root_dir()) && ensure_dir(records_dir());
    }

    bool save_record(const SavedRecord &record, std::string *error = nullptr) const
    {
        if (!ensure_layout()) {
            if (error) *error = "Failed to create nfc_data directory";
            return false;
        }

        const std::string path = records_dir() + "/" + sanitize_filename(record.meta.record_id) + ".json";
        std::ofstream output(path.c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) {
            if (error) *error = "Failed to open record for write";
            return false;
        }

        nlohmann::json document = record;
        output << document.dump(2);
        return true;
    }

    std::vector<SavedRecord> list_records() const
    {
        std::vector<SavedRecord> result;
        if (!ensure_layout()) return result;

        DIR *dir = opendir(records_dir().c_str());
        if (!dir) return result;

        struct dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            const char *name = entry->d_name;
            if (name[0] == '.') continue;
            const std::string filename(name);
            if (filename.size() < 6 || filename.substr(filename.size() - 5) != ".json") continue;
            SavedRecord record;
            if (load_record(records_dir() + "/" + filename, &record)) {
                result.push_back(record);
            }
        }
        closedir(dir);

        std::sort(result.begin(), result.end(), [](const SavedRecord &lhs, const SavedRecord &rhs) {
            return lhs.meta.created_at > rhs.meta.created_at;
        });
        return result;
    }

    bool load_record_by_id(const std::string &record_id, SavedRecord *record) const
    {
        return load_record(records_dir() + "/" + sanitize_filename(record_id) + ".json", record);
    }

    bool save_emulator_slots(const std::vector<EmulatorSlotRecord> &slots) const
    {
        if (!ensure_layout()) return false;
        std::ofstream output(emulator_config_path().c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) return false;
        nlohmann::json document;
        document["schema_version"] = 1;
        document["schema_name"] = "m5cz.nfc.emulator_config";
        document["slots"] = slots;
        output << document.dump(2);
        return true;
    }

    bool save_emulator_slots_by_protocol(const std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> &slots_by_protocol) const
    {
        if (!ensure_layout()) return false;
        std::ofstream output(emulator_config_path().c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) return false;
        nlohmann::json document;
        document["schema_version"] = 2;
        document["schema_name"] = "m5cz.nfc.emulator_config";
        nlohmann::json groups = nlohmann::json::object();
        for (const auto &protocol : supported_emulator_protocols()) {
            const auto it = slots_by_protocol.find(protocol);
            groups[protocol_storage_key(protocol)] = (it == slots_by_protocol.end())
                ? std::vector<EmulatorSlotRecord>{}
                : it->second;
        }
        document["slots_by_protocol"] = groups;
        output << document.dump(2);
        return true;
    }

    bool save_mifare_keys(const std::vector<MifareKeyRecord> &keys) const
    {
        if (!ensure_layout()) return false;
        std::ofstream output(mifare_keys_path().c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) return false;
        nlohmann::json document;
        document["schema_version"] = 1;
        document["schema_name"] = "m5cz.nfc.mifare_keys";
        document["keys"] = keys;
        output << document.dump(2);
        return true;
    }

    std::vector<EmulatorSlotRecord> load_emulator_slots() const
    {
        std::vector<EmulatorSlotRecord> slots;
        if (!ensure_layout()) return slots;

        std::ifstream input(emulator_config_path().c_str());
        if (!input.is_open()) {
            return default_slots();
        }

        try {
            nlohmann::json document;
            input >> document;
            slots = document.value("slots", default_slots());
        } catch (...) {
            slots = default_slots();
        }

        if (slots.empty()) slots = default_slots();
        return slots;
    }

    std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> load_emulator_slots_by_protocol() const
    {
        auto groups = default_slots_by_protocol();
        if (!ensure_layout()) return groups;

        std::ifstream input(emulator_config_path().c_str());
        if (!input.is_open()) {
            return groups;
        }

        try {
            nlohmann::json document;
            input >> document;
            if (document.contains("slots_by_protocol") && document["slots_by_protocol"].is_object()) {
                const auto &node = document["slots_by_protocol"];
                for (const auto &protocol : supported_emulator_protocols()) {
                    const auto key = protocol_storage_key(protocol);
                    if (node.contains(key) && node[key].is_array()) {
                        groups[protocol] = node[key].get<std::vector<EmulatorSlotRecord>>();
                    }
                }
            } else {
                const auto flat = document.value("slots", default_slots());
                groups.clear();
                for (const auto &protocol : supported_emulator_protocols()) groups[protocol] = {};
                for (auto slot : flat) {
                    if (groups.find(slot.protocol) == groups.end()) slot.protocol = ProtocolKind::Iso14443A;
                    groups[slot.protocol].push_back(slot);
                }
            }
        } catch (...) {
            groups = default_slots_by_protocol();
        }

        for (const auto &protocol : supported_emulator_protocols()) {
            auto &slots = groups[protocol];
            for (size_t i = 0; i < slots.size(); ++i) {
                slots[i].slot_index = static_cast<int>(i);
                slots[i].protocol = protocol;
            }
        }
        return groups;
    }

    std::vector<MifareKeyRecord> load_mifare_keys() const
    {
        std::vector<MifareKeyRecord> keys;
        if (!ensure_layout()) return keys;

        std::ifstream input(mifare_keys_path().c_str());
        if (!input.is_open()) {
            return default_mifare_keys();
        }

        try {
            nlohmann::json document;
            input >> document;
            keys = document.value("keys", std::vector<MifareKeyRecord>{});
        } catch (...) {
            keys = default_mifare_keys();
        }
        return keys;
    }

    static std::vector<EmulatorSlotRecord> default_slots()
    {
        EmulatorSlotRecord s0;
        s0.slot_index    = 0;
        s0.protocol      = ProtocolKind::MifareClassic;
        s0.default_slot  = true;
        s0.default_protocol = true;
        s0.payload_record_id = "DEADBEEF";
        s0.raw_data = { "04: DEAD BEEF 11 22 33 44",
                        "Sector0: 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF",
                        "KeyA:FFFFFFFFFFFF  KeyB:FFFFFFFFFFFF" };

        EmulatorSlotRecord s1;
        s1.slot_index    = 1;
        s1.protocol      = ProtocolKind::Iso14443A;
        s1.default_slot  = false;
        s1.default_protocol = false;
        s1.payload_record_id = "04A1B2C3";
        s1.raw_data = { "UID: 04 A1 B2 C3", "ATQA:0344  SAK:20  NFC-A T4T",
                        "AID:D2760000850101  App:NDEF" };

        EmulatorSlotRecord s2;
        s2.slot_index    = 2;
        s2.protocol      = ProtocolKind::Iso15693;
        s2.default_slot  = false;
        s2.default_protocol = false;
        s2.payload_record_id = "E0040100112233AA";
        s2.raw_data = { "UID(rev): E0 04 01 00 11 22 33 AA",
                        "DSFID:00  AFI:00  Blocks:32x4B",
                        "IC:TI Tag-it HF-I Plus" };

        return { s0, s1, s2 };
    }

    static std::vector<MifareKeyRecord> default_mifare_keys()
    {
        return {
            {"Factory A", "FFFFFFFFFFFF", MifareKeyType::KeyA, true, "default", "2026-05-01T00:00:00"},
            {"Factory B", "FFFFFFFFFFFF", MifareKeyType::KeyB, true, "default", "2026-05-01T00:00:00"},
            {"MAD Key", "A0A1A2A3A4A5", MifareKeyType::KeyA, true, "default", "2026-05-01T00:00:00"},
            {"NFC Forum", "D3F7D3F7D3F7", MifareKeyType::KeyA, true, "default", "2026-05-01T00:00:00"},
        };
    }

private:
    static std::vector<ProtocolKind> supported_emulator_protocols()
    {
        return {
            ProtocolKind::Iso14443A,
            ProtocolKind::Iso14443B,
            ProtocolKind::Iso15693,
            ProtocolKind::MifareClassic,
        };
    }

    static std::string protocol_storage_key(ProtocolKind protocol)
    {
        switch (protocol) {
        case ProtocolKind::Iso14443A: return "iso14443a";
        case ProtocolKind::Iso14443B: return "iso14443b";
        case ProtocolKind::Iso15693: return "iso15693";
        case ProtocolKind::MifareClassic: return "mifare_classic";
        default: return "unknown";
        }
    }

    static std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> default_slots_by_protocol()
    {
        std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> groups;
        const auto base = default_slots();
        for (const auto &protocol : supported_emulator_protocols()) {
            groups[protocol] = {};
            for (auto slot : base) {
                if (slot.protocol == protocol) groups[protocol].push_back(slot);
            }
            for (size_t i = 0; i < groups[protocol].size(); ++i) {
                groups[protocol][i].slot_index = static_cast<int>(i);
                groups[protocol][i].protocol = protocol;
            }
        }
        return groups;
    }

    static bool ensure_dir(const std::string &path)
    {
        if (path.empty()) return false;
        if (::mkdir(path.c_str(), 0755) == 0) return true;
        return errno == EEXIST;
    }

    static std::string sanitize_filename(const std::string &value)
    {
        std::string result = value;
        for (char &ch : result) {
            if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == '-')) {
                ch = '_';
            }
        }
        return result;
    }

    static bool load_record(const std::string &path, SavedRecord *record)
    {
        if (!record) return false;
        std::ifstream input(path.c_str());
        if (!input.is_open()) return false;

        try {
            nlohmann::json document;
            input >> document;
            *record = document.get<SavedRecord>();
            return true;
        } catch (...) {
            return false;
        }
    }
};

} // namespace nfc_app