#pragma once

#include "nfc_hex_logger.hpp"
#include "nfc_protocol.hpp"
#include "nfc_storage.hpp"

#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>
#include <tuple>

namespace nfc_app {

struct ConnectionState {
    bool connected = false;
    TransportEndpoint endpoint;
    std::string status = "Disconnected";
    std::string detail = "Select endpoint";
    bool pn532_ready = false;
    DeviceKind device_kind = DeviceKind::Unknown;
};

struct ScanState {
    bool running = false;
    bool has_result = false;
    SavedRecord last_record;
    std::string status = "Idle";
    std::string error;
};

class NfcDeviceService {
public:
    NfcDeviceService()
    {
        refresh_endpoints();
        emulator_slots_by_protocol_ = storage_.load_emulator_slots_by_protocol();
    }

    ~NfcDeviceService()
    {
        cancel_hw_upload_.store(true);
        cancel_hw_mfkey_.store(true);
        if (hw_upload_thread_.joinable()) hw_upload_thread_.join();
        if (scan_thread_.joinable()) scan_thread_.join();
        if (probe_thread_.joinable()) probe_thread_.join();
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        disconnect();
    }

    // ── Hardware EMU slot probe (PN532Killer) ────────────────────────────────
    struct EmuSlotInfo {
        bool probed      = false;
        std::string uid;           // empty if not available
        std::string block0_hex;    // hex string of first block/page, empty if n/a
        // Full dump — populated only when user triggers "Download Data"
        std::vector<std::string> dump_lines;  // formatted hex lines (e.g. "00: 34 5D 80 C4 ...")
        bool dump_loaded = false;
    };

    EmuSlotInfo emu_slot_info(ProtocolKind protocol, int slot) const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        auto it = emu_slot_cache_.find({protocol, slot});
        return (it != emu_slot_cache_.end()) ? it->second : EmuSlotInfo{};
    }

    bool emu_probe_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_probe_running_;
    }

    std::string emu_probe_error() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_probe_error_;
    }

    // Switch hardware emulator slot + probe block0 in background thread.
    // Cancels any in-progress probe so the new switch is never silently dropped.
    bool hw_switch_emu_slot_and_probe(ProtocolKind protocol, int slot)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
        }
        // Signal any running probe to stop, then join it.
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);

        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_probe_running_ = true;
            emu_probe_error_.clear();
        }
        emu_probe_thread_ = std::thread([this, protocol, slot]() {
            perform_emu_slot_probe(protocol, slot);
        });
        return true;
    }

    static uint8_t emu_type_byte(ProtocolKind p)
    {
        switch (p) {
        case ProtocolKind::MifareClassic: return 0x01;
        case ProtocolKind::Iso15693:      return 0x03;
        default:                          return 0x02;  // NTAG / Iso14443A
        }
    }

    // Cycle HW EMU protocol: MFC → NTAG(Iso14443A) → ISO15693 → MFC
    void cycle_hw_emu_protocol()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (selected_emulator_protocol_ == ProtocolKind::MifareClassic)
            selected_emulator_protocol_ = ProtocolKind::Iso14443A;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso14443A)
            selected_emulator_protocol_ = ProtocolKind::Iso15693;
        else
            selected_emulator_protocol_ = ProtocolKind::MifareClassic;
    }

    // Start async full dump download from HW EMU slot. Results stored in EmuSlotInfo::dump_lines.
    bool hw_start_emu_dump_async(ProtocolKind protocol, int slot)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
        }
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_dump_running_ = true;
        }
        emu_dump_thread_ = std::thread([this, protocol, slot]() {
            perform_emu_slot_dump(protocol, slot);
        });
        return true;
    }

    bool emu_dump_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_dump_running_;
    }

    // Start asynchronous upload of a saved MFC record to the given HW EMU slot (0-based).
    // Returns false if already running or scan is running.
    bool hw_start_upload_async(int slot, const SavedRecord &record)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
            if (record.tag.raw_data.size() != 64) return false;
        }
        cancel_hw_upload_.store(true);
        if (hw_upload_thread_.joinable()) hw_upload_thread_.join();
        cancel_hw_upload_.store(false);
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            hw_upload_running_  = true;
            hw_upload_progress_ = 0;
            hw_upload_ok_       = false;
        }
        hw_upload_thread_ = std::thread([this, slot, record]() {
            perform_hw_upload(slot, record);
        });
        return true;
    }

    bool hw_upload_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_running_;
    }

    int hw_upload_progress() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_progress_;
    }

    bool hw_upload_ok() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_ok_;
    }

    void refresh_endpoints()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        endpoints_ = NfcTransportFactory::enumerate_endpoints();
        if (selected_endpoint_ >= static_cast<int>(endpoints_.size())) selected_endpoint_ = 0;
        if (endpoints_.empty()) return;
        // Auto-select the first USB endpoint when the intended mode is USB (default at startup).
        if (intended_kind_ == TransportKind::UsbSerial) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == TransportKind::UsbSerial) {
                    selected_endpoint_ = i;
                    break;
                }
            }
        }
    }

    // ── Device probe ─────────────────────────────────────────────────────────

    // Start background probe of all non-mock endpoints.
    // Results become available via probe_results().
    void start_probe_all()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (probe_running_) return;
            probe_running_ = true;
            // Initialise result list with "probing" placeholders
            probe_results_.clear();
            for (const auto &ep : endpoints_) {
                if (ep.kind == TransportKind::I2cBus) continue;
                DeviceProbeResult r;
                r.path      = ep.path;
                r.transport = ep.kind;
                r.probing   = true;
                probe_results_.push_back(r);
            }
            if (probe_results_.empty()) {
                probe_running_ = false;
                return;
            }
        }
        if (probe_thread_.joinable()) probe_thread_.join();
        probe_thread_ = std::thread([this]() { perform_probe_all(); });
    }

    bool probe_running() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return probe_running_;
    }

    std::vector<DeviceProbeResult> probe_results() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return probe_results_;
    }

    // ── UART configuration ───────────────────────────────────────────────────

    UartConfig uart_config() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return uart_config_;
    }

    void set_uart_config(const UartConfig &cfg)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        uart_config_ = cfg;
        // Update any matching UART endpoint's baud rate
        for (auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial && ep.path == cfg.device_path) {
                ep.baud_rate = cfg.baud_rate;
            }
        }
    }

    // Returns UART endpoints only (no mock, no USB)
    std::vector<TransportEndpoint> uart_endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TransportEndpoint> out;
        for (const auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial) out.push_back(ep);
        }
        return out;
    }

    // Returns USB serial endpoints only (no mock, no UART)
    std::vector<TransportEndpoint> usb_endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TransportEndpoint> out;
        for (const auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UsbSerial) out.push_back(ep);
        }
        return out;
    }

    // Select a USB endpoint by path and reset connection state.
    // Returns true if found and selected.
    bool select_usb_endpoint_by_path(const std::string &path)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
            if (endpoints_[i].path == path) {
                if (transport_) { transport_->close(); transport_.reset(); }
                connection_ = ConnectionState{};
                selected_endpoint_ = i;
                return true;
            }
        }
        return false;
    }

    // Pin reference table for common M5CardputerZero UART ports
    // Returns {tx_pin, rx_pin} or {-1,-1} if unknown
    static std::pair<int,int> uart_pin_hint(const std::string &dev_path)
    {
        // AX620Q / CardputerZero UART mappings (from device tree reference)
        if (dev_path.find("ttyTHS0") != std::string::npos) return {14, 15};
        if (dev_path.find("ttyTHS1") != std::string::npos) return {16, 17};
        if (dev_path.find("ttyTHS2") != std::string::npos) return {18, 19};
        if (dev_path.find("ttyS0") != std::string::npos)   return {14, 15};
        if (dev_path.find("ttyAMA0") != std::string::npos) return {8, 9};   // RPi-style
        if (dev_path.find("ttyAMA1") != std::string::npos) return {0, 1};
        return {-1, -1};
    }

    std::vector<TransportEndpoint> endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return endpoints_;
    }

    TransportEndpoint current_endpoint() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
            if (endpoints_[selected_endpoint_].kind == intended_kind_)
                return endpoints_[selected_endpoint_];
        }
        // No real endpoint for intended kind: return a synthetic one so UI can display the mode
        TransportEndpoint syn;
        syn.kind = intended_kind_;
        syn.path = "";
        syn.label = std::string(to_string(intended_kind_)) + " (no device)";
        syn.baud_rate = 0;
        return syn;
    }

    void cycle_endpoint(int delta)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return;
        const int count = static_cast<int>(endpoints_.size());
        selected_endpoint_ = (selected_endpoint_ + delta + count) % count;
    }

    // Cycle through MOCK → USB → UART → MOCK, always including all three kinds.
    // Does NOT auto-connect; just selects the endpoint and returns.
    bool cycle_device_mode(std::string *status = nullptr)
    {
        // Save current path so we can restore stable selection after re-enumeration
        std::string current_path;
        TransportKind current_kind = TransportKind::UsbSerial;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Use intended_kind_ as the authoritative "current" so that if the
            // last cycle landed on an empty slot we still advance from there.
            current_kind = intended_kind_;
            if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
                current_path = endpoints_[selected_endpoint_].path;
            }
        }

        refresh_endpoints();
        std::lock_guard<std::mutex> lock(mutex_);

        // Restore selected_endpoint_ by path after re-enumeration to avoid stale index
        if (!current_path.empty()) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].path == current_path) {
                    selected_endpoint_ = i;
                    break;
                }
            }
        }

        // Build cycle: USB → UART → I2C (always; Mock removed).
        std::vector<TransportKind> cycle;
        cycle.push_back(TransportKind::UsbSerial);
        cycle.push_back(TransportKind::UartSerial);
        cycle.push_back(TransportKind::I2cBus);

        // current_kind already determined above (stable after refresh)

        // Find next kind in cycle
        TransportKind target_kind = cycle[0];
        for (size_t i = 0; i < cycle.size(); ++i) {
            if (cycle[i] == current_kind) {
                target_kind = cycle[(i + 1) % cycle.size()];
                break;
            }
        }

        // Select first endpoint matching target kind (prefer configured UART path)
        int target_index = -1;
        if (target_kind == TransportKind::UartSerial && !uart_config_.device_path.empty()) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == target_kind && endpoints_[i].path == uart_config_.device_path) {
                    target_index = i;
                    break;
                }
            }
        }
        if (target_index < 0) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == target_kind) {
                    target_index = i;
                    break;
                }
            }
        }
        // Disconnect old transport regardless of whether we found an endpoint
        if (transport_) { transport_->close(); transport_.reset(); }
        connection_ = ConnectionState{};
        intended_kind_ = target_kind;

        if (target_index < 0) {
            // No physical device for this kind – stay in the slot, report it
            if (status) *status = std::string(to_string(target_kind)) + ": no device";
            return false;
        }

        selected_endpoint_ = target_index;
        if (status) *status = std::string("Mode: ") + to_string(target_kind);
        return true;
    }

    // Toggle between USB and UART endpoint groups, prefer configured UART path,
    // then auto-connect and probe the selected device.
    bool cycle_transport_mode(std::string *status = nullptr)
    {
        refresh_endpoints();

        TransportEndpoint selected;
        bool selected_ok = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<TransportKind> available;
            bool has_usb = false;
            bool has_uart = false;
            for (const auto &ep : endpoints_) {
                if (ep.kind == TransportKind::UsbSerial) has_usb = true;
                if (ep.kind == TransportKind::UartSerial) has_uart = true;
            }
            if (has_usb) available.push_back(TransportKind::UsbSerial);
            if (has_uart) available.push_back(TransportKind::UartSerial);
            if (available.empty()) {
                if (status) *status = "No USB/UART device found";
                return false;
            }

            TransportKind current_kind = TransportKind::UsbSerial;
            if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
                current_kind = endpoints_[selected_endpoint_].kind;
            }

            size_t next_kind_idx = 0;
            for (size_t i = 0; i < available.size(); ++i) {
                if (available[i] == current_kind) {
                    next_kind_idx = (i + 1) % available.size();
                    break;
                }
            }
            const TransportKind target_kind = available[next_kind_idx];

            int target_index = -1;
            if (target_kind == TransportKind::UartSerial && !uart_config_.device_path.empty()) {
                for (size_t i = 0; i < endpoints_.size(); ++i) {
                    if (endpoints_[i].kind == target_kind && endpoints_[i].path == uart_config_.device_path) {
                        target_index = static_cast<int>(i);
                        break;
                    }
                }
            }
            if (target_index < 0) {
                for (size_t i = 0; i < endpoints_.size(); ++i) {
                    if (endpoints_[i].kind == target_kind) {
                        target_index = static_cast<int>(i);
                        break;
                    }
                }
            }
            if (target_index < 0) {
                if (status) *status = "No endpoint for selected transport";
                return false;
            }

            if (transport_) transport_->close();
            transport_.reset();
            connection_ = ConnectionState{};
            selected_endpoint_ = target_index;
            selected = endpoints_[selected_endpoint_];
            selected_ok = true;
        }

        if (!selected_ok) return false;

        if (!connect_current()) {
            if (status) *status = std::string(to_string(selected.kind)) + " selected, connect failed";
            return false;
        }

        const auto state = connection_state();
        if (status) {
            *status = std::string(to_string(selected.kind)) + " -> " +
                      (state.pn532_ready ? state.detail : state.status);
        }
        return true;
    }

    bool connect_current()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return false;

        transport_ = NfcTransportFactory::create(endpoints_[selected_endpoint_]);
        transport_ = std::unique_ptr<INfcTransport>(
            new LoggingTransport(std::move(transport_), "NFC"));
        std::string error;
        if (!transport_->open(endpoints_[selected_endpoint_], &error)) {
            connection_.connected = false;
            connection_.endpoint = endpoints_[selected_endpoint_];
            connection_.status = "Connect failed";
            connection_.detail = error;
            connection_.pn532_ready = false;
            connection_.device_kind = DeviceKind::NotConnected;
            transport_.reset();
            return false;
        }

        connection_.connected = true;
        connection_.endpoint = endpoints_[selected_endpoint_];
        connection_.status = std::string("Connected ") + to_string(connection_.endpoint.kind);
        connection_.detail = connection_.endpoint.path;
        connection_.pn532_ready = false;
        connection_.device_kind = DeviceKind::Unknown;

        if (connection_.endpoint.kind == TransportKind::UsbSerial ||
            connection_.endpoint.kind == TransportKind::UartSerial) {
            Pn532KillerClient client(transport_.get());
            std::string probe_error;
            std::string firmware;
            const auto kind = client.detect_device(&firmware, &probe_error);
            connection_.device_kind = kind;
            if (kind == DeviceKind::PN532Killer || kind == DeviceKind::PN532) {
                connection_.pn532_ready = true;
                connection_.status = std::string("Connected ") + to_string(kind);
                const std::string fw_label = firmware.empty() ? to_string(kind) : firmware;
                connection_.detail = fw_label + std::string(" @ ") + connection_.endpoint.path;
            } else {
                connection_.detail = std::string("Raw serial only: ") + probe_error;
            }
        } else {
            // I2C: not yet implemented
            connection_.detail = "I2C: not yet implemented";
        }
        return true;
    }

    void disconnect()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (transport_) transport_->close();
        transport_.reset();
        connection_ = ConnectionState{};
    }

    ConnectionState connection_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return connection_;
    }

    ScanState scan_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return scan_;
    }

    // Drain lines pushed in real-time during a Gen1A dump (called by UI each frame).
    std::vector<std::string> drain_pending_log()
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        std::vector<std::string> out;
        out.swap(pending_log_lines_);
        return out;
    }

    // Switch PN532Killer back to reader mode. Cancel any running EMU probe/dump first.
    void hw_switch_to_reader_mode()
    {
        NfcHexLog::get().log_event("reader", "switching to reader mode");
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_probe_running_ = false;
            emu_dump_running_  = false;
        }
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            client.set_work_mode(0x01, 0x01, 0x00, nullptr);
        }
    }

    bool start_scan()
    {
        if (scan_thread_.joinable()) scan_thread_.join();
        // Cancel any running EMU probe/dump threads to avoid racing set_work_mode calls
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        std::lock_guard<std::mutex> lock(mutex_);
        if (!transport_ || !transport_->is_open()) {
            scan_.running = false;
            scan_.status = "No device";
            scan_.error = "Connect USB/UART first";
            return false;
        }
        if (scan_.running) return false;

        scan_.running = true;
        scan_.has_result = false;
        scan_.status = "Scanning";
        scan_.error.clear();
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }

        scan_thread_ = std::thread([this]() { perform_scan(); });
        return true;
    }

    bool connect_and_scan(std::string *status = nullptr)
    {
        const auto state = connection_state();
        if (!state.connected) {
            if (!connect_current()) {
                if (status) *status = "Connect failed";
                return false;
            }
        }

        if (!start_scan()) {
            const auto scan = scan_state();
            if (status) *status = scan.error.empty() ? scan.status : scan.error;
            return false;
        }

        if (status) *status = "Scanning card...";
        return true;
    }

    bool save_last_scan(std::string *error = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!scan_.has_result) {
            if (error) *error = "No scan result to save";
            return false;
        }
        return storage_.save_record(scan_.last_record, error);
    }

    bool delete_saved_record(const std::string &record_id, std::string *error = nullptr)
    {
        return storage_.delete_record(record_id, error);
    }

    std::vector<MifareKeyRecord> list_mifare_keys() const
    {
        return storage_.load_mifare_keys();
    }

    bool upsert_mifare_key(int index, const MifareKeyRecord &record, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        MifareKeyRecord normalized = record;
        normalized.key_hex = normalize_mifare_key_hex(record.key_hex);
        if (normalized.key_hex.size() != 12) {
            if (err) *err = "Key must be 12 hex chars";
            return false;
        }
        if (normalized.label.empty()) {
            normalized.label = std::string("Key ") + normalized.key_hex.substr(8, 4);
        }
        if (normalized.created_at.empty()) normalized.created_at = iso8601_now();
        if (normalized.source.empty()) normalized.source = "manual";

        if (index < 0 || index >= static_cast<int>(keys.size())) keys.push_back(normalized);
        else keys[index] = normalized;

        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    bool delete_mifare_key(int index, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        if (index < 0 || index >= static_cast<int>(keys.size())) {
            if (err) *err = "Key not found";
            return false;
        }
        keys.erase(keys.begin() + index);
        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    bool toggle_mifare_key_enabled(int index, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        if (index < 0 || index >= static_cast<int>(keys.size())) {
            if (err) *err = "Key not found";
            return false;
        }
        keys[index].enabled = !keys[index].enabled;
        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    // ── Key dictionary file service ──────────────────────────────────────────

    std::vector<std::string> list_key_files() const
    {
        return storage_.list_key_files();
    }

    std::vector<std::string> load_key_file(const std::string &filename) const
    {
        return storage_.load_key_file(filename);
    }

    // Save keys from a SavedRecord's raw_data (MFC sector trailers) to <uid>.dic.
    bool save_keys_from_record(const SavedRecord &rec, std::string *err = nullptr) const
    {
        const std::string uid = rec.tag.uid.empty() ? rec.meta.record_id : rec.tag.uid;
        return storage_.save_uid_key_file(uid, rec.tag.raw_data, err);
    }

    // ── MFKey async crack ────────────────────────────────────────────────────

    struct MfkeyResult {
        uint32_t uid;
        uint8_t  sector;
        uint8_t  key_type; // 0=A, 1=B
        std::string key_hex; // empty if not found
    };

    // Synchronously set sniffer slot UID from 8-char hex string (e.g. "DEADBEEF").
    // Builds block0: uid[4] + BCC[1] + SAK(0x08)[1] + ATQA(0x04,0x00)[2] + pad[8]
    bool hw_sniff_set_uid(const std::string &uid_hex)
    {
        if (uid_hex.size() < 8) return false;
        {
            char msg[32];
            std::snprintf(msg, sizeof(msg), "set sniffer UID: %s", uid_hex.substr(0, 8).c_str());
            NfcHexLog::get().log_event("mfkey32v2", msg);
        }
        uint8_t uid[4];
        for (int i = 0; i < 4; ++i) {
            uid[i] = static_cast<uint8_t>(std::stoul(uid_hex.substr(i * 2, 2), nullptr, 16));
        }
        uint8_t block0[16] = {};
        block0[0] = uid[0]; block0[1] = uid[1]; block0[2] = uid[2]; block0[3] = uid[3];
        block0[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]; // BCC
        block0[5] = 0x08; // SAK MFC 1K
        block0[6] = 0x04; block0[7] = 0x00; // ATQA
        // bytes 8-15 remain 0

        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        if (!transport_raw || !transport_raw->is_open()) return false;
        Pn532KillerClient client(transport_raw);
        return client.sniff_set_uid(block0);
    }

    // Synchronously enter sniffer mode on the device.
    // with_card=false → mfkey32v2 (no-card), with_card=true → mfkey64 (card-present)
    bool hw_sniff_enter_mode(bool with_card)
    {
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2",
                                   with_card ? "enter card-present sniffer mode" : "enter no-card sniffer mode");
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        if (!transport_raw || !transport_raw->is_open()) return false;
        Pn532KillerClient client(transport_raw);
        return client.sniff_enter_mode(with_card);
    }

    bool hw_start_mfkey_async(bool with_card)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        if (hw_mfkey_running_) return false;
        cancel_hw_mfkey_.store(false);
        hw_mfkey_running_  = true;
        hw_mfkey_progress_ = 0;
        hw_mfkey_results_.clear();
        hw_mfkey_thread_ = std::thread([this, with_card]() {
            perform_hw_mfkey(with_card);
        });
        hw_mfkey_thread_.detach();
        return true;
    }

    bool hw_mfkey_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_running_;
    }

    int hw_mfkey_progress() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_progress_;
    }

    std::vector<MfkeyResult> hw_mfkey_results() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_results_;
    }

    // Import a cracked MFKey result into the internal MIFARE keys JSON.
    bool import_mfkey_result(const MfkeyResult &res, std::string *err = nullptr)
    {
        if (res.key_hex.size() != 12) { if (err) *err = "No key"; return false; }
        MifareKeyRecord rec;
        char buf[64];
        std::snprintf(buf, sizeof(buf), "MFKey s%02u%c",
                      static_cast<unsigned>(res.sector), res.key_type == 0 ? 'A' : 'B');
        rec.label    = buf;
        rec.key_hex  = res.key_hex;
        rec.type     = (res.key_type == 0) ? MifareKeyType::KeyA : MifareKeyType::KeyB;
        rec.enabled  = true;
        rec.source   = "mfkey";
        return upsert_mifare_key(-1, rec, err);
    }

    std::vector<SavedRecord> list_saved_records() const
    {
        return storage_.list_records();
    }

    std::vector<EmulatorSlotRecord> emulator_slots() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(selected_emulator_protocol_);
    }

    std::vector<EmulatorSlotRecord> emulator_slots_padded(ProtocolKind protocol) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(protocol);
    }

    void cycle_slot(int delta)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &selected_slot = selected_slot_by_protocol_[selected_emulator_protocol_];
        selected_slot = (selected_slot + delta + 8) % 8;
    }

    int selected_slot_index() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = selected_slot_by_protocol_.find(selected_emulator_protocol_);
        return it == selected_slot_by_protocol_.end() ? 0 : it->second;
    }

    int selected_slot_index_for_protocol(ProtocolKind protocol) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = selected_slot_by_protocol_.find(protocol);
        return it == selected_slot_by_protocol_.end() ? 0 : it->second;
    }

    ProtocolKind current_emulator_protocol() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return selected_emulator_protocol_;
    }

    void toggle_slot_protocol()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (selected_emulator_protocol_ == ProtocolKind::Iso14443A) selected_emulator_protocol_ = ProtocolKind::Iso14443B;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso14443B) selected_emulator_protocol_ = ProtocolKind::Iso15693;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso15693) selected_emulator_protocol_ = ProtocolKind::MifareClassic;
        else selected_emulator_protocol_ = ProtocolKind::Iso14443A;
    }

    bool emulation_allowed(std::string *reason = nullptr) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!connection_.connected || connection_.device_kind != DeviceKind::PN532Killer) {
            if (reason) *reason = "PN532Killer required for EMU";
            return false;
        }
        return true;
    }

    void set_default_slot()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slots = emulator_slots_by_protocol_[selected_emulator_protocol_];
        ensure_protocol_slots_locked(selected_emulator_protocol_);
        const int selected_slot = selected_slot_by_protocol_[selected_emulator_protocol_];
        for (size_t i = 0; i < slots.size(); ++i) {
            slots[i].default_slot = (static_cast<int>(i) == selected_slot);
        }
        save_emulator_slots_locked();
    }

    bool upload_record_to_slot(const SavedRecord &record)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slot = current_slot_for_protocol_locked(record.tag.protocol, selected_slot_by_protocol_[record.tag.protocol]);
        slot.payload_record_id = record.meta.record_id;
        slot.protocol = record.tag.protocol;
        slot.raw_data = record.tag.raw_data;
        return save_emulator_slots_locked();
    }

    // Upload a record to a specific slot index (0-7); auto-expands slots as needed
    bool upload_record_to_slot_n(const SavedRecord &record, int slot_n)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slot = current_slot_for_protocol_locked(record.tag.protocol, slot_n);
        selected_slot_by_protocol_[record.tag.protocol] = slot_n;
        slot.payload_record_id = record.meta.record_id;
        slot.protocol = record.tag.protocol;
        slot.raw_data = record.tag.raw_data;
        return save_emulator_slots_locked();
    }

    // Returns exactly 8 slots (padded with empty ones if fewer exist)
    std::vector<EmulatorSlotRecord> emulator_slots_padded() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(selected_emulator_protocol_);
    }

    bool rename_saved_record(const std::string &record_id, const std::string &new_name, std::string *err = nullptr)
    {
        SavedRecord r;
        if (!storage_.load_record_by_id(record_id, &r)) {
            if (err) *err = "Record not found";
            return false;
        }
        r.meta.display_name = new_name;
        return storage_.save_record(r, err);
    }

    bool update_record_hex(const std::string &record_id, const std::vector<std::string> &raw_data, std::string *err = nullptr)
    {
        SavedRecord r;
        if (!storage_.load_record_by_id(record_id, &r)) {
            if (err) *err = "Record not found";
            return false;
        }
        r.tag.raw_data = raw_data;
        return storage_.save_record(r, err);
    }

    bool download_slot_to_saved()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto &slot = current_slot_locked();
        SavedRecord record;
        record.meta.created_at = iso8601_now();
        record.meta.record_id = "emu_slot_" + std::to_string(slot.slot_index) + "_" + record.meta.created_at;
        record.meta.display_name = "Slot " + std::to_string(slot.slot_index) + " Snapshot";
        record.meta.source = "emulator_slot";
        record.meta.transport = TransportKind::Mock;
        record.meta.transport_path = "slot://" + std::to_string(slot.slot_index);
        record.tag.protocol = slot.protocol;
        record.tag.tag_type = "Emulator Slot";
        record.tag.uid = slot.payload_record_id;
        record.tag.raw_data = slot.raw_data;
        record.emulator_slot = slot;
        return storage_.save_record(record, nullptr);
    }

private:
    static std::string normalize_mifare_key_hex(const std::string &value)
    {
        std::string out;
        out.reserve(value.size());
        for (char ch : value) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        return out;
    }

    void perform_scan()
    {
        NfcHexLog::get().log_event("scan", "start scan");
        // Snapshot connection under lock, then release so UI can call scan_state() freely.
        TransportEndpoint endpoint;
        DeviceKind device_kind = DeviceKind::Unknown;
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            endpoint    = connection_.endpoint;
            device_kind = connection_.device_kind;
            transport_raw = transport_.get();
        }

        SavedRecord record;
        std::string error;
        bool success = false;

        if (endpoint.kind == TransportKind::Mock) {
            record = build_mock_record(endpoint);
            success = true;
        } else {
            if (!transport_raw) {
                std::lock_guard<std::mutex> lock(mutex_);
                scan_.running = false;
                scan_.status = "No transport";
                scan_.error = "Transport lost during scan";
                return;
            }

            // All I/O done WITHOUT holding mutex_ so UI thread can call scan_state() freely.
            Pn532KillerClient client(transport_raw);

            // For PN532Killer, InListPassiveTarget may return instantly (~50ms) with
            // "no passive target found" because the firmware ignores MxRtyPassiveActivation.
            // Poll for up to 4 seconds (matching nfc-usb-test behaviour) so the user
            // has time to place the card after pressing the scan button.
            // For plain PN532, set_rf_passive_retries(0x20) is configured during
            // detect_device, so each call already waits ~820ms – one call is enough.
            TagInfo tag;
            bool real_ok = false;
            push_log("> Detecting card...");
            {
                auto deadline = std::chrono::steady_clock::now()
                                + std::chrono::seconds(4);
                while (!real_ok && std::chrono::steady_clock::now() < deadline) {
                    tag = TagInfo{};
                    real_ok = client.in_list_passive_target_iso14443a(&tag, &error);
                    if (!real_ok)
                        std::this_thread::sleep_for(std::chrono::milliseconds(150));
                }
            }
            if (real_ok) {
                push_log(std::string("OK ") + to_string(tag.protocol) + " " + tag.uid);
                std::string magic_err;
                if (client.is_gen1a(&magic_err)) {
                    tag.magic_type = "Gen1A";
                    push_log("> Reading Gen1A blocks...");
                    client.read_gen1a_full(nullptr, &tag.block_log, &magic_err,
                        [this](const std::string &line) { push_log(line); });
                } else if (client.is_gen3(&magic_err)) {
                    tag.magic_type = "Gen3";
                } else if (client.is_gen4("00000000", &magic_err)) {
                    tag.magic_type = "Gen4";
                }
            } else {
                push_log(std::string("ERR ") + (error.empty() ? "no card" : error.substr(0, 22)));
            }

            // For standard (non-magic) Mifare Classic, read blocks via default keys.
            std::vector<std::string> mfc_blocks;
            bool mfc_read_ok = false;
            if (real_ok && tag.protocol == ProtocolKind::MifareClassic && tag.magic_type.empty()) {
                push_log("> Reading MFC blocks (default keys)...");
                // Parse UID hex string to bytes (e.g. "15223F3E" → {0x15,0x22,0x3F,0x3E})
                std::vector<uint8_t> uid_bytes;
                for (size_t i = 0; i + 1 < tag.uid.size(); i += 2) {
                    uid_bytes.push_back(static_cast<uint8_t>(
                        std::stoi(tag.uid.substr(i, 2), nullptr, 16)));
                }
                const int sc = (tag.tag_type.find("4K") != std::string::npos) ? 40 : 16;
                // Re-select the card after magic detection attempts may have disturbed it.
                client.reselect_card_lightweight(nullptr);
                std::string mfc_err;
                mfc_read_ok = client.read_mifare_standard(uid_bytes, sc, &mfc_blocks, &mfc_err,
                    [this](const std::string &line) { push_log(line); });
            }

            if (real_ok) {
                const std::string scan_source =
                    (device_kind == DeviceKind::PN532Killer) ? "pn532killer" :
                    (device_kind == DeviceKind::PN532)       ? "pn532"       : "nfc";
                record = make_record_from_tag(tag, endpoint, false, scan_source);
                if (record.tag.protocol == ProtocolKind::MifareClassic) {
                    const int sc = (record.tag.tag_type.find("4K") != std::string::npos) ? 40 : 16;
                    record.mifare_dump = MifareClassicDump{};
                    record.mifare_dump->sector_count = sc;
                    record.mifare_dump->block_count = (sc <= 32) ? sc * 4 : 32 * 4 + (sc - 32) * 16;
                    if (mfc_read_ok) {
                        record.mifare_dump->blocks_hex = mfc_blocks;
                        record.mifare_dump->attack.method = AttackMethod::DefaultKeys;
                        record.mifare_dump->attack.status = AttackStatus::Success;
                        record.mifare_dump->attack.dump_obtained = true;
                        // Populate raw_data so the Hex Editor shows all 64 blocks.
                        // Each entry is a 32-char uppercase hex string (16 bytes).
                        record.tag.raw_data = mfc_blocks;
                    } else if (!tag.magic_type.empty()) {
                        // Gen1A blocks are in tag.block_log; convert to hex entries
                        record.mifare_dump->blocks_hex.assign(record.mifare_dump->block_count, "");
                        for (const auto &line : tag.block_log) {
                            // Format: "NN:HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH"
                            if (line.size() >= 4 && line[2] == ':') {
                                int blk = std::stoi(line.substr(0, 2), nullptr, 10);
                                if (blk >= 0 && blk < record.mifare_dump->block_count)
                                    record.mifare_dump->blocks_hex[blk] = line.substr(3);
                            }
                        }
                        record.mifare_dump->attack.method = AttackMethod::None;
                        record.mifare_dump->attack.status = AttackStatus::Success;
                        record.mifare_dump->attack.dump_obtained = !tag.block_log.empty();
                        // Populate raw_data so the Hex Editor shows all blocks.
                        record.tag.raw_data = record.mifare_dump->blocks_hex;
                    } else {
                        record.mifare_dump->attack.status = AttackStatus::Failed;
                        record.mifare_dump->attack.reason = "no matching default key";
                    }
                }
                success = true;
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        scan_.running = false;
        scan_.has_result = success;
        scan_.last_record = record;
        scan_.status = success ? "Scan ready" : "Scan failed";
        scan_.error = success ? record.meta.notes : error;
    }

    SavedRecord build_mock_record(const TransportEndpoint &endpoint) const
    {
        // 轮转三种卡型，让模拟器看起来每次扫描都有变化
        const int kind = scan_mock_counter_++ % 3;

        TagInfo tag;
        if (kind == 0) {
            tag.protocol = ProtocolKind::MifareClassic;
            tag.tag_type = "Mifare Classic 1K";
            tag.uid = "DE AD BE EF";
            tag.identity_fields["atqa"] = "0004";
            tag.identity_fields["sak"]  = "08";
            tag.identity_fields["capacity"] = "1K";
            tag.raw_data = {
                "Block0:  DE AD BE EF 21 08 04 00 46 49 4C 4C 45 44 4B 45",
                "Block1:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "Block3:  FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF",
            };
        } else if (kind == 1) {
            tag.protocol = ProtocolKind::Iso14443A;
            tag.tag_type = "NFC-A Type 4 (NTAG213)";
            tag.uid = "04 B3 7C 2A";
            tag.identity_fields["atqa"] = "0044";
            tag.identity_fields["sak"]  = "00";
            tag.identity_fields["type"] = "NTAG213 144B";
            tag.raw_data = {
                "UID: 04 B3 7C 2A",
                "CC: E1 10 12 00  (NDEF 144B)",
                "NDEF: https://m5stack.com/products/cardputer",
            };
        } else {
            tag.protocol = ProtocolKind::Iso15693;
            tag.tag_type = "ISO 15693 (iCODE SLI)";
            tag.uid = "E0 04 01 00 5A 4B 3C 2D";
            tag.identity_fields["dsfid"] = "00";
            tag.identity_fields["afi"]   = "00";
            tag.identity_fields["blocks"] = "32 x 4B";
            tag.raw_data = {
                "UID(rev): E0 04 01 00 5A 4B 3C 2D",
                "DSFID:00  AFI:00  Blocks:32x4B",
                "Block0: 48 65 6C 6C  ('Hell')",
            };
        }

        SavedRecord record = make_record_from_tag(tag, endpoint, true, "mock_scan");
        if (kind == 0) {
            MifareClassicDump dump;
            dump.sector_count = 16;
            dump.block_count  = 64;
            dump.attack.method = AttackMethod::DefaultKeys;
            dump.attack.status = AttackStatus::Success;
            dump.attack.dump_obtained = true;
            // Generate 64 mock blocks of 16 bytes each.
            // Sector trailers (blocks 3,7,11,...,63) use FF..FF key pattern.
            for (int blk = 0; blk < 64; ++blk) {
                char hex[33];
                const bool trailer = ((blk + 1) % 4 == 0);
                if (blk == 0) {
                    // Block 0: UID + manufacturer data
                    std::snprintf(hex, sizeof(hex), "DEADBEEF2108040046494C4C45444B45");
                } else if (trailer) {
                    std::snprintf(hex, sizeof(hex), "FFFFFFFFFFFF078069FFFFFFFFFFFF%02X", blk);
                } else {
                    std::snprintf(hex, sizeof(hex), "000000000000000000000000000000%02X", blk);
                }
                dump.blocks_hex.push_back(hex);
            }
            // Populate raw_data so the Hex Editor shows all 64 blocks.
            record.tag.raw_data = dump.blocks_hex;
            record.mifare_dump = dump;
        }
        record.meta.notes = "Mock data — PN532Killer command set pending";
        return record;
    }

    SavedRecord make_record_from_tag(const TagInfo &tag, const TransportEndpoint &endpoint, bool mock, const std::string &source) const
    {
        SavedRecord record;
        record.meta.created_at = iso8601_now();
        record.meta.record_id = make_record_id(tag);
        record.meta.display_name = make_record_name(tag);
        record.meta.source = source;
        record.meta.transport = endpoint.kind;
        record.meta.transport_path = endpoint.path;
        record.meta.mock = mock;
        record.tag = tag;
        return record;
    }

    EmulatorSlotRecord &current_slot_locked()
    {
        return current_slot_for_protocol_locked(selected_emulator_protocol_, selected_slot_by_protocol_[selected_emulator_protocol_]);
    }

    EmulatorSlotRecord &current_slot_for_protocol_locked(ProtocolKind protocol, int slot_index)
    {
        ensure_protocol_slots_locked(protocol);
        auto &slots = emulator_slots_by_protocol_[protocol];
        if (slot_index < 0) slot_index = 0;
        if (slot_index > 7) slot_index = 7;
        return slots[slot_index];
    }

    void ensure_protocol_slots_locked(ProtocolKind protocol)
    {
        auto &slots = emulator_slots_by_protocol_[protocol];
        while (static_cast<int>(slots.size()) < 8) {
            EmulatorSlotRecord empty;
            empty.slot_index = static_cast<int>(slots.size());
            empty.protocol = protocol;
            slots.push_back(empty);
        }
        for (size_t i = 0; i < slots.size(); ++i) {
            slots[i].slot_index = static_cast<int>(i);
            slots[i].protocol = protocol;
        }
    }

    std::vector<EmulatorSlotRecord> protocol_slots_padded_locked(ProtocolKind protocol) const
    {
        auto it = emulator_slots_by_protocol_.find(protocol);
        std::vector<EmulatorSlotRecord> slots = (it == emulator_slots_by_protocol_.end()) ? std::vector<EmulatorSlotRecord>{} : it->second;
        while (static_cast<int>(slots.size()) < 8) {
            EmulatorSlotRecord empty;
            empty.slot_index = static_cast<int>(slots.size());
            empty.protocol = protocol;
            slots.push_back(empty);
        }
        return slots;
    }

    bool save_emulator_slots_locked()
    {
        ensure_protocol_slots_locked(ProtocolKind::Iso14443A);
        ensure_protocol_slots_locked(ProtocolKind::Iso14443B);
        ensure_protocol_slots_locked(ProtocolKind::Iso15693);
        ensure_protocol_slots_locked(ProtocolKind::MifareClassic);
        return storage_.save_emulator_slots_by_protocol(emulator_slots_by_protocol_);
    }

    // Push a log line from ANY thread without holding mutex_.
    void push_log(const std::string &line)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        pending_log_lines_.push_back(line);
    }

    mutable std::mutex mutex_;
    mutable std::mutex pending_log_mutex_;          // separate — safe to lock inside scan thread
    std::vector<std::string> pending_log_lines_;    // real-time per-block lines, drained by UI
    NfcStorage storage_;
    std::vector<TransportEndpoint> endpoints_;
    int selected_endpoint_ = 0;
    TransportKind intended_kind_ = TransportKind::UsbSerial; // tracks user intent even when no device
    std::unique_ptr<INfcTransport> transport_;
    ConnectionState connection_;
    ScanState scan_;
    ProtocolKind selected_emulator_protocol_ = ProtocolKind::MifareClassic;
    std::map<ProtocolKind, int> selected_slot_by_protocol_;
    std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> emulator_slots_by_protocol_;
    std::thread scan_thread_;
    std::thread probe_thread_;
    std::thread emu_probe_thread_;
    std::atomic<bool> cancel_emu_probe_{false};
    std::thread emu_dump_thread_;
    std::atomic<bool> cancel_emu_dump_{false};
    std::thread hw_upload_thread_;
    std::atomic<bool> cancel_hw_upload_{false};
    std::thread hw_mfkey_thread_;
    std::atomic<bool> cancel_hw_mfkey_{false};
    std::map<std::pair<ProtocolKind,int>, EmuSlotInfo> emu_slot_cache_;
    bool emu_probe_running_ = false;
    bool emu_dump_running_  = false;
    bool hw_upload_running_ = false;
    int  hw_upload_progress_ = 0;   // 0-64 (blocks uploaded so far)
    bool hw_upload_ok_       = false;
    bool hw_mfkey_running_   = false;
    int  hw_mfkey_progress_  = 0;
    std::vector<MfkeyResult> hw_mfkey_results_;
    std::string emu_probe_error_;
    mutable int scan_mock_counter_ = 0;
    std::vector<DeviceProbeResult> probe_results_;
    bool probe_running_ = false;
    UartConfig uart_config_;

    void perform_emu_slot_probe(ProtocolKind protocol, int slot)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "probe EMU slot %d", slot + 1);
            NfcHexLog::get().log_event("emu-probe", msg);
        }
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }

        EmuSlotInfo info;
        info.probed = true;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const uint8_t type_byte = emu_type_byte(protocol);

            // Switch hardware to this emulator slot and stay in EMU mode.
            std::string sw_err;
            client.set_work_mode(0x02, type_byte, static_cast<uint8_t>(slot), &sw_err);

            // Breakable wait for hardware to stabilize (10ms ticks, ~150ms total)
            for (int i = 0; i < 15; ++i) {
                if (cancel_emu_probe_.load()) {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    emu_probe_running_ = false;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            // Prepare read session
            client.emu_prepare_read(type_byte, static_cast<uint8_t>(slot));
            std::this_thread::sleep_for(std::chrono::milliseconds(20));

            if (protocol == ProtocolKind::MifareClassic) {
                // MFC: block0 bytes[0..3] = 4-byte UID
                std::vector<uint8_t> block0;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &block0)
                    && block0.size() >= 4) {
                    const size_t n = std::min(block0.size(), size_t{16});
                    char buf[33] = {};
                    for (size_t i = 0; i < n; ++i)
                        snprintf(buf + i * 2, 3, "%02X", block0[i]);
                    info.block0_hex = buf;
                    snprintf(buf, 9, "%02X%02X%02X%02X",
                             block0[0], block0[1], block0[2], block0[3]);
                    info.uid = buf;
                }
            } else if (protocol == ProtocolKind::Iso15693) {
                // ISO15693: UID at special index 0xFE00, 8 bytes reversed
                std::vector<uint8_t> uid_bytes;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0xFE00, &uid_bytes)
                    && uid_bytes.size() >= 8) {
                    char buf[17] = {};
                    // Reversed display: uid_bytes[7..0]
                    for (int i = 7; i >= 0; --i)
                        snprintf(buf + (7 - i) * 2, 3, "%02X", uid_bytes[i]);
                    info.uid = buf;
                }
                // Also read block0 so the right panel can show data before full download.
                std::vector<uint8_t> blk0;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &blk0)
                    && !blk0.empty()) {
                    const size_t n = std::min(blk0.size(), size_t{16});
                    char buf[33] = {};
                    for (size_t i = 0; i < n; ++i)
                        snprintf(buf + i * 2, 3, "%02X", blk0[i]);
                    info.block0_hex = buf;
                }
            } else {
                // NTAG/MFU: page0[0..2] + page1[0..3] = 7-byte UID
                std::vector<uint8_t> page0, page1;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &page0)
                    && page0.size() >= 4) {
                    char buf[9] = {};
                    for (size_t i = 0; i < 4; ++i)
                        snprintf(buf + i * 2, 3, "%02X", page0[i]);
                    info.block0_hex = buf;  // page0 hex
                }
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 1, &page1)
                    && page0.size() >= 3 && page1.size() >= 4) {
                    char buf[15] = {};
                    snprintf(buf, 15, "%02X%02X%02X%02X%02X%02X%02X",
                             page0[0], page0[1], page0[2],
                             page1[0], page1[1], page1[2], page1[3]);
                    info.uid = buf;
                }
            }
        }

        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        emu_slot_cache_[{protocol, slot}] = info;
        emu_probe_running_ = false;
    }

    // ── HW Upload (hfmfeload-based): upload a MFC SavedRecord to a HW EMU slot ─
    // Uses setEmulatorData (0x1E): one frame per block + done frame (index=0xFFFF).
    void perform_hw_upload(int slot, SavedRecord record)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "upload to HW slot %d", slot + 1);
            NfcHexLog::get().log_event("upload", msg);
        }
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }

        bool ok = false;
        if (transport_raw && transport_raw->is_open() && record.tag.raw_data.size() == 64) {
            Pn532KillerClient client(transport_raw);
            constexpr uint8_t type_mfc = 1;
            const uint8_t actual_slot = static_cast<uint8_t>(slot);
            bool any_fail = false;
            for (int blk = 0; blk < 64; ++blk) {
                if (cancel_hw_upload_.load()) break;
                // Parse hex string to 16 bytes
                const std::string &hex = record.tag.raw_data[static_cast<size_t>(blk)];
                if (hex.size() < 32) { any_fail = true; break; }
                std::vector<uint8_t> data;
                data.reserve(16);
                for (int b = 0; b < 16; ++b) {
                    const char hi = hex[static_cast<size_t>(b * 2)];
                    const char lo = hex[static_cast<size_t>(b * 2 + 1)];
                    auto from_hex = [](char c) -> uint8_t {
                        if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                        if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                        if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
                        return 0;
                    };
                    data.push_back(static_cast<uint8_t>((from_hex(hi) << 4) | from_hex(lo)));
                }
                if (!client.emu_upload_block(type_mfc, actual_slot,
                                             static_cast<uint16_t>(blk), data)) {
                    any_fail = true;
                    break;
                }
                {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_upload_progress_ = blk + 1;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            if (!any_fail && !cancel_hw_upload_.load()) {
                client.emu_upload_done(type_mfc, actual_slot);
                ok = true;
            }
        }

        NfcHexLog::get().log_event("upload", ok ? "upload done OK" : "upload failed");
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        hw_upload_running_  = false;
        hw_upload_ok_       = ok;
    }

    // ── MFKey crack worker ────────────────────────────────────────────────────
    // Fetches sniff nonces from PN532Killer and calls mfkey64/mfkey32v2 binaries.
    void perform_hw_mfkey(bool with_card)
    {
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2",
                                   with_card ? "start mfkey64" : "start mfkey32v2");
        // Wait for device to finish saving sniffer log after reader-mode switch.
        // Without this delay, GetSnifferLog arrives while device is still committing.
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", "waiting for device to save sniff log");
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", "fetching nonce entries");
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }

        std::vector<MfkeyResult> results;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const auto entries = client.sniff_get_mfkey_entries(with_card);
            const int total = static_cast<int>(entries.size());
            {
                char msg[64];
                std::snprintf(msg, sizeof(msg), "got %d nonce entries", total);
                NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", msg);
            }
            const std::string bin_dir = hal_path_mfkey_bin_dir();

            if (with_card) {
                // mfkey64: card-present — one auth session per entry
                // De-duplicate by (uid, nt, nr, ar, at)
                std::set<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t,uint32_t>> seen;
                int done = 0;
                for (const auto &e : entries) {
                    if (cancel_hw_mfkey_.load()) break;
                    auto key = std::make_tuple(e.uid, e.nt, e.nr, e.ar, e.at);
                    if (!seen.insert(key).second) continue;
                    char cmd[512];
                    std::snprintf(cmd, sizeof(cmd),
                        "\"%s/mfkey64\" %08x %08x %08x %08x %08x 2>/dev/null",
                        bin_dir.c_str(), e.uid, e.nt, e.nr, e.ar, e.at);
                    NfcHexLog::get().log_event("mfkey64", cmd);
                    std::string out = run_cmd_capture(cmd);
                    MfkeyResult res{e.uid, e.sector, e.key_type, {}};
                    res.key_hex = parse_mfkey_result(out);
                    if (!out.empty()) NfcHexLog::get().log_event("mfkey64", out.substr(0, out.find('\n')).c_str());
                    results.push_back(res);
                    ++done;
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_mfkey_progress_ = done * 100 / std::max(1, total);
                }
            } else {
                // mfkey32v2: no-card — needs 2 nonce pairs per (uid, sector, key_type)
                using GroupKey = std::tuple<uint32_t, uint8_t, uint8_t>;
                std::map<GroupKey, std::vector<Pn532KillerClient::MfkeyEntry>> groups;
                for (const auto &e : entries)
                    groups[{e.uid, e.sector, e.key_type}].push_back(e);
                const int group_count = static_cast<int>(groups.size());
                int done = 0;
                for (auto &[gk, caps] : groups) {
                    if (cancel_hw_mfkey_.load()) break;
                    const auto [uid, sector, key_type] = gk;
                    MfkeyResult res{uid, sector, key_type, {}};
                    // Try all pairs until a key is found
                    for (size_t i = 0; i < caps.size() && res.key_hex.empty(); ++i) {
                        for (size_t j = i + 1; j < caps.size() && res.key_hex.empty(); ++j) {
                            if (caps[i].nt == caps[j].nt) continue;
                            char cmd[512];
                            std::snprintf(cmd, sizeof(cmd),
                                "\"%s/mfkey32v2\" %08x %08x %08x %08x %08x %08x %08x 2>/dev/null",
                                bin_dir.c_str(), uid,
                                caps[i].nt, caps[i].nr, caps[i].ar,
                                caps[j].nt, caps[j].nr, caps[j].ar);
                            NfcHexLog::get().log_event("mfkey32v2", cmd);
                            std::string out = run_cmd_capture(cmd);
                            if (!out.empty()) NfcHexLog::get().log_event("mfkey32v2", out.substr(0, out.find('\n')).c_str());
                            res.key_hex = parse_mfkey_result(out);
                        }
                    }
                    results.push_back(res);
                    ++done;
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_mfkey_progress_ = done * 100 / std::max(1, group_count);
                }
            }
        }

        {
            int found_count = 0;
            for (const auto &r : results) if (!r.key_hex.empty()) ++found_count;
            char msg[64];
            std::snprintf(msg, sizeof(msg), "done, %d/%d keys found", found_count, static_cast<int>(results.size()));
            NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", msg);
        }
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        hw_mfkey_running_  = false;
        hw_mfkey_progress_ = 100;
        hw_mfkey_results_  = results;
    }

    // Run a shell command and capture stdout (max 4KB).
    static std::string run_cmd_capture(const char *cmd)
    {
        FILE *f = popen(cmd, "r");
        if (!f) return {};
        std::string out;
        char buf[256];
        while (fgets(buf, sizeof(buf), f)) out += buf;
        pclose(f);
        return out;
    }

    // Parse "Found Key: [XXXXXXXXXXXX]" from mfkey output.
    static std::string parse_mfkey_result(const std::string &output)
    {
        static const char *PREFIX = "Found Key: [";
        const size_t pos = output.find(PREFIX);
        if (pos == std::string::npos) return {};
        const size_t start = pos + strlen(PREFIX);
        const size_t end   = output.find(']', start);
        if (end == std::string::npos || end <= start) return {};
        std::string key = output.substr(start, end - start);
        // Normalize to uppercase 12 chars
        if (key.size() < 12) key = std::string(12 - key.size(), '0') + key;
        for (char &c : key) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        return key.size() == 12 ? key : std::string{};
    }

    // ── Full dump download (triggered by user action "Download Data") ─────────
    // Downloads all blocks/pages from the current HW EMU slot and stores formatted
    // hex lines in EmuSlotInfo::dump_lines.  Runs in a background thread.
    void perform_emu_slot_dump(ProtocolKind protocol, int slot)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "fetch dump slot %d", slot + 1);
            NfcHexLog::get().log_event("emu-dump", msg);
        }
        INfcTransport *transport_raw = nullptr;
        TransportEndpoint endpoint;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            endpoint      = connection_.endpoint;
        }

        std::vector<std::string> lines;
        bool ok = false;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const uint8_t type_byte = emu_type_byte(protocol);

            // Determine block count and bytes per block
            int block_count  = 64;
            int bytes_per_block = 16;
            if (protocol == ProtocolKind::Iso14443A) {          // NTAG
                block_count  = 45;  // NTAG213 default
                bytes_per_block = 4;
            } else if (protocol == ProtocolKind::Iso15693) {
                block_count  = 40;
                bytes_per_block = 4;
            }

            client.emu_prepare_read(type_byte, static_cast<uint8_t>(slot));
            std::this_thread::sleep_for(std::chrono::milliseconds(30));

            for (int blk = 0; blk < block_count; ++blk) {
                if (cancel_emu_dump_.load()) break;

                std::vector<uint8_t> data;
                if (!client.emu_download_block(type_byte, static_cast<uint8_t>(slot),
                                               static_cast<uint16_t>(blk), &data)) break;

                // Format line: "00: XXYYZZ..." (no spaces between bytes)
                char linebuf[80] = {};
                int pos = snprintf(linebuf, sizeof(linebuf), "%02X: ", blk);
                const int max_bytes = std::min((int)data.size(), bytes_per_block);
                for (int b = 0; b < max_bytes; ++b)
                    pos += snprintf(linebuf + pos, sizeof(linebuf) - pos, "%02X", data[b]);
                lines.push_back(linebuf);
                ok = true;

                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }

        // Save successful dump to local SAVED storage so it appears in the SAVED tab.
        if (ok) {
            TagInfo tag;
            tag.protocol = protocol;
            // Get UID from cache if already probed (may be empty).
            {
                std::lock_guard<std::mutex> lk2(pending_log_mutex_);
                auto it = emu_slot_cache_.find({protocol, slot});
                if (it != emu_slot_cache_.end() && !it->second.uid.empty())
                    tag.uid = it->second.uid;
            }
            // Convert dump_lines ("HH: XXYY...") to raw_data (plain hex per block).
            for (const auto &line : lines) {
                if (line.size() > 4)
                    tag.raw_data.push_back(line.substr(4));
                else
                    tag.raw_data.push_back(line);
            }

            SavedRecord record;
            record.meta.created_at     = iso8601_now();
            record.meta.record_id      = std::string("emu_dump_") + to_string(protocol)
                                         + "_" + std::to_string(slot)
                                         + "_" + record.meta.created_at;
            record.meta.display_name   = std::string("EMU ") + to_string(protocol)
                                         + " Slot" + std::to_string(slot);
            record.meta.source         = "emu_download";
            record.meta.transport      = endpoint.kind;
            record.meta.transport_path = endpoint.path;
            record.tag = tag;
            storage_.save_record(record, nullptr);
        }

        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        if (ok) {
            auto &info = emu_slot_cache_[{protocol, slot}];
            info.dump_lines  = std::move(lines);
            info.dump_loaded = true;
        }
        emu_dump_running_ = false;
    }

    void perform_probe_all()
    {
        // Take a snapshot of endpoints to probe (without holding the lock)
        std::vector<TransportEndpoint> to_probe;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &ep : endpoints_) {
                if (ep.kind != TransportKind::I2cBus) to_probe.push_back(ep);
            }
        }

        for (size_t i = 0; i < to_probe.size(); ++i) {
            const auto &ep = to_probe[i];
            DeviceProbeResult result;
            result.path      = ep.path;
            result.transport = ep.kind;
            result.probing   = false;

            // Open a temporary transport
            auto transport = NfcTransportFactory::create(ep);
            std::string open_error;
            if (!transport->open(ep, &open_error)) {
                result.device_kind = DeviceKind::NotConnected;
                result.error = open_error;
            } else {
                Pn532KillerClient client(transport.get());
                std::string fw;
                std::string err;
                result.device_kind = client.detect_device(&fw, &err);
                result.firmware    = fw;
                result.error       = err;
                transport->close();
            }

            // Update probe_results_ entry in place
            std::lock_guard<std::mutex> lock(mutex_);
            if (i < probe_results_.size()) {
                probe_results_[i] = result;
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        probe_running_ = false;
    }

};

} // namespace nfc_app