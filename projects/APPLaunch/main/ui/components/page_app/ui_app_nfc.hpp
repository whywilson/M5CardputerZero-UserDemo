#pragma once

#include "../nfc/nfc_device_service.hpp"
#include "../ui_app_page.hpp"
#include "compat/input_keys.h"
#include "keyboard_input.h"

#include <cctype>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

class UINfcPage : public app_base
{
    enum class Tab {
        Read = 0,
        Saved,
        Emulator,
        Tools,
    };

    enum class Modal {
        None,
        Action,       // Upload to Slot / Edit Name / Edit Hex
        SlotSelect,   // Choose target slot 0-7
        EditName,     // Rename the record
        EditHex,      // Edit raw hex data lines
        DeviceProbe,  // Probe all ports for PN532/PN532Killer
        UartConfig,   // Configure UART device path + baud rate
        UidChanger,   // Tool placeholder page
        TagEraser,    // Tool placeholder page
        ToolPage,      // Tool detail page
        EmulatorAction,// Upload / download / default menu
        HexExitConfirm,// Save/discard/cancel prompt
        ToolInfo,      // 'i' key tool detail popup (Tools tab only)
        AppInfo,       // 'i' key global RFID app introduction
        PostScan,      // After scan result: Read Again / Save Tag menu
        ReadMenu,      // Read-mode OK menu: [Scan Card / Port Settings (UART) or Reconnect (USB)]
        PortSettings,  // TX / RX / BAUD config popup
        UsbSelect,     // Multiple USB ports: choose which to connect
        HexLog,        // Ctrl+L full-screen hex TX/RX log overlay
    };

public:
    UINfcPage() : app_base()
    {
        set_page_title("RFID");
        refresh_saved_records();
        refresh_mifare_keys();
        creat_UI();
        event_handler_init();
        ui_timer_ = lv_timer_create(UINfcPage::ui_timer_cb, 200, this);
        render_all();
    }

    ~UINfcPage()
    {
        if (ui_timer_) lv_timer_delete(ui_timer_);
    }

private:
    nfc_app::NfcDeviceService service_;
    std::unordered_map<std::string, lv_obj_t *> ui_obj_;
    std::vector<nfc_app::SavedRecord> saved_records_;
    Tab current_tab_ = Tab::Read;
    int read_action_idx_ = 0;
    int saved_idx_ = 0;
    int tools_idx_ = 0;
    lv_timer_t *ui_timer_ = nullptr;
    std::string ui_message_ = "v1: USB/UART abstracted, full PN532Killer command set pending";
    Modal modal_          = Modal::None;
    int   modal_idx_      = 0;
    int   slot_select_idx_= 0;
    std::string edit_buf_;
    int   edit_hex_line_  = 0;
    bool  edit_hex_dirty_ = false;
    std::vector<nfc_app::MifareKeyRecord> mifare_keys_;
    int mifare_key_idx_ = 0;
    int mifare_key_field_idx_ = 0;
    bool mifare_key_editing_ = false;
    bool mifare_key_creating_ = false;
    nfc_app::MifareKeyRecord mifare_key_edit_;
    // UART config edit state
    int   uart_field_idx_ = 0;  // 0=device 1=baud 2=tx 3=rx
    nfc_app::UartConfig uart_edit_buf_;
    int active_tool_idx_ = 0;
    // Read tab scan log
    std::vector<std::string> scan_log_lines_;
    int log_scroll_offset_ = 0;
    bool last_scan_running_ = false;
    int  app_info_scroll_ = 0;  // AppInfo modal scroll offset (line index)
    // Long-press scroll tracking
    uint32_t held_scroll_key_      = 0;
    uint32_t held_scroll_start_ms_ = 0;
    uint32_t held_scroll_last_ms_  = 0;
    // Hardware EMU slot (PN532Killer)
    int hw_emu_slot_ = 0;
    // Dump panel scroll offset (line index within dump_lines)
    int emu_dump_scroll_ = 0;
    // Toast notification (auto-dismiss 1s popup)
    std::string toast_msg_;
    uint32_t    toast_expire_tick_ = 0;  // 0 = no active toast
    // EMU dump completion tracking (to show toast when async dump finishes)
    bool last_emu_dump_running_   = false;
    // HW upload completion tracking
    bool last_hw_upload_running_  = false;
    // MFKey tool state
    bool last_hw_mfkey_running_  = false;
    std::vector<nfc_app::NfcDeviceService::MfkeyResult> mfkey_results_;
    int  mfkey_result_idx_ = 0;
    // MFKey step-by-step wizard state
    // mfkey32v2: 0=uid_input 1=sniffing 2=cracking 3=results
    // mfkey64:   0=ready     1=sniffing 2=cracking 3=results
    int  mfkey_step_ = 0;
    std::string mfkey_uid_input_; // hex UID typed by user (mfkey32v2 only)
    // MIFARE Keys file-browser sub-mode
    bool mifare_keys_file_mode_ = false;      // false=internal, true=file list
    std::vector<std::string> key_files_;      // .dic/.txt file names
    int  key_file_idx_ = 0;                   // selected file
    std::vector<std::string> key_file_keys_;  // keys loaded from selected file
    int  key_file_key_idx_ = 0;               // scroll in loaded key list
    // Port Settings field selection (0=TX 1=RX 2=BAUD)
    int port_settings_field_ = 0;
    // USB port selection (index into usb_endpoints() list)
    int usb_select_idx_ = 0;
    // Cached USB endpoint list for UsbSelect modal
    std::vector<nfc_app::TransportEndpoint> usb_select_list_;
    // Hex log overlay scroll offset (line index from top)
    int hex_log_scroll_ = 0;

    static constexpr int TAB_H = 24;
    static constexpr int CONTENT_Y = 26;
    static constexpr int CONTENT_H = 120;
    static constexpr int LOG_VISIBLE_LINES = 9;
    // HexLog overlay: 320×140 content area, 11px per line => ~12 lines
    static constexpr int LOG_VISIBLE_HEX_LINES = 12;

    void creat_UI()
    {
        lv_obj_t *bg = lv_obj_create(ui_APP_Container);
        lv_obj_set_size(bg, 320, 150);
        lv_obj_set_pos(bg, 0, 0);
        lv_obj_set_style_radius(bg, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(bg, lv_color_hex(0x0B0B0B), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(bg, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(bg, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(bg, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(bg, LV_OBJ_FLAG_SCROLLABLE);
        ui_obj_["bg"] = bg;

        lv_obj_t *tab_bar = lv_obj_create(bg);
        lv_obj_set_size(tab_bar, 320, TAB_H);
        lv_obj_set_pos(tab_bar, 0, 0);
        lv_obj_set_style_radius(tab_bar, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(tab_bar, lv_color_hex(0x111111), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(tab_bar, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(tab_bar, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(tab_bar, LV_OBJ_FLAG_SCROLLABLE);

        const char *titles[4] = {"READ", "SAVED", "EMU", "TOOLS"};
        for (int index = 0; index < 4; ++index) {
            const std::string key = std::string("tab_") + std::to_string(index);
            lv_obj_t *item = lv_obj_create(tab_bar);
            lv_obj_set_size(item, 78, TAB_H - 2);
            lv_obj_set_pos(item, 1 + index * 80, 1);
            lv_obj_set_style_radius(item, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_border_width(item, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_pad_all(item, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(item, LV_OBJ_FLAG_SCROLLABLE);
            lv_obj_t *label = lv_label_create(item);
            lv_label_set_text(label, titles[index]);
            lv_obj_center(label);
            ui_obj_[key] = item;
        }

        lv_obj_t *content = lv_obj_create(bg);
        lv_obj_set_size(content, 320, CONTENT_H);
        lv_obj_set_pos(content, 0, CONTENT_Y);
        lv_obj_set_style_radius(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
        ui_obj_["content"] = content;
    }

    void event_handler_init()
    {
        lv_obj_add_event_cb(ui_root, UINfcPage::static_lvgl_handler, LV_EVENT_ALL, this);
    }

    static void static_lvgl_handler(lv_event_t *e)
    {
        UINfcPage *self = static_cast<UINfcPage *>(lv_event_get_user_data(e));
        if (self) self->event_handler(e);
    }

    static void ui_timer_cb(lv_timer_t *timer)
    {
        UINfcPage *self = static_cast<UINfcPage *>(lv_timer_get_user_data(timer));
        if (!self) return;
        // Long-press scroll: after holding key for 400ms scroll, after 1500ms scroll 3x fast
        // Works for Read tab scan log AND for HexLog modal
        if (self->held_scroll_key_ != 0) {
            const bool is_read_scroll = self->modal_ == Modal::None && self->current_tab_ == Tab::Read;
            const bool is_hexlog_scroll = self->modal_ == Modal::HexLog;
            if (is_read_scroll || is_hexlog_scroll) {
                const uint32_t now = lv_tick_get();
                const uint32_t held_ms = now - self->held_scroll_start_ms_;
                const uint32_t interval = (held_ms > 1500) ? 50 : 150;
                if (held_ms > 400 && now - self->held_scroll_last_ms_ > interval) {
                    const int dir   = (self->held_scroll_key_ == KEY_DOWN) ? 1 : -1;
                    const int step  = (held_ms > 1500) ? 3 : 1;
                    const int delta = dir * step;
                    if (is_read_scroll) {
                        const int max_scroll = std::max(0, (int)self->scan_log_lines_.size() - LOG_VISIBLE_LINES);
                        self->log_scroll_offset_ = std::max(0, std::min(max_scroll, self->log_scroll_offset_ + delta));
                    } else {
                        const int total = nfc_app::NfcHexLog::get().total_lines();
                        const int max_scroll = std::max(0, total - LOG_VISIBLE_HEX_LINES);
                        self->hex_log_scroll_ = std::max(0, std::min(max_scroll, self->hex_log_scroll_ + delta));
                        self->render_all();
                    }
                    self->held_scroll_last_ms_ = now;
                }
            }
        }
        // Auto-clear expired toast
        if (!self->toast_msg_.empty() && self->toast_expire_tick_ != 0) {
            if (lv_tick_get() >= self->toast_expire_tick_) {
                self->toast_msg_.clear();
                self->toast_expire_tick_ = 0;
            }
        }
        // Detect EMU dump completion → show toast once
        const bool emu_running_now = self->service_.emu_dump_running();
        if (self->last_emu_dump_running_ && !emu_running_now) {
            // Dump just finished; service already auto-saved → show toast
            self->show_toast("Saved");
        }
        self->last_emu_dump_running_ = emu_running_now;
        // Detect HW upload completion → show toast
        const bool upload_running_now = self->service_.hw_upload_running();
        if (self->last_hw_upload_running_ && !upload_running_now) {
            self->show_toast(self->service_.hw_upload_ok() ? "Upload OK" : "Upload failed");
        }
        self->last_hw_upload_running_ = upload_running_now;
        // Detect MFKey crack completion → cache results and advance wizard to step 3
        const bool mfkey_running_now = self->service_.hw_mfkey_running();
        if (self->last_hw_mfkey_running_ && !mfkey_running_now) {
            // Normal path: saw running=true, now running=false
            self->mfkey_results_ = self->service_.hw_mfkey_results();
            self->mfkey_result_idx_ = 0;
            if (self->mfkey_step_ == 2) self->mfkey_step_ = 3;
            self->show_toast(self->mfkey_results_.empty() ? "No results" : "Cracking done");
        } else if (self->mfkey_step_ == 2 && !mfkey_running_now) {
            // Race-condition path: task finished before timer ever saw running=true
            // (e.g. no captured nonces → returns instantly; binary missing → returns instantly)
            self->mfkey_results_ = self->service_.hw_mfkey_results();
            self->mfkey_result_idx_ = 0;
            self->mfkey_step_ = 3;
            self->show_toast(self->mfkey_results_.empty() ? "No results" : "Cracking done");
        }
        self->last_hw_mfkey_running_ = mfkey_running_now;
        self->render_all();
    }

    void event_handler(lv_event_t *e)
    {
        // Must guard first: handler is registered for LV_EVENT_ALL.
        // LV_EVENT_KEYBOARD_GET_KEY dereferences lv_event_get_param() directly,
        // which is null/garbage for non-keyboard events → crash without this guard.
        if (lv_event_get_code(e) != LV_EVENT_KEYBOARD) return;
        if (!lv_event_get_param(e)) return;

        const uint32_t raw_key = LV_EVENT_KEYBOARD_GET_KEY(e);
        const auto *key_item = static_cast<struct key_item *>(lv_event_get_param(e));
        const uint32_t mods = key_item ? key_item->mods : 0;

        // Track key press for long-press scroll (Read tab or HexLog modal)
        if (IS_KEY_PRESSED(e)) {
            const uint32_t nk = normalize_main_key(raw_key);
            const bool want_scroll_read = (nk == KEY_UP || nk == KEY_DOWN)
                                          && modal_ == Modal::None
                                          && current_tab_ == Tab::Read;
            const bool want_scroll_hexlog = (nk == KEY_UP || nk == KEY_DOWN)
                                             && modal_ == Modal::HexLog;
            if (want_scroll_read || want_scroll_hexlog) {
                if (held_scroll_key_ != nk) {
                    held_scroll_key_      = nk;
                    held_scroll_start_ms_ = lv_tick_get();
                    held_scroll_last_ms_  = held_scroll_start_ms_;
                }
            }
            return;
        }

        if (!IS_KEY_RELEASED(e)) return;

        // On release, clear held scroll key
        {
            const uint32_t nk = normalize_main_key(raw_key);
            if (nk == KEY_UP || nk == KEY_DOWN) {
                held_scroll_key_ = 0;
            }
        }

        // Global Ctrl+L: toggle HexLog overlay (works from any tab/state)
        if ((mods & KBD_MOD_CTRL) && raw_key == KEY_L) {
            if (modal_ == Modal::HexLog) {
                modal_ = Modal::None;
            } else {
                modal_ = Modal::HexLog;
                // Scroll to bottom so latest entries are visible
                const int total = nfc_app::NfcHexLog::get().total_lines();
                hex_log_scroll_ = std::max(0, total - LOG_VISIBLE_HEX_LINES);
            }
            render_all();
            return;
        }

        if (modal_ != Modal::None) {
            handle_modal_key(raw_key, mods);
            return;
        }

        // In EMU tab: F/X always cycle hardware slot (even when dump is shown and UP/DOWN scrolls)
        if (current_tab_ == Tab::Emulator && modal_ == Modal::None &&
            (raw_key == KEY_F || raw_key == KEY_X)) {
            const auto conn = service_.connection_state();
            if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
                const int delta = (raw_key == KEY_F) ? -1 : 1;
                hw_emu_slot_ = (hw_emu_slot_ + delta + 8) % 8;
                emu_dump_scroll_ = 0;
                const auto proto = service_.current_emulator_protocol();
                service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
                ui_message_ = "HW Slot " + std::to_string(hw_emu_slot_ + 1);
                render_all();
            }
            return;
        }

        const uint32_t key = normalize_main_key(raw_key);

        switch (key) {
        case KEY_LEFT:
            switch_tab(-1);
            break;
        case KEY_RIGHT:
            switch_tab(1);
            break;
        case KEY_TAB:
            if (current_tab_ == Tab::Read) {
                service_.cycle_device_mode(&ui_message_);
                render_all();
            } else if (current_tab_ == Tab::Emulator) {
                const auto conn = service_.connection_state();
                if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
                    service_.cycle_hw_emu_protocol();
                    // Probe new protocol on the same hardware slot
                    const auto proto = service_.current_emulator_protocol();
                    service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
                } else {
                    service_.toggle_slot_protocol();
                }
                ui_message_ = std::string("Protocol -> ") + nfc_app::to_string(service_.current_emulator_protocol());
                render_all();
            }
            break;
        case KEY_UP:
            navigate(-1);
            break;
        case KEY_DOWN:
            navigate(1);
            break;
        case KEY_ENTER:
            activate();
            break;
        case KEY_I:
            if (modal_ == Modal::None) {
                modal_ = Modal::AppInfo;
                render_all();
            }
            break;
        case KEY_S:
            if (current_tab_ == Tab::Read) {                std::string error;
                if (service_.save_last_scan(&error)) {
                    refresh_saved_records();
                    show_toast("Saved");
                    ui_message_ = "Record saved to JSON";
                } else {
                    ui_message_ = error;
                }
                render_all();
            }
            break;
        case KEY_R:
            // Quick scan shortcut on Read tab: connect if needed, then scan
            if (current_tab_ == Tab::Read) {
                const auto scan = service_.scan_state();
                if (!scan.running) {
                    scan_log_lines_.clear();
                    log_scroll_offset_ = 0;
                    const auto conn = service_.connection_state();
                    const auto ep   = service_.current_endpoint();
                    if (!conn.connected && ep.kind != nfc_app::TransportKind::I2cBus) {
                        scan_log_lines_.push_back("> Connect " + ep.label.substr(0, 22) + "...");
                        render_all();
                        const bool ok = service_.connect_current();
                        const auto conn2 = service_.connection_state();
                        if (!ok) {
                            scan_log_lines_.push_back("ERR " + conn2.detail.substr(0, 28));
                            ui_message_ = "Connect failed";
                            render_all();
                            break;
                        }
                        scan_log_lines_.push_back("OK  " + conn2.detail.substr(0, 28));
                    }
                    scan_log_lines_.push_back("> Scan card...");
                    service_.start_scan();
                    ui_message_ = "Scanning...";
                    render_all();
                }
            }
            break;
        case KEY_ESC:
            if (go_back_home) go_back_home();
            break;
        default:
            break;
        }
    }

    uint32_t normalize_main_key(uint32_t key) const
    {
        switch (key) {
        case KEY_F: return KEY_UP;
        case KEY_Z: return KEY_LEFT;
        case KEY_X: return KEY_DOWN;
        case KEY_C: return KEY_RIGHT;
        default: return key;
        }
    }

    void switch_tab(int delta)
    {
        const Tab prev_tab = current_tab_;
        int tab_index = static_cast<int>(current_tab_);
        tab_index = (tab_index + delta + 4) % 4;
        current_tab_ = static_cast<Tab>(tab_index);
        const auto conn = service_.connection_state();
        if (current_tab_ == Tab::Emulator) {
            // When entering EMU tab with PN532Killer: auto-enter emulator mode for current slot.
            if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
                const auto proto = service_.current_emulator_protocol();
                service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
            }
        } else if (current_tab_ == Tab::Read) {
            // When entering READ tab with PN532Killer: always switch back to reader mode
            // regardless of which tab we came from (e.g. from Tools or Emulator).
            if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
                service_.hw_switch_to_reader_mode();
            }
        }
        render_all();
    }

    void navigate(int delta)
    {
        switch (current_tab_) {
        case Tab::Read:
            {
                const int max_scroll = std::max(0, (int)scan_log_lines_.size() - LOG_VISIBLE_LINES);
                log_scroll_offset_ = std::max(0, std::min(max_scroll, log_scroll_offset_ + delta));
            }
            break;
        case Tab::Saved:
            if (!saved_records_.empty()) {
                saved_idx_ = (saved_idx_ + delta + static_cast<int>(saved_records_.size())) % static_cast<int>(saved_records_.size());
            }
            break;
        case Tab::Emulator: {
            const auto conn = service_.connection_state();
            if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
                const auto info = service_.emu_slot_info(
                    service_.current_emulator_protocol(), hw_emu_slot_);
                if (info.dump_loaded && !info.dump_lines.empty()) {
                    // Dump is visible: UP/DOWN scroll through blocks
                    const int total = static_cast<int>(info.dump_lines.size());
                    const int max_scroll = std::max(0, total - 7);
                    emu_dump_scroll_ = std::max(0, std::min(max_scroll, emu_dump_scroll_ + delta));
                } else {
                    // No dump: UP/DOWN cycle hardware slot
                    hw_emu_slot_ = (hw_emu_slot_ + delta + 8) % 8;
                    emu_dump_scroll_ = 0;
                    const auto proto = service_.current_emulator_protocol();
                    service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
                    ui_message_ = "HW Slot " + std::to_string(hw_emu_slot_ + 1);
                }
            } else {
                service_.cycle_slot(delta);
                ui_message_ = "Slot changed";
            }
            break;
        }
        case Tab::Tools:
            tools_idx_ = (tools_idx_ + delta + 5) % 5;
            break;
        }
        render_all();
    }

    void activate()
    {
        switch (current_tab_) {
        case Tab::Read:
            {
                const auto scan = service_.scan_state();
                if (scan.has_result) {
                    modal_     = Modal::PostScan;
                    modal_idx_ = 0;
                } else if (!scan.running) {
                    const auto ep = service_.current_endpoint();
                    if (ep.kind == nfc_app::TransportKind::UartSerial) {
                        // UART mode: show Read menu (Scan Card / Port Settings)
                        uart_edit_buf_ = service_.uart_config();
                        port_settings_field_ = 0;
                        modal_ = Modal::ReadMenu;
                        modal_idx_ = 0;
                    } else if (ep.kind == nfc_app::TransportKind::UsbSerial) {
                        // USB mode: if already connected show ReadMenu;
                        //           if not connected and multiple USB → port selector;
                        //           if not connected and single USB → connect now.
                        const auto conn = service_.connection_state();
                        if (conn.connected && conn.pn532_ready) {
                            modal_ = Modal::ReadMenu;
                            modal_idx_ = 0;
                        } else {
                            // Refresh endpoint list so we get the latest USB devices
                            service_.refresh_endpoints();
                            usb_select_list_ = service_.usb_endpoints();
                            if (usb_select_list_.size() > 1) {
                                usb_select_idx_ = 0;
                                modal_ = Modal::UsbSelect;
                                modal_idx_ = 0;
                            } else {
                                // Single USB port: connect directly
                                scan_log_lines_.clear();
                                log_scroll_offset_ = 0;
                                const std::string lbl = usb_select_list_.empty()
                                    ? ep.label : usb_select_list_[0].label;
                                scan_log_lines_.push_back("> Connect " + lbl.substr(0, 22) + "...");
                                render_all();
                                const bool ok = service_.connect_current();
                                const auto conn2 = service_.connection_state();
                                if (!ok) {
                                    scan_log_lines_.push_back("ERR " + conn2.detail.substr(0, 28));
                                    ui_message_ = "Connect failed";
                                } else {
                                    scan_log_lines_.push_back("OK  " + conn2.detail.substr(0, 28));
                                    ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn2.device_kind);
                                }
                            }
                        }
                    } else if (ep.kind == nfc_app::TransportKind::I2cBus) {
                        // I2C placeholder: not implemented yet
                        ui_message_ = "I2C: not yet implemented";
                    }
                }
            }
            break;
        case Tab::Saved:
            activate_saved_action();
            break;
        case Tab::Emulator:
            if (service_.emulation_allowed(&ui_message_)) {
                modal_ = Modal::EmulatorAction;
                modal_idx_ = 0;
            }
            break;
        case Tab::Tools:
            activate_tool_action();
            break;
        }
        render_all();
    }

    void activate_read_action()
    {
        switch (read_action_idx_) {
        case 0:
            service_.refresh_endpoints();
            service_.cycle_endpoint(1);
            ui_message_ = "Endpoint cycled";
            break;
        case 1: {
            const auto state = service_.connection_state();
            if (state.connected) {
                service_.disconnect();
                ui_message_ = "Device disconnected";
            } else if (service_.connect_current()) {
                ui_message_ = "Device connected";
            } else {
                ui_message_ = "Connect failed";
            }
            break;
        }
        case 2:
            service_.start_scan();
            ui_message_ = "Scan requested";
            break;
        case 3: {
            std::string error;
            if (service_.save_last_scan(&error)) {
                refresh_saved_records();
                show_toast("Saved");
                ui_message_ = "Record saved to JSON";
            } else {
                ui_message_ = error;
            }
            break;
        }
        default:
            break;
        }
    }

    void activate_saved_action()
    {
        if (saved_records_.empty()) {
            refresh_saved_records();
            ui_message_ = "Reloaded saved list";
            return;
        }
        modal_     = Modal::Action;
        modal_idx_ = 0;
    }

    void activate_tool_action()
    {
        active_tool_idx_ = tools_idx_;
        if (active_tool_idx_ == 0) refresh_mifare_keys();
        // Reset MFKey wizard state when (re-)entering the tool
        if (active_tool_idx_ == 3 || active_tool_idx_ == 4) {
            mfkey_step_      = 0;
            mfkey_uid_input_ = "";
            mfkey_results_.clear();
            mfkey_result_idx_ = 0;
        }
        modal_ = Modal::ToolPage;
        ui_message_ = std::string(tool_name(active_tool_idx_)) + " opened";
    }

    void show_toast(const std::string &msg)
    {
        toast_msg_          = msg;
        toast_expire_tick_  = lv_tick_get() + 1000;
    }

    void refresh_saved_records()
    {
        saved_records_ = service_.list_saved_records();
        if (saved_idx_ >= static_cast<int>(saved_records_.size())) saved_idx_ = 0;
    }

    void refresh_mifare_keys()
    {
        mifare_keys_ = service_.list_mifare_keys();
        if (mifare_key_idx_ > static_cast<int>(mifare_keys_.size())) {
            mifare_key_idx_ = static_cast<int>(mifare_keys_.size());
        }
    }

    void render_all()
    {
        update_scan_log();
        if (current_tab_ == Tab::Tools) {
            if (modal_ == Modal::DeviceProbe) set_page_title("RFID > Device Probe");
            else if (modal_ == Modal::UartConfig) set_page_title("RFID > UART Config");
            else if (modal_ == Modal::UidChanger) set_page_title("RFID > UID Changer");
            else if (modal_ == Modal::TagEraser) set_page_title("RFID > Tag Eraser");
            else if (modal_ == Modal::ToolPage) set_page_title((std::string("RFID > ") + tool_name(active_tool_idx_)).c_str());
            else set_page_title("RFID");
        } else {
            set_page_title("RFID");
        }
        render_tabs();
        render_content();
    }

    void render_tabs()
    {
        for (int index = 0; index < 4; ++index) {
            lv_obj_t *item = ui_obj_[std::string("tab_") + std::to_string(index)];
            const bool active = (index == static_cast<int>(current_tab_));
            lv_obj_set_style_bg_color(item, lv_color_hex(active ? 0xF7A600 : 0x1E1E1E), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(item, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_text_color(item, lv_color_hex(active ? 0x000000 : 0xD0D0D0), LV_PART_MAIN | LV_STATE_DEFAULT);
        }
    }

    void render_content()
    {
        lv_obj_t *content = ui_obj_["content"];
        lv_obj_clean(content);

        switch (current_tab_) {
        case Tab::Read:
            render_read_tab(content);
            if (modal_ == Modal::PostScan) render_post_scan_modal(content);
            else if (modal_ == Modal::ReadMenu) render_read_menu_modal(content);
            else if (modal_ == Modal::PortSettings) render_port_settings_modal(content);
            else if (modal_ == Modal::UsbSelect) render_usb_select_modal(content);
            break;
        case Tab::Saved:
            render_saved_tab(content);
            if (modal_ != Modal::None && modal_ != Modal::AppInfo) render_saved_modal(content);
            break;
        case Tab::Emulator:
            render_emulator_tab(content);
            if (modal_ == Modal::EmulatorAction) render_emulator_modal(content);
            break;
        case Tab::Tools:
            render_tools_tab(content);
            break;
        }
        // Global overlay: AppInfo modal shown on any tab
        if (modal_ == Modal::AppInfo) {
            render_app_info_modal(content);
        }
        // HexLog overlay: full-screen Ctrl+L log overlay (above everything, including AppInfo)
        if (modal_ == Modal::HexLog) {
            render_hex_log_overlay(content);
        }
        // Toast overlay: 1-second auto-dismiss popup on top of everything
        if (!toast_msg_.empty()) {
            render_toast_overlay(content);
        }
    }

    void update_scan_log()
    {
        // Always drain real-time block lines pushed during Gen1A dump
        {
            auto lines = service_.drain_pending_log();
            for (auto &l : lines) {
                scan_log_lines_.push_back(std::move(l));
                log_scroll_offset_ = std::max(0, (int)scan_log_lines_.size() - LOG_VISIBLE_LINES);
            }
        }

        const auto scan = service_.scan_state();
        const bool now_running = scan.running;
        if (!now_running && last_scan_running_) {
            // Scan just finished — show magic type; block lines were already streamed in real-time
            if (scan.has_result) {
                const auto &tag = scan.last_record.tag;
                const std::string &mt = tag.magic_type;
                if (!mt.empty()) {
                    scan_log_lines_.push_back(std::string("MAGIC:") + mt);
                } else {
                    scan_log_lines_.push_back("MAGIC:Normal");
                }
                // block_log lines already pushed via drain_pending_log during scan; skip re-dump
            } else {
                scan_log_lines_.push_back(std::string("ERR ") + (scan.error.empty() ? "no tag" : to_compact(scan.error, 22)));
            }
            log_scroll_offset_ = std::max(0, (int)scan_log_lines_.size() - LOG_VISIBLE_LINES);
        }
        last_scan_running_ = now_running;
        // Cap log size to avoid unbounded growth
        if (scan_log_lines_.size() > 100) {
            scan_log_lines_.erase(scan_log_lines_.begin(), scan_log_lines_.begin() + 50);
            log_scroll_offset_ = std::max(0, log_scroll_offset_ - 50);
        }
    }

    // ── MFC dump helpers ─────────────────────────────────────────────────────

    static bool has_dump_lines(const std::vector<std::string> &lines)
    {
        for (const auto &l : lines) {
            if (l.size() >= 3 && std::isdigit((unsigned char)l[0]) &&
                std::isdigit((unsigned char)l[1]) && l[2] == ':')
                return true;
        }
        return false;
    }

    static bool is_default_mfc_key(const std::string &hex12)
    {
        static const char *defaults[] = {
            "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7",
            "000000000000", "B0B1B2B3B4B5", "4D3A99C351DD", nullptr
        };
        std::string up(hex12);
        for (auto &c : up) c = (char)std::toupper((unsigned char)c);
        for (int i = 0; defaults[i]; ++i)
            if (up == defaults[i]) return true;
        return false;
    }

    // Render one dump line ("BB:HHHH...32hex") with sector-trailer coloring.
    // unscii_8 is exactly 8px per glyph: positions are in multiples of 8.
    void render_dump_line_colored(lv_obj_t *parent, int x_base, int y, const std::string &line)
    {
        constexpr int CW = 8;  // unscii_8 char width in px
        if (line.size() < 35 || line[2] != ':') {
            create_text(parent, x_base, y, to_compact(line, 37).c_str(), 0xD8D8D8, 8);
            return;
        }
        const int block_num = (line[0] - '0') * 10 + (line[1] - '0');
        const bool is_trailer = (block_num % 4 == 3);

        // "BB:" prefix in dark gray — use unscii_8 (font_size<8) for fixed 8px/char
        char prefix[4] = { line[0], line[1], ':', '\0' };
        create_text(parent, x_base, y, prefix, 0x606060, 7);

        const int hx = x_base + 3 * CW;  // hex data starts after "BB:"
        const std::string hex = line.substr(3, 32);

        // Use font_size=7 → lv_font_unscii_8 (fixed 8px/char), matching CW=8.
        // montserrat_8 is proportional (~5-7px/char) and breaks position math.
        constexpr int DUMP_FONT = 7;

        if (is_trailer) {
            // Key A (bytes 0-5): hex chars [0..11]
            const std::string keyA = hex.substr(0, 12);
            create_text(parent, hx,               y, keyA.c_str(),
                        is_default_mfc_key(keyA) ? 0x00CC66u : 0xFF8800u, DUMP_FONT);
            // Access Conditions + GPB (bytes 6-9): hex chars [12..19]
            const std::string ac = hex.substr(12, 8);
            create_text(parent, hx + 12 * CW,    y, ac.c_str(),   0xF7A600, DUMP_FONT);
            // Key B (bytes 10-15): hex chars [20..31]
            const std::string keyB = hex.substr(20, 12);
            create_text(parent, hx + 20 * CW,    y, keyB.c_str(),
                        is_default_mfc_key(keyB) ? 0x00CC66u : 0xFF8800u, DUMP_FONT);
        } else {
            create_text(parent, hx, y, hex.c_str(), 0xC0C0C0, DUMP_FONT);
        }
    }

    void render_read_tab(lv_obj_t *parent)
    {
        const auto scan = service_.scan_state();
        const auto endpoint = service_.current_endpoint();
        const nfc_app::SavedRecord &record = scan.last_record;

        // ── Top summary bar: transport mode pills + device label ──────────
        lv_obj_t *summary = create_panel(parent, 0, 0, 320, 18, 0x161616);
        {
            const nfc_app::TransportKind cur = endpoint.kind;
            struct { const char *label; nfc_app::TransportKind kind; int x; } modes[] = {
                {"USB",  nfc_app::TransportKind::UsbSerial,   4},
                {"UART", nfc_app::TransportKind::UartSerial, 52},
                {"I2C",  nfc_app::TransportKind::I2cBus,    100},
            };
            for (auto &m : modes) {
                const bool active = (m.kind == cur);
                lv_obj_t *pill = lv_obj_create(summary);
                lv_obj_set_size(pill, 44, 14);
                lv_obj_set_pos(pill, m.x, 2);
                lv_obj_set_style_radius(pill, 3, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_color(pill, lv_color_hex(active ? 0xF7A600 : 0x303030), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_opa(pill, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_border_width(pill, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_pad_all(pill, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_clear_flag(pill, LV_OBJ_FLAG_SCROLLABLE);
                lv_obj_t *lbl = lv_label_create(pill);
                lv_label_set_text(lbl, m.label);
                lv_obj_set_style_text_color(lbl, lv_color_hex(active ? 0x000000 : 0x909090), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_center(lbl);
            }
        }
        {
            std::string disp_label = endpoint.label;
            if (endpoint.kind == nfc_app::TransportKind::UsbSerial) {
                const std::string prefix = std::string(nfc_app::to_string(endpoint.kind)) + " ";
                if (disp_label.size() > prefix.size() && disp_label.substr(0, prefix.size()) == prefix)
                    disp_label = disp_label.substr(prefix.size());
            }
            create_text(summary, 152, 3, to_compact(disp_label, 26).c_str(), 0x00D2FF, 11);
        }

        // ── Card info header (shown when a result exists) ─────────────────
        int log_y = 20;
        int log_h = 100;
        if (scan.has_result) {
            const auto &tag = record.tag;
            const auto &fields = tag.identity_fields;
            auto it_atqa = fields.find("atqa");
            auto it_sak  = fields.find("sak");
            const std::string atqa_str = (it_atqa != fields.end()) ? it_atqa->second : "-";
            const std::string sak_str  = (it_sak  != fields.end()) ? it_sak->second  : "-";

            lv_obj_t *info = create_panel(parent, 0, 20, 320, 13, 0x0C1810);
            // Single line: Protocol + UID + SAK + ATQA
            const std::string card_line =
                std::string(nfc_app::to_string(tag.protocol)) + " " + tag.uid
                + " SAK:" + sak_str + " ATQA:" + atqa_str;
            create_text(info, 4, 2, to_compact(card_line, 52).c_str(), 0x00FF88, 10);
            log_y = 34;
            log_h = 86;
        }

        // ── Log area: always full-width ────────────────────────────────────
        constexpr int LOG_LINE_H = 10;
        const int visible_lines  = log_h / LOG_LINE_H;
        const int total_lines    = static_cast<int>(scan_log_lines_.size());

        lv_obj_t *detail = create_panel(parent, 0, log_y, 320, log_h, 0x0A0A0A);

        if (!scan.running && !scan.has_result && scan_log_lines_.empty()) {
            // Idle — nothing scanned yet
            create_text(detail, 4, 10, "No Card", 0x9E9E9E, 11);
            create_text(detail, 4, 28, "OK: Menu", 0xF7A600, 10);
            create_text(detail, 4, 42, "Tab: mode", 0xD8D8D8, 10);
            if (!scan.error.empty())
                create_text(detail, 4, 56, to_compact(scan.error, 40).c_str(), 0xFF6060, 10);
        } else {
            for (int row = 0; row < visible_lines; ++row) {
                const int idx = log_scroll_offset_ + row;
                if (idx >= total_lines) break;
                const auto &line = scan_log_lines_[idx];
                const int y = 2 + row * LOG_LINE_H;

                if (line.size() >= 3 && std::isdigit((unsigned char)line[0]) &&
                    std::isdigit((unsigned char)line[1]) && line[2] == ':') {
                    render_dump_line_colored(detail, 2, y, line);
                } else {
                    uint32_t color = 0xD0D0D0;
                    if (line.size() >= 2 && line[0] == 'O' && line[1] == 'K') color = 0x00FF88;
                    else if (line.size() >= 3 && line[0] == 'E' && line[1] == 'R' && line[2] == 'R') color = 0xFF6060;
                    else if (!line.empty() && line[0] == '>') color = 0xF7A600;
                    else if (line.size() >= 6 && line.substr(0, 6) == "MAGIC:") color = 0xFFD700;
                    create_text(detail, 4, y, to_compact(line, 40).c_str(), color, 10);
                }
            }
        }
        // No footer — log lines already show status
    }

    void render_saved_tab(lv_obj_t *parent)
    {
        lv_obj_t *list = create_panel(parent, 0, 0, 122, 104, 0x101010);
        lv_obj_t *detail = create_panel(parent, 126, 0, 194, 104, 0x101010);

        if (saved_records_.empty()) {
            create_text(list, 6, 8, "No saved records", 0x7A7A7A, 11);
            create_text(detail, 6, 6, "Save from Read tab first", 0x9E9E9E, 11);
        } else {
            const int visible = saved_records_.size() < 4 ? static_cast<int>(saved_records_.size()) : 4;
            int offset = saved_idx_ - 1;
            if (offset < 0) offset = 0;
            if (offset > static_cast<int>(saved_records_.size()) - visible) offset = static_cast<int>(saved_records_.size()) - visible;
            if (offset < 0) offset = 0;
            for (int row = 0; row < visible; ++row) {
                const int index = offset + row;
                const bool selected = (index == saved_idx_);
                const auto &record = saved_records_[index];
                lv_obj_t *entry = lv_obj_create(list);
                lv_obj_remove_style_all(entry);  // strip theme padding/layout
                lv_obj_set_size(entry, 114, 20);
                lv_obj_set_pos(entry, 4, 8 + row * 24);
                lv_obj_set_style_bg_color(entry, lv_color_hex(selected ? 0xF7A600 : 0x171717), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_opa(entry, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_clear_flag(entry, LV_OBJ_FLAG_SCROLLABLE);
                create_text(entry, 4, 0, to_compact(record.meta.display_name, 14).c_str(), selected ? 0x000000 : 0xFFFFFF, 11);
                create_text(entry, 4, 10, nfc_app::to_string(record.tag.protocol), selected ? 0x2F2F2F : 0x9E9E9E, 10);
            }

            const auto &record = saved_records_[saved_idx_];
            const std::string uid_str = record.tag.uid.empty()
                ? (record.tag.raw_data.empty() ? "(none)" : to_compact(record.tag.raw_data[0], 22))
                : record.tag.uid;
            create_text(detail, 6,  4, to_compact(record.meta.display_name, 22).c_str(), 0xFFFFFF, 12);
            create_text(detail, 6, 19, (std::string("UID: ") + uid_str).c_str(), 0x00D2FF, 11);
            create_text(detail, 6, 33, (std::string("Type: ") + nfc_app::to_string(record.tag.protocol)).c_str(), 0xD8D8D8, 11);
            create_text(detail, 6, 47, (std::string("Src: ") + record.meta.source).c_str(), 0x8DB6FF, 11);
            create_text(detail, 6, 61, to_compact(record.meta.created_at, 22).c_str(), 0x9E9E9E, 10);
            create_text(detail, 6, 75, "OK: upload / edit / rename / delete", 0xF7A600, 10);
            create_text(detail, 6, 88, record.meta.mock ? "[mock]" : "[JSON]", 0x555555, 10);
        }

        create_footer(parent, ui_message_);
    }

    void render_emulator_tab(lv_obj_t *parent)
    {
        const auto connection = service_.connection_state();
        const auto protocol = service_.current_emulator_protocol();

        lv_obj_t *left  = create_panel(parent, 0, 0, 116, 104, 0x101010);
        lv_obj_t *right = create_panel(parent, 120, 0, 200, 104, 0x101010);

        if (connection.device_kind == nfc_app::DeviceKind::PN532Killer) {
            // ── HW EMU mode: show PN532Killer hardware slot ──────────────────
            const std::string proto_name =
                (protocol == nfc_app::ProtocolKind::MifareClassic) ? "MFC" :
                (protocol == nfc_app::ProtocolKind::Iso15693)      ? "ISO15693" : "NTAG";

            // Left: slot carousel + probe status
            create_text(left, 6, 4, proto_name.c_str(), 0x00D2FF, 11);
            const std::string slot_str = "HW Slot " + std::to_string(hw_emu_slot_ + 1) + "/8";
            create_text(left, 6, 18, slot_str.c_str(), 0xFFFFFF, 12);

            const auto info = service_.emu_slot_info(protocol, hw_emu_slot_);
            if (service_.emu_probe_running()) {
                create_text(left, 6, 38, "probing...", 0xF7A600, 10);
            } else if (info.probed) {
                if (!info.uid.empty())
                    create_text(left, 6, 38, to_compact(info.uid, 16).c_str(), 0x00FF88, 10);
                else {
                    const std::string err = service_.emu_probe_error();
                    create_text(left, 6, 38, err.empty() ? "(no UID)" : to_compact(err, 16).c_str(), 0xFF8888, 10);
                }
            }
            create_text(left, 6, 56, "Tab:proto", 0xD8D8D8, 10);
            create_text(left, 6, 68, "F/X:slot", 0xD8D8D8, 10);
            create_text(left, 6, 80, "OK:menu", 0xF7A600, 10);

            // Right: dump lines if downloaded, otherwise block0 hex
            static constexpr int DUMP_ROWS = 7;
            static constexpr int ROW_H     = 13;
            const bool showing_dump = info.dump_loaded && !info.dump_lines.empty();
            if (service_.hw_upload_running()) {
                const int prog = service_.hw_upload_progress();
                char prog_buf[32];
                snprintf(prog_buf, sizeof(prog_buf), "Uploading %d/64", prog);
                create_text(right, 6, 6,  "Upload:", 0xF7A600, 10);
                create_text(right, 6, 22, prog_buf, 0xFFFFFF, 11);
                // Simple progress bar (width 0-160 proportional to 0-64)
                lv_obj_t *bar_bg = lv_obj_create(right);
                lv_obj_set_pos(bar_bg, 6, 42);
                lv_obj_set_size(bar_bg, 162, 10);
                lv_obj_set_style_bg_color(bar_bg, lv_color_hex(0x333333), 0);
                lv_obj_set_style_border_width(bar_bg, 0, 0);
                lv_obj_set_style_radius(bar_bg, 3, 0);
                lv_obj_set_style_pad_all(bar_bg, 0, 0);
                const int fill_w = prog * 162 / 64;
                if (fill_w > 0) {
                    lv_obj_t *bar_fill = lv_obj_create(bar_bg);
                    lv_obj_set_pos(bar_fill, 0, 0);
                    lv_obj_set_size(bar_fill, fill_w, 10);
                    lv_obj_set_style_bg_color(bar_fill, lv_color_hex(0x00D2FF), 0);
                    lv_obj_set_style_border_width(bar_fill, 0, 0);
                    lv_obj_set_style_radius(bar_fill, 3, 0);
                    lv_obj_set_style_pad_all(bar_fill, 0, 0);
                }
            } else if (service_.emu_dump_running()) {
                create_text(right, 6, 6,  "Dump:", 0x8E8E8E, 10);
                create_text(right, 6, 22, "(downloading...)", 0xF7A600, 10);
            } else if (showing_dump) {
                const int total = static_cast<int>(info.dump_lines.size());
                const int scroll = std::max(0, std::min(emu_dump_scroll_,
                                             std::max(0, total - DUMP_ROWS)));
                char hdr[24];
                snprintf(hdr, sizeof(hdr), "Blk %d-%d/%d",
                         scroll, std::min(scroll + DUMP_ROWS - 1, total - 1), total);
                create_text(right, 6, 2, hdr, 0x00D2FF, 10);
                for (int r = 0; r < DUMP_ROWS && (scroll + r) < total; ++r)
                    create_text(right, 6, 14 + r * ROW_H,
                                info.dump_lines[scroll + r].c_str(), 0xD8D8D8, 10);
                if (total > DUMP_ROWS)
                    create_text(right, 6, 96, "U/D scroll", 0x555555, 10);
            } else if (service_.emu_probe_running()) {
                create_text(right, 6, 6,  "Block 0:", 0x8E8E8E, 10);
                create_text(right, 6, 22, "(probing...)", 0xF7A600, 10);
            } else if (info.probed && !info.block0_hex.empty()) {
                // Show block 0 in "00: HEXHEX..." format
                const auto &h = info.block0_hex;  // hex string of block0 bytes
                const size_t byte_count = h.size() / 2;
                // 8 bytes per display row (16 hex chars)
                auto row_fmt = [&](int byte_off) -> std::string {
                    std::string s;
                    for (size_t i = 0; i < 8 && (byte_off + (int)i) < (int)byte_count; ++i)
                        s += h.substr(static_cast<size_t>((byte_off + (int)i) * 2), 2);
                    return s;
                };
                create_text(right, 6, 4,  "00: ", 0x8E8E8E, 10);
                create_text(right, 32, 4, row_fmt(0).c_str(), 0xD8D8D8, 10);
                if (byte_count > 8) {
                    create_text(right, 6, 18, "   ", 0x8E8E8E, 10);
                    create_text(right, 32, 18, row_fmt(8).c_str(), 0xD8D8D8, 10);
                }
                create_text(right, 6, 36, "OK>Download for full", 0x444444, 10);
            } else {
                create_text(right, 6, 4,  "Block 0:", 0x8E8E8E, 10);
                create_text(right, 6, 20, "(no data)", 0x555555, 10);
                create_text(right, 6, 36, "F/X to probe slot", 0x444444, 10);
            }
        } else if (connection.device_kind == nfc_app::DeviceKind::PN532) {
            // ── PN532 does not support hardware EMU ──────────────────────────
            create_text(left, 6, 4,  "EMU", 0xFF4444, 12);
            create_text(left, 6, 22, "Not supported", 0xFF8888, 11);
            create_text(left, 6, 40, "PN532 has no", 0x9E9E9E, 10);
            create_text(left, 6, 54, "emulator mode", 0x9E9E9E, 10);

            create_text(right, 6, 4,  "Requires", 0x8E8E8E, 11);
            create_text(right, 6, 20, "PN532Killer", 0xFFD700, 12);
            create_text(right, 6, 38, "for HW emulation", 0x8E8E8E, 10);
            create_text(right, 6, 60, (std::string("Connected: ") + nfc_app::to_string(connection.device_kind)).c_str(), 0x555555, 10);
        } else {
            // ── No PN532Killer connected ─────────────────────────────────────
            create_text(left, 6, 4,  "EMU", 0x888888, 12);
            create_text(left, 6, 22, "No device", 0xAAAAAA, 11);
            create_text(left, 6, 40, "Connect a", 0x9E9E9E, 10);
            create_text(left, 6, 54, "PN532Killer", 0x9E9E9E, 10);

            create_text(right, 6, 4,  "Hardware EMU", 0x8E8E8E, 11);
            create_text(right, 6, 20, "requires", 0x8E8E8E, 10);
            create_text(right, 6, 34, "PN532Killer", 0xFFD700, 12);
            create_text(right, 6, 56, (std::string("Status: ") + nfc_app::to_string(connection.device_kind)).c_str(), 0x555555, 10);
        }

        create_footer(parent, ui_message_);
    }

    void render_emulator_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 170, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *card = make_modal_card(overlay, 220, 94, 0xF7A600);
        const auto slot = service_.selected_slot_index();
        create_text(card, 8, 5, (std::string(nfc_app::to_string(service_.current_emulator_protocol())) + " Slot " + std::to_string(slot)).c_str(), 0xFFFFFF, 12);
        const char *options[] = {"Download Data", "Upload Data", "Set Default"};
        for (int i = 0; i < 3; ++i) {
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 22 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x2A2A2A), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 4, options[i], sel ? 0x000000 : 0xD0D0D0, 11);
        }
    }

    void render_tools_tab(lv_obj_t *parent)
    {
        // MFKey tools (idx 3/4) use a full-width panel — hide the tool list
        const bool mfkey_active = (modal_ == Modal::ToolPage) &&
                                   (active_tool_idx_ == 3 || active_tool_idx_ == 4);

        lv_obj_t *detail = nullptr;
        if (mfkey_active) {
            detail = create_panel(parent, 0, 0, 320, 104, 0x101010);
        } else {
            lv_obj_t *list = create_panel(parent, 0, 0, 140, 104, 0x101010);
            detail = create_panel(parent, 144, 0, 176, 104, 0x101010);

            for (int i = 0; i < 5; ++i) {
                const bool selected = (modal_ == Modal::None) ? (tools_idx_ == i) : (active_tool_idx_ == i);
                lv_obj_t *row = lv_obj_create(list);
                lv_obj_remove_style_all(row);
                lv_obj_set_size(row, 132, 18);
                lv_obj_set_pos(row, 4, 6 + i * 19);
                lv_obj_set_style_bg_color(row, lv_color_hex(selected ? 0xF7A600 : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
                create_text(row, 4, 3, to_compact(tool_name(i), 16).c_str(), selected ? 0x000000 : 0xFFFFFF, 11);
            }
        }

        if (modal_ == Modal::ToolPage || modal_ == Modal::DeviceProbe || modal_ == Modal::UartConfig ||
            modal_ == Modal::UidChanger || modal_ == Modal::TagEraser) {
            render_tools_modal(detail);
        } else if (modal_ == Modal::ToolInfo) {
            render_tool_info_modal(parent);
        } else {
            create_text(detail, 6, 6, tool_name(tools_idx_), 0xFFFFFF, 12);
            switch (tools_idx_) {
            case 0:
                create_text(detail, 6, 24, "Manage saved key dict", 0xD8D8D8, 11);
                create_text(detail, 6, 37, "Add / edit / disable keys", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "OK to open manager", 0x8DB6FF, 11);
                break;
            case 1:
                create_text(detail, 6, 24, "Change writable card UID", 0xD8D8D8, 11);
                create_text(detail, 6, 37, "hf mf setuid style flow", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "OK to view workflow", 0x8DB6FF, 11);
                break;
            case 2:
                create_text(detail, 6, 24, "Format tag memory", 0xD8D8D8, 11);
                create_text(detail, 6, 37, "NDEF / blank templates", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "OK to view workflow", 0x8DB6FF, 11);
                break;
            case 3:
                create_text(detail, 6, 24, "Recover Mifare key", 0xD8D8D8, 11);
                create_text(detail, 6, 37, "Save to Mifare Keys", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "PN532Killer mfkey32v2", 0x8DB6FF, 11);
                break;
            case 4:
                create_text(detail, 6, 24, "Recover 64-bit nonce key", 0xD8D8D8, 11);
                create_text(detail, 6, 37, "Save to Mifare Keys", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "PN532Killer mfkey64", 0x8DB6FF, 11);
                break;
            default: break;
            }
        }

        create_footer(parent, ui_message_);
    }

    // ── Post-scan action menu (OK after a scan result) ───────────────────────
    void render_post_scan_modal(lv_obj_t *parent)
    {
        const auto &tag = service_.scan_state().last_record.tag;
        lv_obj_t *card = make_modal_card(parent, 180, 86, 0xF7A600);
        const std::string title = tag.uid.empty() ? "Tag Scanned" : to_compact(tag.uid, 20);
        create_text(card, 8, 6, title.c_str(), 0xFFFFFF, 12);
        const char *options[] = {"Read Again", "Save Tag", "Clear Log"};
        for (int i = 0; i < 3; ++i) {
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 164, 18);
            lv_obj_set_pos(row, 8, 24 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x2A2A2A), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 4, options[i], sel ? 0x000000 : 0xD0D0D0, 11);
        }
    }

    void handle_post_scan_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:   modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN:
        case KEY_X:   modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER: {
            const int action = modal_idx_;
            modal_     = Modal::None;
            modal_idx_ = 0;
            if (action == 0) {
                // Read Again: clear result and scan
                service_.connect_and_scan(&ui_message_);
            } else if (action == 1) {
                // Save Tag
                std::string error;
                if (service_.save_last_scan(&error)) {
                    refresh_saved_records();
                    show_toast("Saved");
                    ui_message_ = "Record saved to JSON";
                } else {
                    ui_message_ = error;
                }
            } else {
                // Clear Log
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                ui_message_ = "Log cleared";
            }
            break;
        }
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    // ── ReadMenu modal (Read-mode OK: Scan Card + Port Settings/Reconnect) ───
    void render_read_menu_modal(lv_obj_t *parent)
    {
        const auto ep = service_.current_endpoint();
        const bool is_usb = (ep.kind == nfc_app::TransportKind::UsbSerial);

        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *card = make_modal_card(overlay, 180, 82, 0x00D2FF);
        create_text(card, 8, 5, is_usb ? "USB Actions" : "UART Actions", 0x00D2FF, 12);
        const char *opt0 = "Scan Card";
        const char *opt1 = is_usb ? "Reconnect" : "Port Settings";
        const char *opt2 = "Clear Log";
        const char *options[] = {opt0, opt1, opt2};
        for (int i = 0; i < 3; ++i) {
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 164, 18);
            lv_obj_set_pos(row, 8, 22 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 3, options[i], sel ? 0x000000 : 0xD0D0D0, 11);
        }
        // 3-item modal: no keyboard hint needed
    }

    void handle_read_menu_key(uint32_t key)
    {
        const auto ep = service_.current_endpoint();
        const bool is_usb = (ep.kind == nfc_app::TransportKind::UsbSerial);
        switch (key) {
        case KEY_UP:
        case KEY_F:   modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN:
        case KEY_X:   modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER:
            if (modal_idx_ == 0) {
                // Scan Card
                modal_ = Modal::None;
                modal_idx_ = 0;
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                const auto conn = service_.connection_state();
                if (!conn.connected) {
                    scan_log_lines_.push_back("> Connect " + ep.label.substr(0, 22) + "...");
                    render_all();
                    const bool ok = service_.connect_current();
                    const auto conn2 = service_.connection_state();
                    if (!ok) {
                        scan_log_lines_.push_back("ERR " + conn2.detail.substr(0, 28));
                        ui_message_ = "Connect failed";
                        return;
                    }
                    scan_log_lines_.push_back("OK  " + conn2.detail.substr(0, 28));
                } else {
                    scan_log_lines_.push_back("OK  " + conn.detail.substr(0, 28));
                }
                scan_log_lines_.push_back("> Scan card...");
                service_.start_scan();
                ui_message_ = "Scanning...";
            } else if (modal_idx_ == 1) {
                if (is_usb) {
                    // USB: Reconnect
                    modal_ = Modal::None;
                    modal_idx_ = 0;
                    scan_log_lines_.clear();
                    log_scroll_offset_ = 0;
                    service_.disconnect();
                    scan_log_lines_.push_back("> Reconnect " + ep.label.substr(0, 20) + "...");
                    render_all();
                    const bool ok = service_.connect_current();
                    const auto conn2 = service_.connection_state();
                    if (!ok) {
                        scan_log_lines_.push_back("ERR " + conn2.detail.substr(0, 28));
                        ui_message_ = "Reconnect failed";
                    } else {
                        scan_log_lines_.push_back("OK  " + conn2.detail.substr(0, 28));
                        ui_message_ = std::string("Reconnected: ") + nfc_app::to_string(conn2.device_kind);
                    }
                } else {
                    // UART: Port Settings
                    uart_edit_buf_ = service_.uart_config();
                    port_settings_field_ = 0;
                    modal_ = Modal::PortSettings;
                    modal_idx_ = 0;
                }
            } else {
                // modal_idx_ == 2: Clear Log
                modal_ = Modal::None;
                modal_idx_ = 0;
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                ui_message_ = "Log cleared";
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    // ── UsbSelect modal (multiple USB ports: choose which to connect) ─────────
    void render_usb_select_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        const int n = static_cast<int>(usb_select_list_.size());
        const int card_h = 28 + std::max(1, n) * 20;
        lv_obj_t *card = make_modal_card(overlay, 200, card_h, 0x00D2FF);
        create_text(card, 8, 5, "Select USB Port", 0x00D2FF, 12);

        for (int i = 0; i < n; ++i) {
            const bool sel = (usb_select_idx_ == i);
            // Strip "USB " prefix from label for compactness
            std::string lbl = usb_select_list_[i].label;
            const std::string pfx = "USB ";
            if (lbl.size() > pfx.size() && lbl.compare(0, pfx.size(), pfx) == 0)
                lbl = lbl.substr(pfx.size());
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 184, 18);
            lv_obj_set_pos(row, 8, 22 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 3, lbl.c_str(), sel ? 0x000000 : 0xD0D0D0, 11);
        }
        if (n == 0) {
            create_text(card, 8, 26, "No USB device found", 0xFF4444, 11);
        }
    }

    void handle_usb_select_key(uint32_t key)
    {
        const int n = static_cast<int>(usb_select_list_.size());
        switch (key) {
        case KEY_UP:
        case KEY_F:
            if (n > 0) usb_select_idx_ = (usb_select_idx_ - 1 + n) % n;
            break;
        case KEY_DOWN:
        case KEY_X:
            if (n > 0) usb_select_idx_ = (usb_select_idx_ + 1) % n;
            break;
        case KEY_ENTER:
            if (n > 0 && usb_select_idx_ < n) {
                modal_ = Modal::None;
                modal_idx_ = 0;
                const auto &selected_ep = usb_select_list_[usb_select_idx_];
                service_.select_usb_endpoint_by_path(selected_ep.path);
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                scan_log_lines_.push_back("> Connect " + selected_ep.label.substr(0, 22) + "...");
                render_all();
                const bool ok = service_.connect_current();
                const auto conn2 = service_.connection_state();
                if (!ok) {
                    scan_log_lines_.push_back("ERR " + conn2.detail.substr(0, 28));
                    ui_message_ = "Connect failed";
                } else {
                    scan_log_lines_.push_back("OK  " + conn2.detail.substr(0, 28));
                    ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn2.device_kind);
                }
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    // ── PortSettings modal (TX / RX GPIO / BAUD) ─────────────────────────────
    void render_port_settings_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *card = make_modal_card(overlay, 240, 100, 0xF7A600);
        create_text(card, 8, 4, "Port Settings", 0xF7A600, 12);

        const char *field_labels[] = {"TX GPIO:", "RX GPIO:", "Baud:"};
        const int field_vals[] = { uart_edit_buf_.tx_pin, uart_edit_buf_.rx_pin, uart_edit_buf_.baud_rate };
        for (int i = 0; i < 3; ++i) {
            const bool sel = (port_settings_field_ == i);
            char vbuf[16];
            if (field_vals[i] < 0) std::snprintf(vbuf, sizeof(vbuf), "(unknown)");
            else std::snprintf(vbuf, sizeof(vbuf), "%d", field_vals[i]);
            std::string line = std::string(field_labels[i]) + " " + vbuf;
            if (sel && !edit_buf_.empty()) line = std::string(field_labels[i]) + " " + edit_buf_ + "_";
            uint32_t col = sel ? 0xFFFF00 : 0xD8D8D8;
            create_text(card, 8, 20 + i * 20, line.c_str(), col, 11);
        }
        create_text(card, 8, 85, "F/X field  type digits  Enter apply  ESC save", 0x666666, 10);
    }

    void handle_port_settings_key(uint32_t key)
    {
        const int FIELDS = 3;
        if (key == KEY_ESC) {
            // Apply any pending edit and save
            apply_port_settings_field();
            nfc_app::UartConfig cfg = service_.uart_config();
            cfg.tx_pin    = uart_edit_buf_.tx_pin;
            cfg.rx_pin    = uart_edit_buf_.rx_pin;
            cfg.baud_rate = uart_edit_buf_.baud_rate;
            service_.set_uart_config(cfg);
            ui_message_ = "Port settings saved";
            modal_ = Modal::ReadMenu;
            modal_idx_ = 0;
            edit_buf_.clear();
            return;
        }
        if (key == KEY_UP || key == KEY_F) {
            apply_port_settings_field();
            port_settings_field_ = (port_settings_field_ - 1 + FIELDS) % FIELDS;
            return;
        }
        if (key == KEY_DOWN || key == KEY_X) {
            apply_port_settings_field();
            port_settings_field_ = (port_settings_field_ + 1) % FIELDS;
            return;
        }
        if (key == KEY_ENTER) {
            apply_port_settings_field();
            return;
        }
        if (key == KEY_BACKSPACE) {
            if (!edit_buf_.empty()) edit_buf_.pop_back();
            return;
        }
        // Accept digits only
        char c = keycode_to_char(key);
        if (c >= '0' && c <= '9' && edit_buf_.size() < 7) edit_buf_ += c;
    }

    void apply_port_settings_field()
    {
        if (edit_buf_.empty()) return;
        try {
            int v = std::stoi(edit_buf_);
            if (port_settings_field_ == 0) uart_edit_buf_.tx_pin    = v;
            else if (port_settings_field_ == 1) uart_edit_buf_.rx_pin = v;
            else                                uart_edit_buf_.baud_rate = v;
        } catch (...) {}
        edit_buf_.clear();
    }

    // ── Tool info popup ('i' key) ────────────────────────────────────────────
    void render_tool_info_modal(lv_obj_t *parent)    {
        lv_obj_t *card = make_modal_card(parent, 300, 100, 0x00D2FF);
        create_text(card, 8, 5, tool_name(tools_idx_), 0x00D2FF, 12);

        struct ToolDesc {
            const char *lines[3];
        };
        static const ToolDesc descs[5] = {
            {{"Manage MIFARE key dictionary.",
              "Keys used by MFKey32/64 attacks",
              "and sector authentication."}},
            {{"Write UID to Gen1a magic card.",
              "Scan target → type UID → write.",
              "Requires Gen1a/Gen3 card."}},
            {{"Erase tag to blank/NDEF state.",
              "Select template, preview blocks,",
              "then confirm write."}},
            {{"MFKey32v2: nested-nonce attack.",
              "PN532Killer sniff two reads same",
              "sector w/o card → recover key."}},
            {{"MFKey64: hardnested attack.",
              "PN532Killer sniff read with card",
              "present → recover key."}},
        };
        const auto &d = descs[tools_idx_];
        for (int i = 0; i < 3; ++i) {
            create_text(card, 8, 24 + i * 18, d.lines[i], 0xD8D8D8, 11);
        }
        create_text(card, 8, 88, "ESC: close", 0x555555, 10);
    }

    // ── Global RFID App intro popup ('i' key, any tab) ───────────────────────
    void render_toast_overlay(lv_obj_t *parent)
    {
        // Semi-transparent centered popup, auto-dismissed after 1 s
        lv_obj_t *card = lv_obj_create(parent);
        lv_obj_remove_style_all(card);
        static constexpr int W = 120, H = 32;
        lv_obj_set_size(card, W, H);
        lv_obj_set_pos(card, (320 - W) / 2, (CONTENT_H - H) / 2);
        lv_obj_set_style_radius(card, 6, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(card, lv_color_hex(0x1A3A1A), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(card, 230, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(card, lv_color_hex(0x00CC44), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(card, 1, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *lbl = lv_label_create(card);
        lv_label_set_text(lbl, toast_msg_.c_str());
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x00EE55), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_text_font(lbl, &lv_font_unscii_8, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_center(lbl);
    }

    // ── HexLog modal ─────────────────────────────────────────────────────────

    void handle_hex_log_key(uint32_t key)
    {
        const int total   = nfc_app::NfcHexLog::get().total_lines();
        const int max_off = std::max(0, total - LOG_VISIBLE_HEX_LINES);
        if (key == KEY_ESC) {
            modal_ = Modal::None;
        } else if (key == KEY_UP) {
            hex_log_scroll_ = std::max(0, hex_log_scroll_ - 1);
        } else if (key == KEY_DOWN) {
            hex_log_scroll_ = std::min(max_off, hex_log_scroll_ + 1);
        } else if (key == KEY_DELETE || key == 127 /* LV_KEY_DEL */) {
            // Clear in-memory log lines
            nfc_app::NfcHexLog::get().clear();
            hex_log_scroll_ = 0;
        }
    }

    void render_hex_log_overlay(lv_obj_t *parent)
    {
        // Full-width dark panel covering entire content area
        lv_obj_t *panel = lv_obj_create(parent);
        lv_obj_set_size(panel, 320, 150);
        lv_obj_set_pos(panel, 0, 0);
        lv_obj_set_style_radius(panel, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_color(panel, lv_color_hex(0x050505), LV_PART_MAIN);
        lv_obj_set_style_bg_opa(panel, 245, LV_PART_MAIN);
        lv_obj_set_style_border_width(panel, 0, LV_PART_MAIN);
        lv_obj_set_style_pad_all(panel, 0, LV_PART_MAIN);

        // Title bar
        lv_obj_t *title_bar = lv_obj_create(panel);
        lv_obj_set_size(title_bar, 320, 14);
        lv_obj_set_pos(title_bar, 0, 0);
        lv_obj_set_style_radius(title_bar, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_color(title_bar, lv_color_hex(0x1A1A2E), LV_PART_MAIN);
        lv_obj_set_style_bg_opa(title_bar, 255, LV_PART_MAIN);
        lv_obj_set_style_border_width(title_bar, 0, LV_PART_MAIN);
        lv_obj_set_style_pad_all(title_bar, 0, LV_PART_MAIN);

        const int total = nfc_app::NfcHexLog::get().total_lines();
        char header[64];
        std::snprintf(header, sizeof(header), "HEX LOG  %d lines  [%d-%d]",
                      total,
                      hex_log_scroll_ + 1,
                      std::min(total, hex_log_scroll_ + LOG_VISIBLE_HEX_LINES));
        create_text(title_bar, 4, 2, header, 0x00FFCC, 10);

        // Log lines area
        const auto lines = nfc_app::NfcHexLog::get().get_lines(hex_log_scroll_, LOG_VISIBLE_HEX_LINES);
        const int line_h = 11;
        const int start_y = 15;
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const std::string &ln = lines[static_cast<size_t>(i)];
            // Colour: TX lines (=>) green, RX lines (<=) yellow, events white
            uint32_t col = 0xCCCCCC;
            if (ln.find("=>") != std::string::npos) col = 0x44FF88;
            else if (ln.find("<=") != std::string::npos) col = 0xFFDD44;
            // Truncate to ~52 chars (monospace) so it fits at font size 10
            std::string display = ln.size() > 52 ? ln.substr(0, 52) : ln;
            create_text(panel, 2, start_y + i * line_h, display.c_str(), col, 10);
        }
        if (lines.empty()) {
            create_text(panel, 2, start_y, "(no log entries yet)", 0x555555, 10);
        }

        // Footer hint
        lv_obj_t *footer = lv_obj_create(panel);
        lv_obj_set_size(footer, 320, 13);
        lv_obj_set_pos(footer, 0, 137);
        lv_obj_set_style_radius(footer, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_color(footer, lv_color_hex(0x1A1A2E), LV_PART_MAIN);
        lv_obj_set_style_bg_opa(footer, 255, LV_PART_MAIN);
        lv_obj_set_style_border_width(footer, 0, LV_PART_MAIN);
        lv_obj_set_style_pad_all(footer, 0, LV_PART_MAIN);
        create_text(footer, 4, 2, "U/D:scroll  Del:clear  ESC:close", 0x888888, 10);
    }

    // ── AppInfo modal ─────────────────────────────────────────────────────────

    void render_app_info_modal(lv_obj_t *parent)
    {
        const auto conn = service_.connection_state();
        const auto ep   = service_.current_endpoint();

        lv_obj_t *card = make_modal_card(parent, 308, 110, 0x00D2FF);
        create_text(card, 8, 4, "Device Info", 0x00D2FF, 12);

        char buf[64];

        // Row 0: device kind
        std::snprintf(buf, sizeof(buf), "Device:  %s", nfc_app::to_string(conn.device_kind));
        create_text(card, 8, 22, buf, 0xFFD700, 11);

        // Row 1: firmware / detail (strip " @ /dev/..." path if appended)
        std::string fw_display = conn.detail;
        {
            auto at = fw_display.find(" @ ");
            if (at != std::string::npos) fw_display = fw_display.substr(0, at);
        }
        const std::string fw_str = fw_display.empty() ? "(none)" : fw_display.substr(0, 46);
        std::snprintf(buf, sizeof(buf), "FW:      %s", fw_str.c_str());
        create_text(card, 8, 35, buf, 0xD8D8D8, 11);

        // Row 2: connection path
        const std::string path_str = ep.path.empty() ? "(none)" : ep.path.substr(0, 46);
        std::snprintf(buf, sizeof(buf), "Port:    %s", path_str.c_str());
        create_text(card, 8, 48, buf, 0xD8D8D8, 11);

        // Row 3: status
        const char *status_str = conn.connected ? "Connected" : "Disconnected";
        std::snprintf(buf, sizeof(buf), "Status:  %s", status_str);
        create_text(card, 8, 61, buf, conn.connected ? 0x44FF88 : 0xFF5555, 11);

        // Row 4: PN532 ready flag (useful for debug)
        std::snprintf(buf, sizeof(buf), "NFC Rdy: %s", conn.pn532_ready ? "yes" : "no");
        create_text(card, 8, 74, buf, conn.pn532_ready ? 0x44FF88 : 0x888888, 11);
    }

    // ── Tools-specific modal overlay ─────────────────────────────────────────
    void render_tools_modal(lv_obj_t *parent)
    {
        if (modal_ == Modal::ToolPage) {
            if (active_tool_idx_ == 0) {
                render_mifare_keys_tool(parent);
                return;
            }
            if (active_tool_idx_ == 3 || active_tool_idx_ == 4) {
                render_mfkey_wizard(parent);
                return;
            }
            create_text(parent, 6, 4, tool_name(active_tool_idx_), 0xFFFFFF, 12);
            switch (active_tool_idx_) {
            case 0:
                break;
            case 1:
                create_text(parent, 6, 24, "1. Scan target card", 0xD8D8D8, 11);
                create_text(parent, 6, 38, "2. Type new UID", 0xD8D8D8, 11);
                create_text(parent, 6, 52, "3. Write to magic card", 0x8DB6FF, 11);
                break;
            case 2:
                create_text(parent, 6, 24, "Choose blank / NDEF", 0xD8D8D8, 11);
                create_text(parent, 6, 38, "Preview memory blocks", 0xD8D8D8, 11);
                create_text(parent, 6, 52, "Confirm before write", 0x8DB6FF, 11);
                break;
            default: break;
            }
            create_text(parent, 6, 92, "ESC back to tool list", 0x7A7A7A, 10);
        } else if (modal_ == Modal::DeviceProbe) {
            render_device_probe_modal(parent);
        } else if (modal_ == Modal::UartConfig) {
            render_uart_config_modal(parent);
        } else if (modal_ == Modal::UidChanger) {
            lv_obj_t *card = parent;
            create_text(card, 6, 4, "UID Changer", 0xFFFFFF, 12);
            create_text(card, 6, 24, "Tool scaffold is ready.", 0xD8D8D8, 11);
            create_text(card, 6, 39, "Use this page for UID write", 0xD8D8D8, 11);
            create_text(card, 6, 94, "ESC: back to tools", 0x7A7A7A, 10);
        } else if (modal_ == Modal::TagEraser) {
            lv_obj_t *card = parent;
            create_text(card, 6, 4, "Tag Eraser", 0xFFFFFF, 12);
            create_text(card, 6, 24, "Tool scaffold is ready.", 0xD8D8D8, 11);
            create_text(card, 6, 39, "Use this page for wipe flow", 0xD8D8D8, 11);
            create_text(card, 6, 94, "ESC: back to tools", 0x7A7A7A, 10);
        }
    }

    // ── MFKey step-by-step wizard renderer ───────────────────────────────────
    // Full-width (320px parent). Shared by mfkey32v2 (idx=3) and mfkey64 (idx=4).
    void render_mfkey_wizard(lv_obj_t *parent)
    {
        const bool with_card = (active_tool_idx_ == 4);
        const char *title    = with_card ? "MFkey64" : "MFKey32v2";

        // Title bar with step indicator
        create_text(parent, 8, 4, title, 0xFFFFFF, 12);
        {
            char sbuf[16];
            if (mfkey_step_ < 3)
                std::snprintf(sbuf, sizeof(sbuf), "Step %d/3", mfkey_step_ + 1);
            else
                std::strncpy(sbuf, "Results", sizeof(sbuf));
            create_text(parent, 260, 4, sbuf, 0x6A6A6A, 10);
        }

        // ── mfkey32v2 ────────────────────────────────────────────────────────
        if (!with_card) {
            switch (mfkey_step_) {
            case 0: {
                // Step 1: UID input (optional — Enter with empty = skip UID, use device default)
                create_text(parent, 8, 22, "Step 1/3  Set sniffer UID (optional)", 0xF7A600, 11);
                create_text(parent, 8, 38, "Target card UID (8 hex chars):", 0xD8D8D8, 11);
                const std::string disp = mfkey_uid_input_.empty() ? "_" : mfkey_uid_input_ + "_";
                create_text(parent, 8, 54, disp.c_str(), 0x00FFAA, 12);
                create_text(parent, 8, 74, "Leave empty to use device default UID", 0x888888, 10);
                create_text(parent, 8, 90, "Type UID  Bsp:del  Enter:confirm  ESC:back", 0x7A7A7A, 10);
                break;
            }
            case 1: {
                // Step 2: Device now in sniffer mode
                create_text(parent, 8, 22, "Step 2/3  Sniffer active", 0xF7A600, 11);
                if (mfkey_uid_input_.empty()) {
                    create_text(parent, 8, 38, "No UID set. Device uses its own UID.", 0xD8D8D8, 11);
                } else {
                    const std::string uid_msg = "UID: " + mfkey_uid_input_;
                    create_text(parent, 8, 38, uid_msg.c_str(), 0xD8D8D8, 11);
                }
                create_text(parent, 8, 54, "Approach reader, capture auth sessions.", 0xD8D8D8, 11);
                create_text(parent, 8, 70, "Press Enter when done sniffing.", 0x8DB6FF, 11);
                create_text(parent, 8, 90, "Enter:stop+crack  ESC:abort", 0x7A7A7A, 10);
                break;
            }
            case 2: {
                // Step 3: Cracking
                const int pct = service_.hw_mfkey_progress();
                char buf[48];
                std::snprintf(buf, sizeof(buf), "Cracking... %d%%", pct);
                create_text(parent, 8, 22, "Step 3/3  Calculating keys", 0xF7A600, 11);
                create_text(parent, 8, 38, buf, 0xF7A600, 12);
                create_text(parent, 8, 56, "Running mfkey32v2 on nonce pairs...", 0xD8D8D8, 11);
                break;
            }
            default: // step 3 = results
                render_mfkey_results(parent);
                break;
            }
        } else {
        // ── mfkey64 ──────────────────────────────────────────────────────────
            switch (mfkey_step_) {
            case 0: {
                // Step 1: Ready to enter sniffer mode
                create_text(parent, 8, 22, "Step 1/3  Enter sniffer mode", 0xF7A600, 11);
                create_text(parent, 8, 38, "Place real card on device, then", 0xD8D8D8, 11);
                create_text(parent, 8, 54, "let reader authenticate the card.", 0xD8D8D8, 11);
                create_text(parent, 8, 70, "Press Enter to start card-present sniffing.", 0x8DB6FF, 11);
                create_text(parent, 8, 90, "Enter:enter sniff  ESC:back", 0x7A7A7A, 10);
                break;
            }
            case 1: {
                // Step 2: Device in card-present sniffer mode
                create_text(parent, 8, 22, "Step 2/3  Sniffer active (card)", 0xF7A600, 11);
                create_text(parent, 8, 38, "Device is in card-present sniffer mode.", 0xD8D8D8, 11);
                create_text(parent, 8, 54, "Hold card near reader, let it auth.", 0xD8D8D8, 11);
                create_text(parent, 8, 70, "Press Enter when auth captured.", 0x8DB6FF, 11);
                create_text(parent, 8, 90, "Enter:stop+crack  ESC:back", 0x7A7A7A, 10);
                break;
            }
            case 2: {
                // Step 3: Cracking
                const int pct = service_.hw_mfkey_progress();
                char buf[48];
                std::snprintf(buf, sizeof(buf), "Cracking... %d%%", pct);
                create_text(parent, 8, 22, "Step 3/3  Calculating keys", 0xF7A600, 11);
                create_text(parent, 8, 38, buf, 0xF7A600, 12);
                create_text(parent, 8, 56, "Running mfkey64 on captured auth...", 0xD8D8D8, 11);
                break;
            }
            default: // step 3 = results
                render_mfkey_results(parent);
                break;
            }
        }
    }

    void render_mfkey_results(lv_obj_t *parent)
    {
        if (mfkey_results_.empty()) {
            create_text(parent, 8, 22, "No keys found", 0xFF6666, 12);
            create_text(parent, 8, 42, "Not enough nonce pairs captured.", 0xD8D8D8, 11);
            create_text(parent, 8, 56, "Try again: approach reader more times.", 0xD8D8D8, 11);
            create_text(parent, 8, 90, "R:retry  ESC:back", 0x7A7A7A, 10);
            return;
        }
        // Result list (up to 4 visible rows of 20px each)
        constexpr int visible = 4;
        const int total = static_cast<int>(mfkey_results_.size());
        int offset = mfkey_result_idx_ - 1;
        if (offset < 0) offset = 0;
        if (offset > total - visible) offset = total - visible;
        if (offset < 0) offset = 0;
        for (int r = 0; r < visible; ++r) {
            const int idx = offset + r;
            if (idx >= total) break;
            const bool sel = (idx == mfkey_result_idx_);
            const auto &res = mfkey_results_[static_cast<size_t>(idx)];
            lv_obj_t *row = lv_obj_create(parent);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 306, 18);
            lv_obj_set_pos(row, 6, 18 + r * 19);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x1E1E1E), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            char col[32], val[24];
            std::snprintf(col, sizeof(col), "Sec%02u Key%c", res.sector, res.key_type == 0 ? 'A' : 'B');
            const std::string kd = res.key_hex.empty() ? "(not found)" : res.key_hex;
            std::snprintf(val, sizeof(val), "%s", kd.c_str());
            create_text(row, 4, 1, col, sel ? 0x000000 : 0xFFFFFF, 10);
            create_text(row, 80, 1, val, sel ? 0x2F2F2F : 0x8DB6FF, 10);
        }
        create_text(parent, 8, 90, "U/D select  Enter:save  R:retry  ESC:back", 0x7A7A7A, 10);
    }

    void render_mifare_keys_tool(lv_obj_t *parent)
    {
        // Tab line: [Built-in] [Files]
        {
            const char *tabs[2] = {"Built-in", "Files"};
            for (int t = 0; t < 2; ++t) {
                const bool sel = (mifare_keys_file_mode_ == (t == 1));
                create_text(parent, 6 + t * 86, 4, tabs[t], sel ? 0xF7A600 : 0x6A6A6A, 11);
            }
        }
        create_text(parent, 168, 4, "Tab:switch", 0x4A4A4A, 10);

        if (mifare_key_editing_) {
            const uint32_t col_label = (mifare_key_field_idx_ == 0) ? 0xFFFF00 : 0xD8D8D8;
            const uint32_t col_key = (mifare_key_field_idx_ == 1) ? 0xFFFF00 : 0xD8D8D8;
            const uint32_t col_type = (mifare_key_field_idx_ == 2) ? 0xFFFF00 : 0x8DB6FF;
            create_text(parent, 6, 22, (std::string("Label: ") + to_compact(mifare_key_edit_.label.empty() ? "(unnamed)" : mifare_key_edit_.label, 18)).c_str(), col_label, 11);
            create_text(parent, 6, 38, (std::string("Key: ") + (mifare_key_edit_.key_hex.empty() ? "_" : mifare_key_edit_.key_hex + "_")).c_str(), col_key, 11);
            create_text(parent, 6, 54, (std::string("Type: Key ") + nfc_app::to_string(mifare_key_edit_.type)).c_str(), col_type, 11);
            create_text(parent, 6, 70, mifare_key_creating_ ? "New key entry" : "Edit selected key", 0x7A7A7A, 10);
            create_text(parent, 6, 92, "U/D field  Tab type  Enter save  ESC back", 0x7A7A7A, 10);
            return;
        }

        if (mifare_keys_file_mode_) {
            // File browser sub-mode
            if (key_file_keys_.empty()) {
                // Show file list
                const int n = static_cast<int>(key_files_.size());
                if (n == 0) {
                    create_text(parent, 6, 24, "No .dic/.txt files found", 0xFF6666, 11);
                    create_text(parent, 6, 38, "/home/pi/rfid/keys/", 0x7A7A7A, 10);
                } else {
                    constexpr int visible = 4;
                    int offset = key_file_idx_ - 1;
                    if (offset < 0) offset = 0;
                    if (offset > n - visible) offset = n - visible;
                    if (offset < 0) offset = 0;
                    for (int r = 0; r < visible; ++r) {
                        const int idx = offset + r;
                        if (idx >= n) break;
                        const bool sel = (idx == key_file_idx_);
                        lv_obj_t *row = lv_obj_create(parent);
                        lv_obj_remove_style_all(row);
                        lv_obj_set_size(row, 164, 18);
                        lv_obj_set_pos(row, 6, 20 + r * 18);
                        lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
                        create_text(row, 4, 4, to_compact(key_files_[static_cast<size_t>(idx)], 20).c_str(), sel ? 0x000000 : 0xD0D0D0, 10);
                    }
                }
                create_text(parent, 6, 92, "U/D select  Enter:load file  ESC back", 0x7A7A7A, 10);
            } else {
                // Show keys from loaded file
                const int total = static_cast<int>(key_file_keys_.size());
                constexpr int visible = 4;
                int offset = key_file_key_idx_ - 1;
                if (offset < 0) offset = 0;
                if (offset > total - visible) offset = total - visible;
                if (offset < 0) offset = 0;
                // Show file name as subtitle
                const std::string fname = key_file_idx_ < static_cast<int>(key_files_.size())
                    ? to_compact(key_files_[static_cast<size_t>(key_file_idx_)], 20) : "";
                create_text(parent, 6, 16, fname.c_str(), 0x00D2FF, 10);
                for (int r = 0; r < visible; ++r) {
                    const int idx = offset + r;
                    if (idx >= total) break;
                    const bool sel = (idx == key_file_key_idx_);
                    lv_obj_t *row = lv_obj_create(parent);
                    lv_obj_remove_style_all(row);
                    lv_obj_set_size(row, 164, 16);
                    lv_obj_set_pos(row, 6, 26 + r * 16);
                    lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
                    lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
                    create_text(row, 4, 3, key_file_keys_[static_cast<size_t>(idx)].c_str(), sel ? 0x000000 : 0x8DB6FF, 10);
                }
                char countbuf[32];
                std::snprintf(countbuf, sizeof(countbuf), "%d keys", total);
                create_text(parent, 6, 92, countbuf, 0x7A7A7A, 10);
                create_text(parent, 50, 92, "  Enter:add to Built-in  Bsp:back", 0x7A7A7A, 10);
            }
            return;
        }

        // Built-in key list (original behaviour)
        const int total_rows = static_cast<int>(mifare_keys_.size()) + 1;
        constexpr int visible = 4;
        int offset = mifare_key_idx_ - 1;
        if (offset < 0) offset = 0;
        if (offset > total_rows - visible) offset = total_rows - visible;
        if (offset < 0) offset = 0;

        for (int row = 0; row < visible; ++row) {
            const int index = offset + row;
            if (index >= total_rows) break;
            const bool selected = (index == mifare_key_idx_);
            lv_obj_t *entry = lv_obj_create(parent);
            lv_obj_remove_style_all(entry);
            lv_obj_set_size(entry, 164, 18);
            lv_obj_set_pos(entry, 6, 20 + row * 18);
            lv_obj_set_style_bg_color(entry, lv_color_hex(selected ? 0xF7A600 : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(entry, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(entry, LV_OBJ_FLAG_SCROLLABLE);

            if (index == static_cast<int>(mifare_keys_.size())) {
                create_text(entry, 4, 4, "+ Add Key", selected ? 0x000000 : 0x8DB6FF, 10);
            } else {
                const auto &key = mifare_keys_[index];
                const std::string head = (key.enabled ? "[on] " : "[off] ") + key.label;
                const std::string tail = std::string("K") + nfc_app::to_string(key.type) + " " + key.key_hex;
                create_text(entry, 4, 1, to_compact(head, 18).c_str(), selected ? 0x000000 : 0xFFFFFF, 10);
                create_text(entry, 4, 9, to_compact(tail, 18).c_str(), selected ? 0x2F2F2F : 0x8DB6FF, 10);
            }
        }
        create_text(parent, 6, 92, "U/D select  Enter edit  T on/off  Bsp del  Tab files  ESC back", 0x7A7A7A, 10);
    }

    void render_device_probe_modal(lv_obj_t *parent)
    {
        lv_obj_t *card = parent;
        create_text(card, 6, 4, "Device Probe", 0xFFFFFF, 12);

        const auto results = service_.probe_results();
        const bool running = service_.probe_running();

        if (results.empty()) {
            const char *msg = running ? "Scanning..." : "No USB/UART ports found";
            create_text(card, 6, 22, msg, 0xD8D8D8, 11);
        } else {
            int y = 20;
            for (size_t i = 0; i < results.size() && y < 88; ++i, y += 20) {
                const auto &r = results[i];
                // Port path (short)
                std::string path = r.path;
                const auto slash = path.rfind('/');
                if (slash != std::string::npos) path = path.substr(slash + 1);
                char line1[48];
                if (r.probing) {
                    std::snprintf(line1, sizeof(line1), "%-16s ...", path.c_str());
                } else {
                    std::snprintf(line1, sizeof(line1), "%-16s %s", path.c_str(),
                                  nfc_app::to_string(r.device_kind));
                }
                create_text(card, 6, y, line1, 0xD8D8D8, 11);
                if (!r.firmware.empty()) {
                    create_text(card, 10, y + 10, to_compact(r.firmware, 24).c_str(), 0x8DB6FF, 10);
                    y += 4;  // extra padding for firmware line
                }
            }
            if (running) create_text(card, 6, 88, "Scanning...", 0x8DB6FF, 11);
        }

        if (!running) create_text(card, 6, 92, "OK re-probe  ESC back", 0x7A7A7A, 10);
    }

    void render_uart_config_modal(lv_obj_t *parent)
    {
        lv_obj_t *card = parent;
        create_text(card, 6, 4, "UART Config", 0xFFFFFF, 12);

        // Device path row
        {
            char buf[48];
            const std::string &dev = uart_edit_buf_.device_path;
            std::snprintf(buf, sizeof(buf), "Dev: %s", dev.empty() ? "(none)" : to_compact(dev, 20).c_str());
            uint32_t col = (uart_field_idx_ == 0) ? 0xFFFF00 : 0xD8D8D8;
            create_text(card, 6, 22, buf, col, 11);
        }
        // Baud rate
        {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "Baud: %d", uart_edit_buf_.baud_rate);
            uint32_t col = (uart_field_idx_ == 1) ? 0xFFFF00 : 0xD8D8D8;
            create_text(card, 6, 38, buf, col, 11);
        }
        // Pins (informational)
        {
            char buf[40];
            const auto pins = nfc_app::NfcDeviceService::uart_pin_hint(uart_edit_buf_.device_path);
            if (pins.first >= 0) {
                std::snprintf(buf, sizeof(buf), "TX: GPIO%d  RX: GPIO%d", pins.first, pins.second);
            } else {
                std::snprintf(buf, sizeof(buf), "TX/RX: unknown");
            }
            create_text(card, 6, 54, buf, 0x8DB6FF, 11);
        }
        // Current input when editing device path
        if (uart_field_idx_ == 0 && !edit_buf_.empty()) {
            std::string disp = "> " + edit_buf_;
            create_text(card, 6, 68, disp.c_str(), 0xFFFF88, 11);
        }
        // UART endpoint list hint
        const auto uart_eps = service_.uart_endpoints();
        if (!uart_eps.empty()) {
            int y = 80;
            create_text(card, 6, y, "Detected:", 0x7A7A7A, 10);
            for (size_t i = 0; i < uart_eps.size() && y < 96; ++i) {
                const auto &ep = uart_eps[i];
                std::string p = ep.path;
                const auto s = p.rfind('/'); if (s != std::string::npos) p = p.substr(s+1);
                char line[32]; std::snprintf(line, sizeof(line), "  %s", p.c_str());
                create_text(card, 6, y + 8*(int(i)+1), line, 0x7A7A7A, 10);
                y += 2;
            }
        }
        create_text(card, 6, 92, "U/D field Enter edit ESC save", 0x7A7A7A, 10);
    }

    lv_obj_t *make_modal_card(lv_obj_t *parent)
    {
        // Full-content-area overlay card
        lv_obj_t *card = lv_obj_create(parent);
        lv_obj_set_size(card, 320, 104);
        lv_obj_set_pos(card, 0, 0);
        lv_obj_set_style_bg_color(card, lv_color_hex(0x1A1A2E), 0);
        lv_obj_set_style_bg_opa(card, 245, 0);
        lv_obj_set_style_border_color(card, lv_color_hex(0x3A6FD8), 0);
        lv_obj_set_style_border_width(card, 1, 0);
        lv_obj_set_style_radius(card, 4, 0);
        lv_obj_set_style_pad_all(card, 0, 0);
        lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
        return card;
    }

    void handle_device_probe_key(uint32_t key)
    {
        if (key == KEY_ENTER) {
            service_.start_probe_all();
            ui_message_ = "Probing...";
        } else if (key == KEY_ESC) {
            modal_ = Modal::None;
            ui_message_.clear();
        }
    }

    void handle_uart_config_key(uint32_t key)
    {
        const int FIELDS = 2;  // device path, baud rate (pins are read-only)
        if (key == KEY_ESC) {
            // Save current values
            if (!uart_edit_buf_.device_path.empty()) {
                auto pins = nfc_app::NfcDeviceService::uart_pin_hint(uart_edit_buf_.device_path);
                uart_edit_buf_.tx_pin = pins.first;
                uart_edit_buf_.rx_pin = pins.second;
            }
            service_.set_uart_config(uart_edit_buf_);
            ui_message_ = "UART saved";
            modal_ = Modal::None;
            edit_buf_.clear();
            return;
        }
        if (key == KEY_UP)   { uart_field_idx_ = (uart_field_idx_ - 1 + FIELDS) % FIELDS; return; }
        if (key == KEY_DOWN) { uart_field_idx_ = (uart_field_idx_ + 1) % FIELDS; return; }
        if (key == KEY_ENTER) {
            // Commit typed edit_buf to the current field
            if (uart_field_idx_ == 0 && !edit_buf_.empty()) {
                uart_edit_buf_.device_path = edit_buf_;
                edit_buf_.clear();
            } else if (uart_field_idx_ == 1 && !edit_buf_.empty()) {
                try { uart_edit_buf_.baud_rate = std::stoi(edit_buf_); } catch (...) {}
                edit_buf_.clear();
            }
            return;
        }
        if (key == KEY_BACKSPACE) {
            if (!edit_buf_.empty()) edit_buf_.pop_back();
            return;
        }
        // Typed character — device path accepts printable, baud accepts digits
        if (uart_field_idx_ == 0) {
            char c = keycode_to_char(key);
            if (c >= 32 && c < 127) edit_buf_ += c;
        } else if (uart_field_idx_ == 1) {
            char c = keycode_to_char(key);
            if (c >= '0' && c <= '9') edit_buf_ += c;
        }
    }

    lv_obj_t *create_panel(lv_obj_t *parent, int x, int y, int w, int h, uint32_t color)
    {
        lv_obj_t *panel = lv_obj_create(parent);
        lv_obj_set_size(panel, w, h);
        lv_obj_set_pos(panel, x, y);
        lv_obj_set_style_radius(panel, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(panel, lv_color_hex(color), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(panel, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(panel, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(panel, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
        return panel;
    }

    lv_obj_t *create_text(lv_obj_t *parent, int x, int y, const char *text, uint32_t color, int font_size)
    {
        lv_obj_t *label = lv_label_create(parent);
        // Strip default theme padding so position is exact pixel from parent origin
        lv_obj_set_style_pad_all(label, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_label_set_text(label, text);
        lv_obj_set_pos(label, x, y);
        lv_obj_set_style_text_color(label, lv_color_hex(color), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_text_font(label,
            font_size >= 12 ? &lv_font_montserrat_12 :
            font_size >= 10 ? &lv_font_montserrat_10 :
            font_size >= 8  ? &lv_font_montserrat_8 :
                              &lv_font_unscii_8,
            LV_PART_MAIN | LV_STATE_DEFAULT);
        return label;
    }

    void create_action_row(lv_obj_t *parent, int y, const char *label, bool selected)
    {
        lv_obj_t *row = lv_obj_create(parent);
        lv_obj_set_size(row, lv_obj_get_width(parent) - 8, 18);
        lv_obj_set_pos(row, 4, y);
        lv_obj_set_style_radius(row, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(row, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(row, lv_color_hex(selected ? 0xF7A600 : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
        create_text(row, 4, 3, label, selected ? 0x000000 : 0xFFFFFF, 11);
    }

    void create_footer(lv_obj_t *parent, const std::string &text)
    {
        lv_obj_t *footer = create_panel(parent, 0, 106, 320, 14, 0x0A0A0A);
        create_text(footer, 4, 1, to_compact(text, 52).c_str(), 0x7FA5C9, 10);
    }

    // ── Key code helpers (evdev scan codes → printable char) ────────────────

    // General text input (letters + digits + basic symbols, lowercase)
    static char keycode_to_char(uint32_t key)
    {
        if (key >= KEY_1 && key <= KEY_9) return '0' + (int)(key - KEY_1) + 1;
        if (key == KEY_0) return '0';
        static const char qwerty[] = "qwertyuiop";
        if (key >= KEY_Q && key <= KEY_P) return qwerty[key - KEY_Q];
        static const char asdf[] = "asdfghjkl";
        if (key >= KEY_A && key <= KEY_L) return asdf[key - KEY_A];
        static const char zxcv[] = "zxcvbnm";
        if (key >= KEY_Z && key <= KEY_M) return zxcv[key - KEY_Z];
        if (key == KEY_SPACE) return ' ';
        if (key == 52) return '.';   // KEY_DOT
        if (key == 12) return '-';   // KEY_MINUS
        if (key == 51) return ',';   // KEY_COMMA
        if (key == 26) return '[';   // KEY_LEFTBRACE
        if (key == 27) return ']';   // KEY_RIGHTBRACE
        if (key == 39) return ';';   // KEY_SEMICOLON
        if (key == 40) return '\'';  // KEY_APOSTROPHE
        if (key == 53) return '/';   // KEY_SLASH
        return 0;
    }

    // Hex-specific input: 0-9, A-F (uppercase), space, colon
    static char keycode_to_hex_char(uint32_t key)
    {
        if (key >= KEY_1 && key <= KEY_9) return '0' + (int)(key - KEY_1) + 1;
        if (key == KEY_0) return '0';
        // A-F uppercase only
        if (key == KEY_A) return 'A';
        if (key == KEY_B) return 'B';
        if (key == KEY_C) return 'C';
        if (key == KEY_D) return 'D';
        if (key == KEY_E) return 'E';
        if (key == KEY_F) return 'F';
        if (key == KEY_SPACE) return ' ';
        if (key == 39) return ':';   // KEY_SEMICOLON → colon
        return 0;
    }

    // ── String helpers ───────────────────────────────────────────────────────

    static std::string to_compact(const std::string &text, size_t max_len)
    {
        if (text.size() <= max_len) return text;
        if (max_len < 4) return text.substr(0, max_len);
        return text.substr(0, max_len - 3) + "...";
    }

    static const char *tool_name(int index)
    {
        static const char *TOOLS[5] = {"Mifare Keys", "UID Changer", "Tag Formater", "MFKey32v2", "MFkey64"};
        if (index < 0 || index >= 5) return TOOLS[0];
        return TOOLS[index];
    }

    // ── Modal rendering ─────────────────────────────────────────────────────

    void render_saved_modal(lv_obj_t *parent)
    {
        // Full-area semi-transparent overlay
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 170, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        switch (modal_) {
        case Modal::Action:     render_action_modal_card(overlay);     break;
        case Modal::SlotSelect: render_slot_select_modal_card(overlay); break;
        case Modal::EditName:   render_edit_name_modal_card(overlay);  break;
        case Modal::EditHex:    render_edit_hex_modal_card(overlay);   break;
        case Modal::HexExitConfirm: render_hex_exit_confirm_card(overlay); break;
        default: break;
        }
    }

    lv_obj_t *make_modal_card(lv_obj_t *parent, int w, int h, uint32_t border_color)
    {
        const int OVERLAY_H = CONTENT_H;
        const int mx = (320 - w) / 2;
        const int my = (OVERLAY_H - h) / 2;
        lv_obj_t *card = create_panel(parent, mx, my, w, h, 0x1A1A1A);
        lv_obj_set_style_border_color(card, lv_color_hex(border_color), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(card, 1, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_radius(card, 2, LV_PART_MAIN | LV_STATE_DEFAULT);
        return card;
    }

    void render_action_modal_card(lv_obj_t *parent)
    {
        // Width 220, Height 117 → 4 options + title + hint with padding
        lv_obj_t *card = make_modal_card(parent, 220, 117, 0xF7A600);
        const auto &rec = saved_records_[saved_idx_];
        create_text(card, 8, 6, to_compact(rec.meta.display_name, 26).c_str(), 0xFFFFFF, 12);

        const char *options[] = {"Upload to Slot...", "Edit Name", "Edit Hex Data", "Delete"};
        for (int i = 0; i < 4; ++i) {
            const bool sel = (modal_idx_ == i);
            const bool is_delete = (i == 3);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);  // must be before set_size (size is a style in LVGL9)
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 24 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? (is_delete ? 0xFF4444 : 0xF7A600) : (is_delete ? 0x3A1A1A : 0x2A2A2A)), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 4, options[i], sel ? 0x000000 : (is_delete ? 0xFF8888 : 0xD0D0D0), 11);
        }
        create_text(card, 8, 102, "U/D sel  Enter confirm  ESC cancel", 0x666666, 10);
    }

    void render_slot_select_modal_card(lv_obj_t *parent)
    {
        // Width 250, Height 114 → 5 visible slots + header + hint with bottom padding
        lv_obj_t *card = make_modal_card(parent, 250, 114, 0xF7A600);
        const auto protocol = saved_records_[saved_idx_].tag.protocol;
        create_text(card, 8, 5, (std::string(nfc_app::to_string(protocol)) + " Slot (0-7)").c_str(), 0xFFFFFF, 12);

        const auto slots = service_.emulator_slots_padded(protocol);
        constexpr int VISIBLE = 5;
        int offset = slot_select_idx_ - VISIBLE / 2;
        if (offset < 0) offset = 0;
        if (offset > 8 - VISIBLE) offset = 8 - VISIBLE;

        for (int i = 0; i < VISIBLE; ++i) {
            const int si = offset + i;
            if (si >= 8) break;
            const bool sel = (si == slot_select_idx_);
            const auto &slot = slots[si];
            std::string label = "Slot " + std::to_string(si) + ": ";
            if (slot.payload_record_id.empty()) label += "(empty)";
            else label += to_compact(slot.payload_record_id, 12) + "  [" + nfc_app::to_string(slot.protocol) + "]";

            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);  // must be before set_size (size is a style in LVGL9)
            lv_obj_set_size(row, 234, 15);
            lv_obj_set_pos(row, 8, 21 + i * 16);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 4, 2, to_compact(label, 34).c_str(), sel ? 0x000000 : 0xCCCCCC, 10);
        }
        create_text(card, 8, 100, "U/D select  Enter upload  ESC back", 0x666666, 10);
    }

    void render_edit_name_modal_card(lv_obj_t *parent)
    {
        lv_obj_t *card = make_modal_card(parent, 300, 70, 0x00D2FF);
        create_text(card, 8, 5, "Edit Name", 0x00D2FF, 12);

        // Symmetric input box margins (8px left/right)
        lv_obj_t *box = create_panel(card, 8, 21, 284, 24, 0x0E1A22);
        lv_obj_set_style_border_color(box, lv_color_hex(0x00D2FF), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(box, 1, LV_PART_MAIN | LV_STATE_DEFAULT);
        const std::string cursor_text = to_compact(edit_buf_, 36) + "_";
        create_text(box, 4, 6, cursor_text.c_str(), 0x00D2FF, 11);

        create_text(card, 8, 52, "Type name  Enter save  Bsp delete  ESC cancel", 0x666666, 10);
    }

    // Strip a raw_data line to pure uppercase hex (no prefixes, no spaces)
    static std::string strip_to_hex(const std::string &s)
    {
        std::string result;
        // Skip "Block N: " or similar prefix before the first colon+space
        size_t start = 0;
        const size_t colon = s.find(": ");
        if (colon != std::string::npos) start = colon + 2;
        for (size_t i = start; i < s.size(); ++i) {
            const unsigned char c = static_cast<unsigned char>(s[i]);
            if (std::isxdigit(c)) result += static_cast<char>(std::toupper(c));
        }
        return result;
    }

    // Group a compact hex string as bytes: "A1B2C3" -> "A1 B2 C3"
    static std::string hex_with_byte_spaces(const std::string &hex)
    {
        std::string out;
        out.reserve(hex.size() + hex.size() / 2);
        for (size_t i = 0; i < hex.size(); ++i) {
            if (i > 0 && (i % 2) == 0) out.push_back(' ');
            out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(hex[i]))));
        }
        return out;
    }

    void render_edit_hex_modal_card(lv_obj_t *parent)
    {
        lv_obj_t *card = make_modal_card(parent, 320, CONTENT_H, 0x00FF88);
        create_text(card, 6, 3, "Hex Editor", 0x00FF88, 12);

        const auto &lines = saved_records_[saved_idx_].tag.raw_data;
        const int total = static_cast<int>(lines.size());
        if (total == 0) {
            create_text(card, 8, 28, "(no data)", 0x666666, 11);
            create_text(card, 8, 108, "ESC close", 0x444444, 10);
            return;
        }

        // Text-editor style: fixed-width index + monospace hex data (unscii_8, 8px/char).
        // unscii_8 is exactly 8px per glyph so bytes always align perfectly.
        // 16 bytes raw hex = 32 chars × 8px = 256px, fits from x=32 to x=288 within 320px card.
        constexpr int VISIBLE = 6;
        constexpr int ROW_H   = 13;
        int offset = edit_hex_line_ - 1;
        if (offset < 0) offset = 0;
        if (offset > total - VISIBLE && total >= VISIBLE) offset = total - VISIBLE;
        if (offset < 0) offset = 0;

        for (int i = 0; i < VISIBLE; ++i) {
            const int li = offset + i;
            if (li >= total) break;
            const bool active = (li == edit_hex_line_);
            const int y = 18 + i * ROW_H;
            char lnum[5]; std::snprintf(lnum, sizeof(lnum), "%02d:", li);
            create_text(card, 4, y, lnum, active ? 0x00FF88 : 0x444444, 7);

            const std::string hex = active ? edit_buf_ : strip_to_hex(lines[li]);
            // Show raw hex (no spaces) – unscii_8 gives perfect per-byte alignment.
            const std::string disp = hex.substr(0, 32) + (active ? "_" : "");
            create_text(card, 32, y, disp.c_str(), active ? 0x00FF88 : 0x888888, 7);
        }

        char hint[32];
        std::snprintf(hint, sizeof(hint), "Line %d/%d  Ctrl+S save  ESC exit",
                      edit_hex_line_ + 1, total);
        create_text(card, 4, 108, hint, 0x444444, 7);
    }

    void render_hex_exit_confirm_card(lv_obj_t *parent)
    {
        lv_obj_t *card = make_modal_card(parent, 230, 82, 0x00FF88);
        create_text(card, 8, 5, "Unsaved Hex Data", 0x00FF88, 12);
        const char *options[] = {"Save and Exit", "Discard", "Cancel"};
        for (int i = 0; i < 3; ++i) {
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 214, 16);
            lv_obj_set_pos(row, 8, 22 + i * 18);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00FF88 : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 3, options[i], sel ? 0x000000 : 0xD0D0D0, 10);
        }
    }

    void save_edit_hex(bool close_after_save)
    {
        auto &lines = saved_records_[saved_idx_].tag.raw_data;
        if (edit_hex_line_ >= 0 && edit_hex_line_ < static_cast<int>(lines.size())) {
            lines[edit_hex_line_] = edit_buf_;
        }
        std::string err;
        service_.update_record_hex(saved_records_[saved_idx_].meta.record_id, lines, &err);
        ui_message_ = err.empty() ? "Hex saved" : "Hex err: " + err;
        edit_hex_dirty_ = false;
        if (close_after_save) {
            modal_ = Modal::None;
            modal_idx_ = 0;
        } else {
            modal_ = Modal::EditHex;
        }
    }

    // ── Modal key handling ───────────────────────────────────────────────────

    void handle_modal_key(uint32_t key, uint32_t mods)
    {
        switch (modal_) {
        case Modal::Action:     handle_action_key(key);      break;
        case Modal::SlotSelect: handle_slot_select_key(key); break;
        case Modal::EditName:   handle_edit_name_key(key);   break;
        case Modal::EditHex:    handle_edit_hex_key(key, mods);    break;
        case Modal::HexExitConfirm: handle_hex_exit_confirm_key(key); break;
        case Modal::EmulatorAction: handle_emulator_action_key(key); break;
        case Modal::DeviceProbe: handle_device_probe_key(key); break;
        case Modal::UartConfig:  handle_uart_config_key(key);  break;
        case Modal::ToolPage:
            if (active_tool_idx_ == 0) handle_mifare_keys_tool_key(key);
            else if (active_tool_idx_ == 3 || active_tool_idx_ == 4) handle_mfkey_tool_key(key);
            else if (key == KEY_ESC) modal_ = Modal::None;
            break;
        case Modal::UidChanger:
        case Modal::TagEraser:
        case Modal::ToolInfo:
            if (key == KEY_ESC) modal_ = Modal::None;
            break;
        case Modal::AppInfo:
            if (key == KEY_ESC || key == KEY_I) {
                modal_ = Modal::None;
            }
            break;
        case Modal::PostScan:
            handle_post_scan_key(key);
            break;
        case Modal::ReadMenu:
            handle_read_menu_key(key);
            break;
        case Modal::PortSettings:
            handle_port_settings_key(key);
            break;
        case Modal::UsbSelect:
            handle_usb_select_key(key);
            break;
        case Modal::HexLog:
            handle_hex_log_key(key);
            break;
        default: break;
        }
        render_all();
    }

    void handle_action_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:    modal_idx_ = (modal_idx_ + 3) % 4; break;
        case KEY_DOWN:
        case KEY_X:    modal_idx_ = (modal_idx_ + 1) % 4; break;
        case KEY_ENTER:
            if (modal_idx_ == 0) {
                if (service_.emulation_allowed(&ui_message_)) {
                    slot_select_idx_ = service_.selected_slot_index_for_protocol(saved_records_[saved_idx_].tag.protocol);
                    modal_ = Modal::SlotSelect;
                }
            } else if (modal_idx_ == 1) {
                edit_buf_ = saved_records_[saved_idx_].meta.display_name;
                modal_ = Modal::EditName;
            } else if (modal_idx_ == 2) {
                const auto &lines = saved_records_[saved_idx_].tag.raw_data;
                edit_hex_line_ = 0;
                edit_buf_ = lines.empty() ? "" : strip_to_hex(lines[0]);
                edit_hex_dirty_ = false;
                modal_ = Modal::EditHex;
            } else {
                // Delete
                std::string err;
                const std::string record_id = saved_records_[saved_idx_].meta.record_id;
                if (service_.delete_saved_record(record_id, &err)) {
                    refresh_saved_records();
                    ui_message_ = "Deleted";
                } else {
                    ui_message_ = err;
                }
                modal_     = Modal::None;
                modal_idx_ = 0;
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    void handle_slot_select_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:    slot_select_idx_ = (slot_select_idx_ + 7) % 8; break;
        case KEY_DOWN:
        case KEY_X:    slot_select_idx_ = (slot_select_idx_ + 1) % 8; break;
        case KEY_ENTER: {
            const auto &record = saved_records_[saved_idx_];
            if (service_.upload_record_to_slot_n(record, slot_select_idx_)) {
                ui_message_ = "Uploaded -> Slot " + std::to_string(slot_select_idx_);
            } else {
                ui_message_ = "Upload failed";
            }
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        }
        case KEY_ESC:
            modal_ = Modal::Action;
            break;
        default: break;
        }
    }

    void handle_emulator_action_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:    modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN:
        case KEY_X:    modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER:
            if (!service_.emulation_allowed(&ui_message_)) {
                modal_ = Modal::None;
                modal_idx_ = 0;
                break;
            }
            if (modal_idx_ == 0) {
                // Download Data: pull full block dump from HW slot into cache
                if (service_.hw_start_emu_dump_async(service_.current_emulator_protocol(), hw_emu_slot_)) {
                    ui_message_ = "Downloading slot data...";
                } else {
                    ui_message_ = "Download failed (scan running?)";
                }
            } else if (modal_idx_ == 1) {
                // Upload Data: for PN532Killer send data to HW via setEmulatorData (hfmfeload protocol).
                if (saved_records_.empty()) {
                    ui_message_ = "Upload failed: no saved data";
                } else if (service_.connection_state().device_kind == nfc_app::DeviceKind::PN532Killer
                           && saved_records_[saved_idx_].tag.raw_data.size() == 64) {
                    if (service_.hw_start_upload_async(hw_emu_slot_, saved_records_[saved_idx_])) {
                        ui_message_ = "Uploading to HW slot " + std::to_string(hw_emu_slot_ + 1) + "...";
                    } else {
                        ui_message_ = "Upload failed (busy?)";
                    }
                } else {
                    // Fallback: local slot assignment only
                    if (service_.upload_record_to_slot(saved_records_[saved_idx_])) {
                        ui_message_ = "Uploaded saved data";
                    } else {
                        ui_message_ = "Upload failed";
                    }
                }
            } else {
                service_.set_default_slot();
                ui_message_ = "Set as module default mode";
            }
            modal_ = Modal::None;
            modal_idx_ = 0;
            break;
        case KEY_ESC:
            modal_ = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    void handle_hex_exit_confirm_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:    modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN:
        case KEY_X:    modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER:
            if (modal_idx_ == 0) {
                save_edit_hex(true);
            } else if (modal_idx_ == 1) {
                refresh_saved_records();
                edit_hex_dirty_ = false;
                modal_ = Modal::Action;
                modal_idx_ = 0;
                ui_message_ = "Hex changes discarded";
            } else {
                modal_ = Modal::EditHex;
            }
            break;
        case KEY_ESC:
            modal_ = Modal::EditHex;
            break;
        default: break;
        }
    }

    void handle_edit_name_key(uint32_t key)
    {
        if (key == KEY_ENTER) {
            auto &record = saved_records_[saved_idx_];
            record.meta.display_name = edit_buf_.empty() ? record.meta.display_name : edit_buf_;
            std::string err;
            service_.rename_saved_record(record.meta.record_id, record.meta.display_name, &err);
            ui_message_ = err.empty() ? "Name saved" : "Rename err: " + err;
            modal_     = Modal::None;
            modal_idx_ = 0;
        } else if (key == KEY_ESC) {
            modal_ = Modal::Action;
        } else if (key == KEY_BACKSPACE) {
            if (!edit_buf_.empty()) edit_buf_.pop_back();
        } else {
            char ch = keycode_to_char(key);
            if (ch && edit_buf_.size() < 36) edit_buf_ += ch;
        }
    }

    void handle_edit_hex_key(uint32_t key, uint32_t mods)
    {
        auto &lines = saved_records_[saved_idx_].tag.raw_data;
        const int total = static_cast<int>(lines.size());

        auto commit_current = [&]() {
            if (edit_hex_line_ < total)
                lines[edit_hex_line_] = edit_buf_;  // store as normalized hex
        };

        if ((mods & KBD_MOD_CTRL) && key == KEY_S) {
            commit_current();
            save_edit_hex(false);
        } else if (key == KEY_ESC) {
            commit_current();
            if (edit_hex_dirty_) {
                modal_ = Modal::HexExitConfirm;
                modal_idx_ = 0;
            } else {
                modal_ = Modal::Action;
            }
        } else if (key == KEY_ENTER) {
            commit_current();
            std::vector<std::string> new_lines = lines;
            const int insert_at = new_lines.empty() ? 0 : edit_hex_line_ + 1;
            new_lines.insert(new_lines.begin() + insert_at, std::string());
            lines = new_lines;
            edit_hex_line_ = insert_at;
            edit_buf_.clear();
            edit_hex_dirty_ = true;
        } else if (key == KEY_UP && edit_hex_line_ > 0) {
            commit_current();
            --edit_hex_line_;
            edit_buf_ = strip_to_hex(lines[edit_hex_line_]);
        } else if (key == KEY_DOWN && edit_hex_line_ + 1 < total) {
            commit_current();
            ++edit_hex_line_;
            edit_buf_ = strip_to_hex(lines[edit_hex_line_]);
        } else if (key == KEY_BACKSPACE) {
            if (!edit_buf_.empty()) {
                edit_buf_.pop_back();
                edit_hex_dirty_ = true;
            }
        } else {
            char ch = keycode_to_hex_char(key);
            if (ch && ch != ' ' && ch != ':' && edit_buf_.size() < 80) {
                edit_buf_ += ch;
                edit_hex_dirty_ = true;
            }
        }
    }

    void handle_mifare_keys_tool_key(uint32_t key)
    {
        if (mifare_key_editing_) {
            if (key == KEY_ESC) {
                mifare_key_editing_ = false;
                mifare_key_field_idx_ = 0;
                edit_buf_.clear();
                ui_message_ = "Key edit canceled";
                return;
            }
            if (key == KEY_UP) {
                mifare_key_field_idx_ = (mifare_key_field_idx_ + 2) % 3;
                return;
            }
            if (key == KEY_DOWN) {
                mifare_key_field_idx_ = (mifare_key_field_idx_ + 1) % 3;
                return;
            }
            if (key == KEY_TAB || key == KEY_LEFT || key == KEY_RIGHT) {
                if (mifare_key_field_idx_ == 2) {
                    mifare_key_edit_.type = (mifare_key_edit_.type == nfc_app::MifareKeyType::KeyA)
                        ? nfc_app::MifareKeyType::KeyB
                        : nfc_app::MifareKeyType::KeyA;
                }
                return;
            }
            if (key == KEY_BACKSPACE) {
                if (mifare_key_field_idx_ == 0 && !mifare_key_edit_.label.empty()) {
                    mifare_key_edit_.label.pop_back();
                } else if (mifare_key_field_idx_ == 1 && !mifare_key_edit_.key_hex.empty()) {
                    mifare_key_edit_.key_hex.pop_back();
                }
                return;
            }
            if (key == KEY_ENTER) {
                std::string err;
                const int save_index = mifare_key_creating_ ? -1 : mifare_key_idx_;
                if (service_.upsert_mifare_key(save_index, mifare_key_edit_, &err)) {
                    refresh_mifare_keys();
                    if (mifare_key_creating_) mifare_key_idx_ = static_cast<int>(mifare_keys_.size()) - 1;
                    ui_message_ = "Key saved";
                    mifare_key_editing_ = false;
                    mifare_key_field_idx_ = 0;
                } else {
                    ui_message_ = err;
                }
                return;
            }

            if (mifare_key_field_idx_ == 0) {
                char ch = keycode_to_char(key);
                if (ch && mifare_key_edit_.label.size() < 20) mifare_key_edit_.label += ch;
            } else if (mifare_key_field_idx_ == 1) {
                char ch = keycode_to_hex_char(key);
                if (ch && ch != ' ' && ch != ':' && mifare_key_edit_.key_hex.size() < 12) mifare_key_edit_.key_hex += ch;
            }
            return;
        }

        const int total_rows = static_cast<int>(mifare_keys_.size()) + 1;
        if (key == KEY_ESC) {
            if (mifare_keys_file_mode_) {
                if (!key_file_keys_.empty()) {
                    // Go back to file list
                    key_file_keys_.clear();
                } else {
                    // Exit file mode
                    mifare_keys_file_mode_ = false;
                }
            } else {
                modal_ = Modal::None;
            }
            return;
        }
        // TAB: switch between built-in and file mode
        if (key == KEY_TAB) {
            if (!mifare_keys_file_mode_) {
                // Entering file mode: also try to toggle key if on a key row (for power users)
                // Actually just switch mode; TAB-as-toggle is confusing when file mode is active
                mifare_keys_file_mode_ = true;
                key_files_ = service_.list_key_files();
                key_file_idx_ = 0;
                key_file_keys_.clear();
                key_file_key_idx_ = 0;
            } else {
                mifare_keys_file_mode_ = false;
            }
            return;
        }
        // File mode navigation
        if (mifare_keys_file_mode_) {
            const int fn = static_cast<int>(key_files_.size());
            if (key_file_keys_.empty()) {
                // File list navigation
                if (key == KEY_UP) {
                    if (fn > 0) key_file_idx_ = (key_file_idx_ - 1 + fn) % fn;
                } else if (key == KEY_DOWN) {
                    if (fn > 0) key_file_idx_ = (key_file_idx_ + 1) % fn;
                } else if (key == KEY_ENTER && fn > 0 && key_file_idx_ < fn) {
                    key_file_keys_ = service_.load_key_file(key_files_[static_cast<size_t>(key_file_idx_)]);
                    key_file_key_idx_ = 0;
                    if (key_file_keys_.empty()) ui_message_ = "File is empty";
                }
            } else {
                // Key list navigation within loaded file
                const int kt = static_cast<int>(key_file_keys_.size());
                if (key == KEY_UP) {
                    key_file_key_idx_ = (key_file_key_idx_ - 1 + kt) % kt;
                } else if (key == KEY_DOWN) {
                    key_file_key_idx_ = (key_file_key_idx_ + 1) % kt;
                } else if (key == KEY_BACKSPACE) {
                    key_file_keys_.clear();
                    key_file_key_idx_ = 0;
                } else if (key == KEY_ENTER && key_file_key_idx_ < kt) {
                    // Add selected key to built-in list
                    const std::string &hex = key_file_keys_[static_cast<size_t>(key_file_key_idx_)];
                    nfc_app::MifareKeyRecord rec{};
                    rec.key_hex = hex;
                    const std::string fname = key_file_idx_ < fn ? key_files_[static_cast<size_t>(key_file_idx_)] : "";
                    // Derive a short label from filename without extension
                    rec.label = fname.empty() ? "from_file" : fname.substr(0, fname.rfind('.'));
                    rec.created_at = nfc_app::iso8601_now();
                    rec.enabled = true;
                    std::string err;
                    if (service_.upsert_mifare_key(-1, rec, &err)) {
                        refresh_mifare_keys();
                        show_toast("Imported");
                    } else {
                        ui_message_ = err;
                    }
                }
            }
            return;
        }
        // Built-in key list navigation
        if (key == KEY_UP) {
            mifare_key_idx_ = (mifare_key_idx_ - 1 + total_rows) % total_rows;
            return;
        }
        if (key == KEY_DOWN) {
            mifare_key_idx_ = (mifare_key_idx_ + 1) % total_rows;
            return;
        }
        if (key == KEY_T && mifare_key_idx_ < static_cast<int>(mifare_keys_.size())) {
            // 'T' key for toggle (TAB is now mode-switch)
            std::string err;
            if (service_.toggle_mifare_key_enabled(mifare_key_idx_, &err)) {
                refresh_mifare_keys();
                ui_message_ = "Key toggled";
            } else {
                ui_message_ = err;
            }
            return;
        }
        if (key == KEY_BACKSPACE && mifare_key_idx_ < static_cast<int>(mifare_keys_.size())) {
            std::string err;
            if (service_.delete_mifare_key(mifare_key_idx_, &err)) {
                refresh_mifare_keys();
                if (mifare_key_idx_ > static_cast<int>(mifare_keys_.size())) mifare_key_idx_ = static_cast<int>(mifare_keys_.size());
                ui_message_ = "Key deleted";
            } else {
                ui_message_ = err;
            }
            return;
        }
        if (key == KEY_ENTER) {
            mifare_key_creating_ = (mifare_key_idx_ >= static_cast<int>(mifare_keys_.size()));
            mifare_key_editing_ = true;
            mifare_key_field_idx_ = 0;
            if (mifare_key_creating_) {
                mifare_key_edit_ = nfc_app::MifareKeyRecord{};
                mifare_key_edit_.created_at = nfc_app::iso8601_now();
            } else {
                mifare_key_edit_ = mifare_keys_[mifare_key_idx_];
            }
            return;
        }
    }

    void handle_mfkey_tool_key(uint32_t key)
    {
        const bool with_card = (active_tool_idx_ == 4);

        // Global: ESC always goes back (or resets step)
        if (key == KEY_ESC) {
            if (mfkey_step_ == 0) {
                modal_ = Modal::None;
            } else {
                // Reset to idle — also switch device back to reader mode if sniffing
                if (mfkey_step_ == 1) {
                    service_.hw_switch_to_reader_mode();
                }
                mfkey_step_      = 0;
                mfkey_uid_input_ = "";
                mfkey_results_.clear();
                mfkey_result_idx_ = 0;
            }
            return;
        }

        if (!with_card) {
            // ── mfkey32v2 flow ──────────────────────────────────────────────
            switch (mfkey_step_) {
            case 0: {
                // UID input — optional
                if (key == KEY_BACKSPACE) {
                    if (!mfkey_uid_input_.empty()) mfkey_uid_input_.pop_back();
                    return;
                }
                if (key == KEY_ENTER) {
                    // If UID provided, set it; if empty, skip set_uid and use device default
                    if (!mfkey_uid_input_.empty()) {
                        if (mfkey_uid_input_.size() < 8) {
                            ui_message_ = "UID must be 8 hex chars (4 bytes)";
                            return;
                        }
                        if (!service_.hw_sniff_set_uid(mfkey_uid_input_)) {
                            ui_message_ = "Failed to set sniffer UID — device connected?";
                            return;
                        }
                    }
                    if (!service_.hw_sniff_enter_mode(false)) {
                        ui_message_ = "Failed to enter sniffer mode";
                        return;
                    }
                    mfkey_step_ = 1;
                    ui_message_ = mfkey_uid_input_.empty()
                        ? "Sniffer active (no UID set). Approach reader."
                        : "Sniffer active (UID set). Approach reader.";
                    return;
                }
                // Hex char input (max 8)
                if (mfkey_uid_input_.size() < 8) {
                    char ch = keycode_to_hex_char(key);
                    if (ch) mfkey_uid_input_ += ch;
                }
                break;
            }
            case 1: {
                // Sniffer active — wait for Enter to stop and crack
                if (key == KEY_ENTER) {
                    // Switch back to reader mode, then start async crack
                    service_.hw_switch_to_reader_mode();
                    mfkey_results_.clear();
                    mfkey_result_idx_ = 0;
                    if (service_.hw_start_mfkey_async(false)) {
                        mfkey_step_ = 2;
                        ui_message_ = "MFKey32v2 cracking...";
                    } else {
                        ui_message_ = "Not connected or already running";
                    }
                }
                break;
            }
            case 2: {
                // Cracking in progress — nothing to do, timer tick advances to step 3
                break;
            }
            default: {
                // Results
                handle_mfkey_results_key(key);
                break;
            }
            }
        } else {
            // ── mfkey64 flow ────────────────────────────────────────────────
            switch (mfkey_step_) {
            case 0: {
                // Ready: Enter enters card-present sniffer mode
                if (key == KEY_ENTER) {
                    if (!service_.hw_sniff_enter_mode(true)) {
                        ui_message_ = "Failed to enter sniffer mode — device connected?";
                        return;
                    }
                    mfkey_step_ = 1;
                    ui_message_ = "Sniffer active (card-present). Hold card near reader.";
                }
                break;
            }
            case 1: {
                // Sniffer active — Enter stops and cracks
                if (key == KEY_ENTER) {
                    service_.hw_switch_to_reader_mode();
                    mfkey_results_.clear();
                    mfkey_result_idx_ = 0;
                    if (service_.hw_start_mfkey_async(true)) {
                        mfkey_step_ = 2;
                        ui_message_ = "MFkey64 cracking...";
                    } else {
                        ui_message_ = "Not connected or already running";
                    }
                }
                break;
            }
            case 2: {
                // Cracking in progress
                break;
            }
            default: {
                handle_mfkey_results_key(key);
                break;
            }
            }
        }
    }

    // Shared result navigation + save for both mfkey tools (step 3+)
    void handle_mfkey_results_key(uint32_t key)
    {
        const bool with_card = (active_tool_idx_ == 4);
        switch (key) {
        case KEY_ENTER: {
            if (!mfkey_results_.empty() &&
                mfkey_result_idx_ < static_cast<int>(mfkey_results_.size())) {
                const auto &res = mfkey_results_[static_cast<size_t>(mfkey_result_idx_)];
                if (!res.key_hex.empty()) {
                    std::string err;
                    if (service_.import_mfkey_result(res, &err)) {
                        refresh_mifare_keys();
                        show_toast("Saved");
                        ui_message_ = "Key imported to MIFARE Keys";
                    } else {
                        ui_message_ = err;
                    }
                } else {
                    ui_message_ = "No key to save (not found)";
                }
            }
            break;
        }
        case KEY_R: {
            // Retry: go back to step 0
            mfkey_step_      = 0;
            mfkey_uid_input_ = "";
            mfkey_results_.clear();
            mfkey_result_idx_ = 0;
            ui_message_ = "Retry — reset to step 1";
            break;
        }
        case KEY_UP:
        case KEY_F:
            if (!mfkey_results_.empty())
                mfkey_result_idx_ = (mfkey_result_idx_ - 1 + static_cast<int>(mfkey_results_.size())) % static_cast<int>(mfkey_results_.size());
            break;
        case KEY_DOWN:
        case KEY_X:
            if (!mfkey_results_.empty())
                mfkey_result_idx_ = (mfkey_result_idx_ + 1) % static_cast<int>(mfkey_results_.size());
            break;
        default: break;
        }
        (void)with_card;
    }
};