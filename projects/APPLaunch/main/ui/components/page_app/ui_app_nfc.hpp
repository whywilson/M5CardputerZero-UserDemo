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

    static constexpr int TAB_H = 24;
    static constexpr int CONTENT_Y = 26;
    static constexpr int CONTENT_H = 120;

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
        if (self) self->render_all();
    }

    void event_handler(lv_event_t *e)
    {
        if (!IS_KEY_RELEASED(e)) return;
        const uint32_t raw_key = LV_EVENT_KEYBOARD_GET_KEY(e);
        const auto *key_item = static_cast<struct key_item *>(lv_event_get_param(e));
        const uint32_t mods = key_item ? key_item->mods : 0;

        if (modal_ != Modal::None) {
            handle_modal_key(raw_key, mods);
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
                service_.cycle_transport_mode(&ui_message_);
                render_all();
            } else if (current_tab_ == Tab::Emulator) {
                service_.toggle_slot_protocol();
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
        case KEY_S:
            if (current_tab_ == Tab::Read) {
                std::string error;
                if (service_.save_last_scan(&error)) {
                    refresh_saved_records();
                    ui_message_ = "Record saved to JSON";
                } else {
                    ui_message_ = error;
                }
                render_all();
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
        int tab_index = static_cast<int>(current_tab_);
        tab_index = (tab_index + delta + 4) % 4;
        current_tab_ = static_cast<Tab>(tab_index);
        render_all();
    }

    void navigate(int delta)
    {
        switch (current_tab_) {
        case Tab::Read:
            (void)delta;
            break;
        case Tab::Saved:
            if (!saved_records_.empty()) {
                saved_idx_ = (saved_idx_ + delta + static_cast<int>(saved_records_.size())) % static_cast<int>(saved_records_.size());
            }
            break;
        case Tab::Emulator:
            service_.cycle_slot(delta);
            ui_message_ = "Slot changed";
            break;
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
            service_.connect_and_scan(&ui_message_);
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
        modal_ = Modal::ToolPage;
        ui_message_ = std::string(tool_name(active_tool_idx_)) + " opened";
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
            break;
        case Tab::Saved:
            render_saved_tab(content);
            if (modal_ != Modal::None) render_saved_modal(content);
            break;
        case Tab::Emulator:
            render_emulator_tab(content);
            if (modal_ == Modal::EmulatorAction) render_emulator_modal(content);
            break;
        case Tab::Tools:
            render_tools_tab(content);
            break;
        }
    }

    void render_read_tab(lv_obj_t *parent)
    {
        const auto connection = service_.connection_state();
        const auto scan = service_.scan_state();
        const auto endpoint = service_.current_endpoint();

        lv_obj_t *summary = create_panel(parent, 0, 0, 320, 34, 0x161616);
        create_text(summary, 6, 4, "Transport", 0x8E8E8E, 11);
        create_text(summary, 64, 4,
                    endpoint.kind == nfc_app::TransportKind::UartSerial ? "UART" :
                    endpoint.kind == nfc_app::TransportKind::UsbSerial ? "USB" : "MOCK",
                    0xFFFFFF, 12);
        create_text(summary, 6, 18, to_compact(endpoint.label, 24).c_str(), 0x00D2FF, 11);
        create_text(summary, 164, 18, connection.detail.empty() ? "Tab switch transport" : to_compact(connection.detail, 22).c_str(), 0xA8A8A8, 11);

        lv_obj_t *actions = create_panel(parent, 0, 38, 116, 82, 0x101010);
        create_text(actions, 6, 6, "Read Flow", 0xFFFFFF, 12);
        create_text(actions, 6, 24, "Tab: USB/UART", 0xD8D8D8, 11);
        create_text(actions, 6, 38, "Auto detect", 0xD8D8D8, 11);
        create_text(actions, 6, 52, "OK: scan card", 0xF7A600, 11);
        create_text(actions, 6, 66, connection.connected ? "Connected" : "Ready", 0x8DB6FF, 11);

        lv_obj_t *detail = create_panel(parent, 120, 38, 200, 82, 0x101010);
        const nfc_app::SavedRecord &record = scan.last_record;
        create_text(detail, 6, 4, scan.running ? "Scanning..." : (connection.connected ? connection.status.c_str() : scan.status.c_str()), scan.running ? 0xF7A600 : 0xFFFFFF, 12);
        create_text(detail, 6, 19, (std::string("Type: ") + (scan.has_result ? record.tag.tag_type : "-")).c_str(), 0xD8D8D8, 11);
        create_text(detail, 6, 33, (std::string("UID: ") + (scan.has_result ? record.tag.uid : "-")).c_str(), 0xD8D8D8, 11);
        create_text(detail, 6, 47, (std::string("Proto: ") + (scan.has_result ? nfc_app::to_string(record.tag.protocol) : "-")).c_str(), 0xD8D8D8, 11);
        create_text(detail, 6, 61, (std::string("Source: ") + (scan.has_result ? record.meta.source : scan.error)).c_str(), 0x8DB6FF, 11);

        create_footer(parent, std::string("Tab transport  OK scan  S save  L/R page  ESC back  ") + ui_message_);
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
            create_text(detail, 6, 75, "OK: upload / edit / rename", 0xF7A600, 10);
            create_text(detail, 6, 88, record.meta.mock ? "[mock]" : "[JSON]", 0x555555, 10);
        }

        create_footer(parent, std::string("U/D select  OK actions  L/R page  ") + ui_message_);
    }

    void render_emulator_tab(lv_obj_t *parent)
    {
        const auto connection = service_.connection_state();
        const auto protocol = service_.current_emulator_protocol();
        const auto slots = service_.emulator_slots();
        const int selected_slot = service_.selected_slot_index();
        const int total_slots = static_cast<int>(slots.size());
        const auto slot = slots.empty() ? nfc_app::EmulatorSlotRecord{} : slots[selected_slot];

        lv_obj_t *left = create_panel(parent, 0, 0, 116, 104, 0x101010);
        lv_obj_t *right = create_panel(parent, 120, 0, 200, 104, 0x101010);

        // Left: slot carousel
        create_text(left, 6, 6, nfc_app::to_string(protocol), 0x8E8E8E, 11);
        const std::string slot_str = std::to_string(selected_slot + 1) + " / " + std::to_string(total_slots > 0 ? total_slots : 1);
        create_text(left, 6, 20, slot_str.c_str(), 0xFFFFFF, 12);
        create_text(left, 6, 40, "\x1E  UP", 0xD0D0D0, 11);
        create_text(left, 6, 54, "\x1F  DOWN", 0xD0D0D0, 11);
        create_text(left, 6, 70, "Tab: proto", 0xF7A600, 11);
        create_text(left, 6, 84,
                    connection.device_kind == nfc_app::DeviceKind::PN532Killer || connection.endpoint.kind == nfc_app::TransportKind::Mock
                        ? "OK: menu"
                        : "PN532Killer only",
                    0x9E9E9E, 11);

        // Right: slot detail
        create_text(right, 6, 6, (std::string("Slot ") + std::to_string(slot.slot_index)).c_str(), 0xFFFFFF, 12);
        create_text(right, 6, 21, (std::string("Proto: ") + nfc_app::to_string(protocol)).c_str(), 0xD8D8D8, 11);
        create_text(right, 6, 35, (std::string("Payload: ") + to_compact(slot.payload_record_id.empty() ? "(none)" : slot.payload_record_id, 18)).c_str(), 0xD8D8D8, 11);
        create_text(right, 6, 49, slot.default_slot ? "Default: yes" : "Default: no", 0x8DB6FF, 11);
        create_text(right, 6, 63, (std::string("Device: ") + nfc_app::to_string(connection.device_kind)).c_str(), 0x8DB6FF, 11);
        create_text(right, 6, 78,
                    connection.device_kind == nfc_app::DeviceKind::PN532Killer || connection.endpoint.kind == nfc_app::TransportKind::Mock
                        ? "OK: upload/download/default"
                        : "EMU needs PN532Killer",
                    0xF7A600, 10);

        create_footer(parent, std::string("\x18\x19 slot  Tab proto  OK menu  L/R page  ") + ui_message_);
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

        lv_obj_t *card = make_modal_card(overlay, 220, 86, 0xF7A600);
        const auto slot = service_.selected_slot_index();
        create_text(card, 8, 5, (std::string(nfc_app::to_string(service_.current_emulator_protocol())) + " Slot " + std::to_string(slot)).c_str(), 0xFFFFFF, 12);
        const char *options[] = {"Upload Data", "Download Data", "Set Default"};
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
        create_text(card, 8, 74, "U/D sel  Enter run  ESC close", 0x666666, 10);
    }

    void render_tools_tab(lv_obj_t *parent)
    {
        lv_obj_t *list = create_panel(parent, 0, 0, 140, 104, 0x101010);
        lv_obj_t *detail = create_panel(parent, 144, 0, 176, 104, 0x101010);

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

        if (modal_ == Modal::ToolPage || modal_ == Modal::DeviceProbe || modal_ == Modal::UartConfig ||
            modal_ == Modal::UidChanger || modal_ == Modal::TagEraser) {
            render_tools_modal(detail);
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

        if (modal_ == Modal::None) {
            create_footer(parent, std::string("U/D select  OK enter  L/R page  ") + ui_message_);
        } else {
            create_footer(parent, std::string("RFID > ") + tool_name(active_tool_idx_) + "  ESC back  " + ui_message_);
        }
    }

    // ── Tools-specific modal overlay ─────────────────────────────────────────
    void render_tools_modal(lv_obj_t *parent)
    {
        if (modal_ == Modal::ToolPage) {
            if (active_tool_idx_ == 0) {
                render_mifare_keys_tool(parent);
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
            case 3:
                create_text(parent, 6, 24, "Collect nonces", 0xD8D8D8, 11);
                create_text(parent, 6, 38, "Run MFKey32v2", 0xD8D8D8, 11);
                create_text(parent, 6, 52, "Save into Mifare Keys", 0x8DB6FF, 11);
                break;
            case 4:
                create_text(parent, 6, 24, "Hardnested capture", 0xD8D8D8, 11);
                create_text(parent, 6, 38, "Run MFkey64", 0xD8D8D8, 11);
                create_text(parent, 6, 52, "Save into Mifare Keys", 0x8DB6FF, 11);
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

    void render_mifare_keys_tool(lv_obj_t *parent)
    {
        create_text(parent, 6, 4, "Mifare Keys", 0xFFFFFF, 12);
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
        create_text(parent, 6, 92, "U/D select  Enter edit  Tab on/off  Bsp del  ESC back", 0x7A7A7A, 10);
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
        lv_obj_set_style_text_font(label, font_size >= 12 ? &lv_font_montserrat_12 : &lv_font_montserrat_10, LV_PART_MAIN | LV_STATE_DEFAULT);
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
        // Width 220, Height 90 → 3 options + title
        lv_obj_t *card = make_modal_card(parent, 220, 90, 0xF7A600);
        const auto &rec = saved_records_[saved_idx_];
        create_text(card, 8, 6, to_compact(rec.meta.display_name, 26).c_str(), 0xFFFFFF, 12);

        const char *options[] = {"Upload to Slot...", "Edit Name", "Edit Hex Data"};
        for (int i = 0; i < 3; ++i) {
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);  // must be before set_size (size is a style in LVGL9)
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 24 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x2A2A2A), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 4, options[i], sel ? 0x000000 : 0xD0D0D0, 11);
        }
        create_text(card, 8, 78, "U/D sel  Enter confirm  ESC cancel", 0x666666, 10);
    }

    void render_slot_select_modal_card(lv_obj_t *parent)
    {
        // Width 250, Height 108 → 5 visible slots + header + hint
        lv_obj_t *card = make_modal_card(parent, 250, 108, 0xF7A600);
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
        create_text(card, 8, 97, "U/D select  Enter upload  ESC back", 0x666666, 10);
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

        // Text-editor style: fixed line-number column + text column, caret on active line
        constexpr int VISIBLE = 5;
        constexpr int ROW_H   = 15;
        int offset = edit_hex_line_ - 1;
        if (offset < 0) offset = 0;
        if (offset > total - VISIBLE && total >= VISIBLE) offset = total - VISIBLE;
        if (offset < 0) offset = 0;

        for (int i = 0; i < VISIBLE; ++i) {
            const int li = offset + i;
            if (li >= total) break;
            const bool active = (li == edit_hex_line_);
            const int y = 20 + i * ROW_H;
            char lnum[5]; std::snprintf(lnum, sizeof(lnum), "%2d:", li);
            create_text(card, 16, y, lnum, active ? 0x00FF88 : 0x444444, 10);

            const std::string hex = active ? edit_buf_ : strip_to_hex(lines[li]);
            const std::string spaced = hex_with_byte_spaces(hex);
            const std::string disp = to_compact(spaced, 44) + (active ? "_" : "");
            create_text(card, 58, y, disp.c_str(), active ? 0x00FF88 : 0x888888, 10);
        }

        char hint[80];
        std::snprintf(hint, sizeof(hint), "Line %d/%d  Enter newline  Ctrl+S save  ESC exit",
                      edit_hex_line_ + 1, total);
        create_text(card, 4, 108, hint, 0x444444, 10);
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
        create_text(card, 8, 72, "U/D select  Enter confirm", 0x666666, 10);
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
            else if (key == KEY_ESC) modal_ = Modal::None;
            break;
        case Modal::UidChanger:
        case Modal::TagEraser:
            if (key == KEY_ESC) modal_ = Modal::None;
            break;
        default: break;
        }
        render_all();
    }

    void handle_action_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:   modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN: modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER:
            if (modal_idx_ == 0) {
                if (service_.emulation_allowed(&ui_message_)) {
                    slot_select_idx_ = service_.selected_slot_index_for_protocol(saved_records_[saved_idx_].tag.protocol);
                    modal_ = Modal::SlotSelect;
                }
            } else if (modal_idx_ == 1) {
                edit_buf_ = saved_records_[saved_idx_].meta.display_name;
                modal_ = Modal::EditName;
            } else {
                const auto &lines = saved_records_[saved_idx_].tag.raw_data;
                edit_hex_line_ = 0;
                edit_buf_ = lines.empty() ? "" : strip_to_hex(lines[0]);
                edit_hex_dirty_ = false;
                modal_ = Modal::EditHex;
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
        case KEY_UP:   slot_select_idx_ = (slot_select_idx_ + 7) % 8; break;
        case KEY_DOWN: slot_select_idx_ = (slot_select_idx_ + 1) % 8; break;
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
        case KEY_UP:   modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN: modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER:
            if (!service_.emulation_allowed(&ui_message_)) {
                modal_ = Modal::None;
                modal_idx_ = 0;
                break;
            }
            if (modal_idx_ == 0) {
                if (!saved_records_.empty() && service_.upload_record_to_slot(saved_records_[saved_idx_])) {
                    ui_message_ = "Uploaded saved data";
                } else {
                    ui_message_ = "Upload failed: no saved data";
                }
            } else if (modal_idx_ == 1) {
                if (service_.download_slot_to_saved()) {
                    refresh_saved_records();
                    ui_message_ = "Downloaded slot data";
                } else {
                    ui_message_ = "Download failed";
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
        case KEY_UP:   modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN: modal_idx_ = (modal_idx_ + 1) % 3; break;
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
            modal_ = Modal::None;
            return;
        }
        if (key == KEY_UP) {
            mifare_key_idx_ = (mifare_key_idx_ - 1 + total_rows) % total_rows;
            return;
        }
        if (key == KEY_DOWN) {
            mifare_key_idx_ = (mifare_key_idx_ + 1) % total_rows;
            return;
        }
        if (key == KEY_TAB && mifare_key_idx_ < static_cast<int>(mifare_keys_.size())) {
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
};