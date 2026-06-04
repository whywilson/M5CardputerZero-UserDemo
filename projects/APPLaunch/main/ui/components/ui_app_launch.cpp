#include "../ui.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include "hal/hal_paths.h"
#include "hal/hal_filesystem.h"
#include "hal/hal_process.h"
#include "hal/hal_settings.h"
#include "hal/hal_config.h"
#include "hal/hal_audio.h"
#include <unordered_map>
#include <list>
#include <memory>
#include <string>
#include <cctype>
#include <cstdlib>
#include <functional>
#include <chrono>
#include <atomic>
#include <thread>
#include <sstream>
#include <array>
#include <fstream>
#include <sstream>
#include "ui_launch_page.hpp"
#include "../ui_loading.h"
#include "page_app.h"
#include "nfc/nfc_device_service.hpp"
#include "nfc/nfc_i2c_device.hpp"

/* img_path() now defined in ui_app_page.hpp */

#define PANEL_BORDER_CENTER  0x444444
#define PANEL_BORDER_SIDE    0x222222
#define PANEL_PAD_CENTER     0
#define PANEL_PAD_SIDE       0


static void panel_set_icon(lv_obj_t *panel, const char *src)
{
    lv_obj_set_style_pad_all(panel, 0, LV_PART_MAIN | LV_STATE_DEFAULT);

    lv_obj_t *img = lv_obj_get_child(panel, 0);
    if (!img || !lv_obj_check_type(img, &lv_image_class)) {
        img = lv_image_create(panel);
        lv_obj_set_size(img, LV_PCT(100), LV_PCT(100));
        lv_obj_set_align(img, LV_ALIGN_CENTER);
        lv_image_set_inner_align(img, LV_IMAGE_ALIGN_STRETCH);
    }
    lv_image_set_src(img, src);
}

// ============================================================
// 启动快捷方式示例
// ============================================================
/*
root@pi:/home/pi# cat /usr/share/APPLaunch/applications/vim.desktop
[Desktop Entry]
Name=Vim
TryExec=vim
Exec=vim
Terminal=true
Icon=share/images/e-Mail_80.png
*/

// 前向声明
class app_launch_S;

// ============================================================
// 类型标签
// ============================================================
template <class PageT>
struct page_t
{
    using type = PageT;
};
template <class PageT>
inline constexpr page_t<PageT> page_v{};

// ============================================================
// app:统一的应用描述 + 发射器
// ============================================================
struct app
{
    std::string Name;
    std::string Icon;
    std::string Exec;
    std::function<void(app_launch_S *)> launch;

    // ① 外部命令
    app(std::string name,
        std::string icon,
        std::string exec,
        bool terminal);

    // ① 外部命令
    app(std::string name,
        std::string icon,
        std::string exec,
        bool terminal,
        bool sysplause);

    // ② 内置 UI 页面
    template <class PageT>
    app(std::string name,
        std::string icon,
        page_t<PageT> /*tag*/);
};

// ============================================================
// app_launch_S
// ============================================================
class app_launch_S
{
private:
    int current_app = 2;
    hal_watcher_t dir_watcher = NULL;
    lv_timer_t *watch_timer = nullptr;  // LVGL 3s 定时器
    lv_timer_t *status_timer = nullptr; // 状态栏刷新定时器
    lv_timer_t *nfc_automation_timer = nullptr;
    int fixed_count;
    nfc_app::NfcDeviceService nfc_automation_service_;
    static constexpr const char *kNfcAutomationCmdPath = "/tmp/applaunch_nfc_automation.cmd";
    static constexpr const char *kNfcAutomationStatusPath = "/tmp/applaunch_nfc_automation.status";

public:
    std::list<app> app_list;
    std::shared_ptr<void> app_Page;

public:
    app_launch_S()
    {
        // 固定图标，不允许用户修改
        app_list.emplace_back("RFID",
                              img_path("ic-rfid.png"), page_v<UINfcPage>);
        app_list.emplace_back("Python",
                              img_path("python_100.png"), "python3", true, false);
        app_list.emplace_back("STORE",
                              img_path("store_100.png"),
                              "/usr/share/APPLaunch/bin/M5CardputerZero-AppStore", false);
        app_list.emplace_back("CLI",
                              img_path("cli_100.png"), "bash", true, false);
        app_list.emplace_back("CLAW",
                              img_path("claw_100.png"), "/home/pi/zeroclaw agent", true);
        app_list.emplace_back("SETTING",
                              img_path("setting_100.png"), page_v<UISetupPage>);

        {
            auto it = std::next(app_list.begin(), 0);
            lv_label_set_text(ui_zuoLabelout, it->Name.c_str());
            panel_set_icon(ui_outPanelzuo, it->Icon.c_str());
        }
        {
            auto it = std::next(app_list.begin(), 1);
            lv_label_set_text(ui_zuoLabel, it->Name.c_str());
            panel_set_icon(ui_zuoPanel, it->Icon.c_str());
        }
        {
            auto it = std::next(app_list.begin(), 2);
            lv_label_set_text(ui_switchLabel, it->Name.c_str());
            panel_set_icon(ui_switchPanel, it->Icon.c_str());
        }
        {
            auto it = std::next(app_list.begin(), 3);
            lv_label_set_text(ui_youLabel, it->Name.c_str());
            panel_set_icon(ui_youPanel, it->Icon.c_str());
        }
        {
            auto it = std::next(app_list.begin(), 4);
            lv_label_set_text(ui_youLabelout, it->Name.c_str());
            panel_set_icon(ui_outPanelyou, it->Icon.c_str());
        }

        // 动态图标，根据 Settings 配置过滤
        #define APP_ENABLED(key) (hal_config_get_int("app_" key, 1) != 0)

        if (APP_ENABLED("Music"))
        app_list.emplace_back("MUSIC",
                              img_path("music_100.png"), page_v<UIMusicPage>);
        if (APP_ENABLED("Audio"))
        app_list.emplace_back("AUDIO",
                              img_path("audio_player_100.png"),
                              "tinyplay -D1 -d0 /home/pi/zhou.wav",
                              true);
        if (APP_ENABLED("Hack"))
        app_list.emplace_back("HACK",
                              img_path("hack_100.png"), page_v<UIHackPage>);
        if (APP_ENABLED("Game"))
        app_list.emplace_back("GAME",
                              img_path("game_100.png"), page_v<UIGamePage>);

        if (APP_ENABLED("Math"))
        app_list.emplace_back("MATH",
                              img_path("math_100.png"),
                              "/usr/share/APPLaunch/bin/M5CardputerZero-Calculator", false);

#if defined(__linux__) && !defined(HAL_PLATFORM_SDL)
        if (APP_ENABLED("IP_Panel"))
        app_list.emplace_back("IP_PANEL",
                              img_path("ip_panel_100.png"), page_v<UIIpPanelPage>);
        if (APP_ENABLED("Stocks"))
        app_list.emplace_back("STOCKS",
                              img_path("stocks_100.png"), page_v<UIStockPage>);
        if (APP_ENABLED("Chat"))
        app_list.emplace_back("CHAT",
                              img_path("chat_100.png"), page_v<UIchatPage>);
        if (APP_ENABLED("e-Mail"))
        app_list.emplace_back("e-Mail",
                              img_path("e_mail_100.png"), page_v<UIEmailPage>);
        if (APP_ENABLED("File"))
        app_list.emplace_back("FILE",
                              img_path("file_100.png"), page_v<UIFilePage>);
        if (APP_ENABLED("AICli"))
        app_list.emplace_back("AICli", img_path("aicli_100.png"), page_v<UIAICliPage>);
        if (APP_ENABLED("SSH"))
        app_list.emplace_back("SSH",
                              img_path("ssh_100.png"), page_v<UISSHPage>);
        if (APP_ENABLED("Mesh"))
        app_list.emplace_back("MESH",
                              img_path("mesh_100.png"), page_v<UIMeshPage>);
        if (APP_ENABLED("Rec"))
        app_list.emplace_back("REC",
                              img_path("rec_100.png"), page_v<UIRecPage>);
        if (APP_ENABLED("Camera"))
        app_list.emplace_back("CAMERA",
                              img_path("camera_100.png"), page_v<UICameraPage>);
        if (APP_ENABLED("UnitEnv"))
        app_list.emplace_back("UnitEnv",
                              img_path("unitenv_100.png"), page_v<UIUnitEnvPage>);
        if (APP_ENABLED("Midi"))
        app_list.emplace_back("Midi",
                              img_path("midi_100.png"), page_v<UIMidiPage>);
        if (APP_ENABLED("Gpio"))
        app_list.emplace_back("Gpio",
                              img_path("gpio_100.png"), page_v<UIGpioPage>);
        if (APP_ENABLED("LoRa"))
        app_list.emplace_back("LORA", img_path("lora_100.png"), page_v<UILoraPage>);
        if (APP_ENABLED("Gallery"))
        app_list.emplace_back("GALLERY", img_path("gallery_100.png"), page_v<UIGalleryPage>);
        if (APP_ENABLED("HikePod"))
        app_list.emplace_back("HIKEPOD", img_path("hikepod_100.png"), page_v<UIHikePodPage>);
        if (APP_ENABLED("Tank"))
        app_list.emplace_back("TANK", img_path("tank_100.png"), page_v<UITankBattlePage>);
        app_list.emplace_back("Love",
                                    img_path("game_100.png"), page_v<UILovyanPage>);
#endif
        #undef APP_ENABLED

        fixed_count = app_list.size();
        applications_load();

        // 初始化 inotify，监听 applications 目录
        inotify_init_watch();

        // 创建 LVGL 3s 定时器，周期性检查目录变化
        watch_timer = lv_timer_create(app_dir_watch_cb, 3000, this);

        // 状态栏定时刷新（时间 + 电量），每5秒更新一次
        update_home_status_bar();
        status_timer = lv_timer_create(home_status_timer_cb, 5000, this);
        nfc_automation_timer = lv_timer_create(nfc_automation_timer_cb, 200, this);

    }

    void launch_app()
    {
        auto it = std::next(app_list.begin(), current_app);
        it->launch(this);
    }

    static void lv_go_back_home(void *arg)
    {
        auto self = (app_launch_S *)arg;
        printf("[HOME] lv_go_back_home executing (page=%p)\n", self->app_Page.get());
        lv_timer_enable(true);
        lv_indev_set_group(lv_indev_get_next(NULL), Screen1group);
        lv_disp_load_scr(ui_Screen1);
        lv_refr_now(NULL);
        if (self->app_Page)
            self->app_Page.reset();
        printf("[HOME] lv_go_back_home done, on launcher home\n");
    }

    void go_back_home()
    {
        printf("[HOME] go_back_home() requested, scheduling async call (page=%p)\n", app_Page.get());
        lv_async_call(lv_go_back_home, this);
    }

    // 改为接收 std::string，不再依赖 app::Exec 成员
    void launch_Exec_in_terminal(const std::string &exec, bool sysplause = true)
    {
        printf("Launching terminal app: %s\n", exec.c_str());
        /* Instant visual feedback; paint before the (potentially slow)
         * Console page construction so the user sees it right away. */
        ui_loading_show("Loading...");
        lv_refr_now(NULL);
        auto p = std::make_shared<UIConsolePage>();
        app_Page = p;
        lv_disp_load_scr(p->get_ui());
        lv_indev_set_group(lv_indev_get_next(NULL), p->get_key_group());
        p->go_back_home = std::bind(&app_launch_S::go_back_home, this);
        p->terminal_sysplause = sysplause;
        /* Console page fully covers APP_Container; safe to hide now.
         * The heavy exec() call below will still run while the terminal
         * page is on-screen — no overlay needed at that point. */
        ui_loading_hide();
        p->exec(exec);
    }

    void launch_Exec(const std::string &exec)
    {
        printf("Launching external app: %s\n", exec.c_str());
        /* Show overlay BEFORE we tear down LVGL input/timers so the user
         * gets immediate feedback when ENTER was pressed. The overlay
         * stays drawn on the framebuffer right up until the child takes
         * it over via hal_process_exec_blocking(). */
        ui_loading_show("Loading...");
        lv_disp_t *disp = lv_disp_get_default();
        lv_indev_t *indev = lv_indev_get_next(NULL);
        LVGL_RUN_FLAGE = 0;
        if (indev)
            lv_indev_set_group(indev, NULL);
        lv_timer_enable(false);
        lv_refr_now(disp);

        int ret = hal_process_exec_blocking(exec.c_str(), &LVGL_HOME_KEY_FLAGE);
        printf("App %s exited with code %d\n", exec.c_str(), ret);
        lv_timer_enable(true);
        if (indev)
            lv_indev_set_group(indev, Screen1group);
        lv_disp_load_scr(ui_Screen1);
        /* Child process has returned; we are back on the launcher home.
         * Hide the overlay so it doesn't linger. */
        ui_loading_hide();
        lv_obj_invalidate(lv_screen_active());
        lv_refr_now(disp);
        LVGL_RUN_FLAGE = 1;
    }

    void zuo(lv_obj_t *panel, lv_obj_t *label)
    {
        current_app = current_app == (int)app_list.size() - 1 ? 0 : current_app + 1;
        int next_app = current_app;
        next_app = next_app == (int)app_list.size() - 1 ? 0 : next_app + 1;
        next_app = next_app == (int)app_list.size() - 1 ? 0 : next_app + 1;
        auto it = std::next(app_list.begin(), next_app);
        lv_label_set_text(label, it->Name.c_str());
        panel_set_icon(panel, it->Icon.c_str());
    }

    void you(lv_obj_t *panel, lv_obj_t *label)
    {
        current_app = current_app == 0 ? (int)app_list.size() - 1 : current_app - 1;
        int next_app = current_app;
        next_app = next_app == 0 ? (int)app_list.size() - 1 : next_app - 1;
        next_app = next_app == 0 ? (int)app_list.size() - 1 : next_app - 1;
        auto it = std::next(app_list.begin(), next_app);
        lv_label_set_text(label, it->Name.c_str());
        panel_set_icon(panel, it->Icon.c_str());
    }

    void applications_load()
    {
        const char *app_dir = hal_path_applications_dir();
        DIR *dir = opendir(app_dir);
        if (!dir)
        {
            perror("applications_load: opendir failed");
            return;
        }

        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL)
        {
            // 仅处理 *.desktop 文件
            const char *name = entry->d_name;
            size_t len = strlen(name);
            if (len <= 8 || strcmp(name + len - 8, ".desktop") != 0)
                continue;

            std::string filepath = std::string(app_dir) + "/" + name;
            std::ifstream ifs(filepath);
            if (!ifs.is_open())
            {
                fprintf(stderr, "applications_load: cannot open %s\n", filepath.c_str());
                continue;
            }

            // 解析 INI 文件
            std::string app_name, app_icon, app_exec;
            bool app_terminal = false;
            bool app_sysplause = true;
            bool in_desktop_entry = false;

            std::string line;
            while (std::getline(ifs, line))
            {
                // 去除行尾的 \r（Windows 换行符）
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();

                // 跳过空行和注释
                if (line.empty() || line[0] == '#' || line[0] == ';')
                    continue;

                // 检测节头
                if (line[0] == '[')
                {
                    in_desktop_entry = (line == "[Desktop Entry]");
                    continue;
                }

                if (!in_desktop_entry)
                    continue;

                // 解析 key=value
                auto eq = line.find('=');
                if (eq == std::string::npos)
                    continue;

                std::string key = line.substr(0, eq);
                std::string value = line.substr(eq + 1);

                // 去除 key 首尾空格
                auto ltrim = [](std::string &s)
                {
                    size_t i = 0;
                    while (i < s.size() && (s[i] == ' ' || s[i] == '\t'))
                        ++i;
                    s = s.substr(i);
                };
                auto rtrim = [](std::string &s)
                {
                    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
                        s.pop_back();
                };
                ltrim(key);
                rtrim(key);
                ltrim(value);
                rtrim(value);

                if (key == "Name")
                    app_name = value;
                else if (key == "Icon")
                    app_icon = value;
                else if (key == "Exec")
                    app_exec = value;
                else if (key == "Terminal")
                    app_terminal = (value == "true" || value == "True" || value == "1");
                else if (key == "Sysplause")
                    app_sysplause = (value == "true" || value == "True" || value == "1");
            }

            // 必须有 Name 和 Exec 才能注册
            if (app_name.empty() || app_exec.empty())
            {
                fprintf(stderr, "applications_load: skip %s (missing Name or Exec)\n", filepath.c_str());
                continue;
            }
            bool in_list = false;
            for (const auto &it : app_list)
            {
                if ((!it.Exec.empty() && it.Exec == app_exec) || it.Name == app_name)
                {
                    in_list = true;
                    break;
                }
            }
            if (in_list)
            {
                fprintf(stderr, "applications_load: skip %s (duplicate Name/Exec)\n", filepath.c_str());
                continue;
            }

            app_list.emplace_back(app_name, app_icon, app_exec, app_terminal, app_sysplause);
        }

        closedir(dir);
    }

    // ============================================================
    // inotify 初始化：以非阻塞模式监听 applications 目录
    // ============================================================
    void inotify_init_watch()
    {
        dir_watcher = hal_dir_watch_start(hal_path_applications_dir());
    }

    // ============================================================
    // 刷新 UI 面板（根据当前 current_app 更新 5 个槽位）
    // ============================================================
    void refresh_ui_panels()
    {
        int sz = (int)app_list.size();
        if (sz == 0)
            return;

        // 确保 current_app 在合法范围内
        if (current_app >= sz)
            current_app = sz - 1;

        auto app_at = [&](int idx) -> app &
        {
            idx = ((idx % sz) + sz) % sz;
            return *std::next(app_list.begin(), idx);
        };

        // 最左外（隐藏）
        {
            auto &a = app_at(current_app - 2);
            lv_label_set_text(ui_zuoLabelout, a.Name.c_str());
            panel_set_icon(ui_outPanelzuo, a.Icon.c_str());
        }
        // 左
        {
            auto &a = app_at(current_app - 1);
            lv_label_set_text(ui_zuoLabel, a.Name.c_str());
            panel_set_icon(ui_zuoPanel, a.Icon.c_str());
        }
        // 中心
        {
            auto &a = app_at(current_app);
            lv_label_set_text(ui_switchLabel, a.Name.c_str());
            panel_set_icon(ui_switchPanel, a.Icon.c_str());
        }
        // 右
        {
            auto &a = app_at(current_app + 1);
            lv_label_set_text(ui_youLabel, a.Name.c_str());
            panel_set_icon(ui_youPanel, a.Icon.c_str());
        }
        // 最右外（隐藏）
        {
            auto &a = app_at(current_app + 2);
            lv_label_set_text(ui_youLabelout, a.Name.c_str());
            panel_set_icon(ui_outPanelyou, a.Icon.c_str());
        }
    }

    // ============================================================
    // 重新加载动态应用列表（保留固定条目，重扫描 applications 目录）
    // ============================================================
    void applications_reload()
    {
        int sz = (int)app_list.size();
        if (sz > fixed_count)
        {
            auto it = std::next(app_list.begin(), fixed_count);
            app_list.erase(it, app_list.end());
        }
        applications_load();
        refresh_ui_panels();
    }

    // ============================================================
    // 主页状态栏刷新：时间 + 电量（BQ27220）
    // ============================================================
    static void home_status_timer_cb(lv_timer_t *timer)
    {
        auto *self = static_cast<app_launch_S *>(lv_timer_get_user_data(timer));
        if (self)
            self->update_home_status_bar();
    }

    void update_home_status_bar()
    {
        // WiFi signal bars: show/hide + color by strength
        hal_wifi_status_t wifi = hal_wifi_get_status();
        if (wifi.connected) {
            lv_obj_clear_flag(ui_wifiPanel, LV_OBJ_FLAG_HIDDEN);
            int sig = wifi.signal;
            uint32_t on_color  = 0x33CC33;
            uint32_t off_color = 0x4D4D4D;
            lv_obj_set_style_bg_color(ui_wifiBar1, lv_color_hex(sig > 0 ? on_color : off_color), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(ui_wifiBar2, lv_color_hex(sig >= 30 ? on_color : off_color), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(ui_wifiBar3, lv_color_hex(sig >= 60 ? on_color : off_color), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_color(ui_wifiBar4, lv_color_hex(sig >= 80 ? on_color : off_color), LV_PART_MAIN | LV_STATE_DEFAULT);
        } else {
            lv_obj_add_flag(ui_wifiPanel, LV_OBJ_FLAG_HIDDEN);
        }

        // Time
        char time_buf[16];
        hal_time_str(time_buf, sizeof(time_buf));
        lv_label_set_text(ui_timeLabel, time_buf);

        // Battery
        hal_battery_info_t bat = hal_battery_read();
        if (bat.valid)
        {
            int soc = bat.soc;
            if (soc > 100)
                soc = 100;
            if (soc < 0)
                soc = 0;
            lv_bar_set_value(ui_Bar1, soc, LV_ANIM_ON);

            char pwr_buf[16];
            snprintf(pwr_buf, sizeof(pwr_buf), "%d%%", soc);
            lv_label_set_text(ui_powerLabel, pwr_buf);
            if (soc == 100)
                lv_obj_set_style_text_font(ui_powerLabel, &lv_font_montserrat_10, LV_PART_MAIN | LV_STATE_DEFAULT);
            else
                lv_obj_set_style_text_font(ui_powerLabel, LV_FONT_DEFAULT, LV_PART_MAIN | LV_STATE_DEFAULT);
        }
    }

    // ============================================================
    // LVGL 定时器回调：检测 inotify 事件，有变化则刷新列表
    // ============================================================
    static void app_dir_watch_cb(lv_timer_t *timer)
    {
        auto *self = static_cast<app_launch_S *>(lv_timer_get_user_data(timer));
        if (!self || !self->dir_watcher)
            return;

        if (hal_dir_watch_poll(self->dir_watcher) > 0)
        {
            printf("app_dir_watch_cb: applications dir changed, reloading...\n");
            self->applications_reload();
        }
    }

    static std::string trim_ascii(const std::string &in)
    {
        size_t begin = 0;
        while (begin < in.size() && std::isspace(static_cast<unsigned char>(in[begin]))) ++begin;
        size_t end = in.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(in[end - 1]))) --end;
        return in.substr(begin, end - begin);
    }

    static std::string upper_ascii(std::string text)
    {
        for (char &ch : text) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        return text;
    }

    static int nfc_profile_index_from_token(const std::string &token)
    {
        std::string out;
        out.reserve(token.size());
        for (unsigned char ch : token) {
            if (std::isalnum(ch)) out.push_back(static_cast<char>(std::toupper(ch)));
        }
        if (out == "NTAG" || out == "NTAG213" || out == "ISO14443A" || out == "NFCA") return 0;
        if (out == "MIFARE" || out == "MIFARE1K" || out == "MIFARECLASSIC" || out == "MIFARECLASSIC1K" || out == "MFC") return 1;
        if (out == "ISO15693" || out == "NFCV") return 2;
        return -1;
    }

    static int spi_profile_index_from_token(const std::string &token)
    {
        std::string out;
        out.reserve(token.size());
        for (unsigned char ch : token) {
            if (std::isalnum(ch)) out.push_back(static_cast<char>(std::toupper(ch)));
        }
        if (out == "MIFARE" || out == "MIFARE1K" || out == "MIFARECLASSIC" || out == "MIFARECLASSIC1K" || out == "MFC" || out == "MFC1K") return 0;
        if (out == "NTAG" || out == "NTAG215" || out == "ISO14443A" || out == "NFCA") return 1;
        if (out == "NTAG216") return 2;
        return -1;
    }

    static bool is_iso15693_token(const std::string &token)
    {
        std::string out;
        out.reserve(token.size());
        for (unsigned char ch : token) {
            if (std::isalnum(ch)) out.push_back(static_cast<char>(std::toupper(ch)));
        }
        return (out == "ISO15693" || out == "NFCV");
    }

    void write_nfc_automation_status(const std::string &line) const
    {
        std::ofstream out(kNfcAutomationStatusPath, std::ios::trunc);
        if (!out.good()) return;
        out << line << '\n';
    }

    bool pop_nfc_automation_command(std::string *command)
    {
        if (!command) return false;
        std::ifstream in(kNfcAutomationCmdPath);
        if (!in.good()) return false;
        std::string line;
        std::getline(in, line);
        in.close();
        std::remove(kNfcAutomationCmdPath);
        line = trim_ascii(line);
        if (line.empty()) return false;
        *command = line;
        return true;
    }

    bool ensure_nfcunit_connected_for_automation(std::string *error)
    {
        auto conn = nfc_automation_service_.connection_state();
        if (conn.connected && conn.device_kind == nfc_app::DeviceKind::NFCUnit) return true;

        auto i2c_endpoints = nfc_automation_service_.scan_i2c_devices();
        if (i2c_endpoints.empty()) {
            if (error) *error = "No NFC Unit I2C endpoint";
            return false;
        }

        size_t pick = 0;
        for (size_t i = 0; i < i2c_endpoints.size(); ++i) {
            if (i2c_endpoints[i].path.find(":0x50") != std::string::npos) {
                pick = i;
                break;
            }
        }

        nfc_automation_service_.select_i2c_endpoint(i2c_endpoints[pick]);
        if (!nfc_automation_service_.connect_current()) {
            conn = nfc_automation_service_.connection_state();
            if (error) *error = conn.detail.empty() ? "NFC Unit connect failed" : conn.detail;
            return false;
        }

        conn = nfc_automation_service_.connection_state();
        if (!conn.connected || conn.device_kind != nfc_app::DeviceKind::NFCUnit) {
            if (error) *error = "Connected device is not NFC Unit";
            return false;
        }
        return true;
    }

    bool ensure_spi_connected_for_automation(const std::string &path, std::string *error)
    {
        const std::string spi_path = path.empty() ? "/dev/spidev0.2" : path;
        auto conn = nfc_automation_service_.connection_state();
        if (conn.connected &&
            conn.endpoint.kind == nfc_app::TransportKind::SpiBus &&
            conn.endpoint.path == spi_path) {
            return true;
        }

        nfc_app::TransportEndpoint ep;
        ep.kind = nfc_app::TransportKind::SpiBus;
        ep.path = spi_path;
        ep.label = "SPI " + spi_path;
        nfc_automation_service_.select_spi_endpoint(ep);

        if (!nfc_automation_service_.connect_current()) {
            conn = nfc_automation_service_.connection_state();
            if (error) *error = conn.detail.empty() ? "SPI connect failed" : conn.detail;
            return false;
        }
        if (error) error->clear();
        return true;
    }

    void process_nfc_automation_command()
    {
        std::string command;
        if (!pop_nfc_automation_command(&command)) return;

        std::istringstream iss(command);
        std::string verb;
        iss >> verb;
        const std::string verb_upper = upper_ascii(verb);

        auto emit_ok = [this](const std::string &line) {
            write_nfc_automation_status("OK " + line);
        };
        auto emit_err = [this](const std::string &line) {
            write_nfc_automation_status("ERR " + line);
        };

        if (verb_upper == "STATUS") {
            const auto conn = nfc_automation_service_.connection_state();
            std::ostringstream oss;
            oss << "status connected=" << (conn.connected ? 1 : 0)
                << " device=" << nfc_app::to_string(conn.device_kind)
                << " profile=" << nfc_automation_service_.nfcunit_profile_label()
                << " running=" << (nfc_automation_service_.nfcunit_emulation_running() ? 1 : 0)
                << " nfc_profile=" << nfc_automation_service_.nfcunit_profile_label()
                << " nfc_running=" << (nfc_automation_service_.nfcunit_emulation_running() ? 1 : 0)
                << " spi_profile=" << nfc_automation_service_.spi_profile_label()
                << " spi_running=" << (nfc_automation_service_.spi_listener_active() ? 1 : 0)
                << " spi_iso15693_emu=" << (nfc_automation_service_.spi_supports_iso15693_emulation() ? 1 : 0);
            emit_ok(oss.str());
            return;
        }

        if (verb_upper == "SPI_CAPS") {
            emit_ok(nfc_automation_service_.spi_caps_status_line());
            return;
        }

        if (verb_upper == "STOP") {
            nfc_automation_service_.spi_stop_listener();
            const bool ok = nfc_automation_service_.grovenfc_deactivate();
            if (ok) emit_ok("stop emulation");
            else emit_err("stop failed");
            return;
        }

        std::string arg;
        std::getline(iss, arg);
        arg = trim_ascii(arg);

        if (verb_upper == "PROFILE") {
            const int profile = nfc_profile_index_from_token(arg);
            if (profile < 0) {
                emit_err("unknown profile: " + arg);
                return;
            }
            nfc_automation_service_.set_nfcunit_profile_index(profile);
            emit_ok("profile=" + nfc_automation_service_.nfcunit_profile_label());
            return;
        }

        if (verb_upper == "SPI_PROFILE") {
            if (is_iso15693_token(arg)) {
                emit_err("SPI ISO15693 emulation requires transparent GPIO timing");
                return;
            }
            const int profile = spi_profile_index_from_token(arg);
            if (profile < 0) {
                emit_err("unknown spi profile: " + arg);
                return;
            }
            nfc_automation_service_.set_spi_profile_index(profile);
            emit_ok("spi_profile=" + nfc_automation_service_.spi_profile_label());
            return;
        }

        if (verb_upper == "START" || verb_upper == "RUN") {
            int run_profile = -1;
            if (verb_upper == "RUN") {
                run_profile = nfc_profile_index_from_token(arg);
                if (run_profile < 0) {
                    emit_err("unknown profile: " + arg);
                    return;
                }
            }

            std::string err;
            if (run_profile >= 0 && run_profile != nfc_automation_service_.nfcunit_profile_index()) {
                (void)nfc_automation_service_.grovenfc_deactivate();
                nfc_automation_service_.disconnect();
            }
            if (!ensure_nfcunit_connected_for_automation(&err)) {
                emit_err(err.empty() ? "connect failed" : err);
                return;
            }
            if (run_profile >= 0) {
                nfc_automation_service_.set_nfcunit_profile_index(run_profile);
            }
            if (nfc_automation_service_.start_nfcunit_current_profile_emulation(&err)) {
                std::ostringstream oss;
                oss << "run profile=" << nfc_automation_service_.nfcunit_profile_label()
                    << " running=" << (nfc_automation_service_.nfcunit_emulation_running() ? 1 : 0);
                emit_ok(oss.str());
            } else {
                emit_err(err.empty() ? "start failed" : err);
            }
            return;
        }

        if (verb_upper == "SCAN") {
            std::string status;
            if (nfc_automation_service_.connect_and_scan(&status)) {
                emit_ok(status.empty() ? "scan started" : status);
            } else {
                emit_err(status.empty() ? "scan failed" : status);
            }
            return;
        }

        if (verb_upper == "SPI_RUN") {
            std::istringstream args_ss(arg);
            std::string token1;
            std::string token2;
            args_ss >> token1 >> token2;

            int run_profile = -1;
            bool run_iso15693 = false;
            std::string spi_path = "/dev/spidev0.2";
            if (!token1.empty()) {
                const int p = spi_profile_index_from_token(token1);
                if (p >= 0) {
                    run_profile = p;
                    if (!token2.empty()) spi_path = token2;
                } else if (is_iso15693_token(token1)) {
                    run_iso15693 = true;
                    if (!token2.empty()) spi_path = token2;
                } else {
                    spi_path = token1;
                }
            }

            std::string err;
            if (!ensure_spi_connected_for_automation(spi_path, &err)) {
                emit_err(err.empty() ? "SPI connect failed" : err);
                return;
            }
            if (run_profile >= 0) {
                nfc_automation_service_.set_spi_profile_index(run_profile);
            }
            if (run_iso15693) {
                if (!nfc_automation_service_.spi_start_iso15693_emulation(&err)) {
                    emit_err(err.empty() ? "SPI ISO15693 emulation unsupported" : err);
                    return;
                }
                emit_ok("spi run profile=ISO15693 running=1");
                return;
            }
            if (!nfc_automation_service_.spi_start_current_profile(&err)) {
                emit_err(err.empty() ? "spi emu start failed" : err);
                return;
            }

            std::ostringstream oss;
            oss << "spi run profile=" << nfc_automation_service_.spi_profile_label()
                << " running=" << (nfc_automation_service_.spi_listener_active() ? 1 : 0);
            emit_ok(oss.str());
            return;
        }

        if (verb_upper == "SCAN_SPI") {
            const std::string spi_path = arg.empty() ? "/dev/spidev0.2" : arg;

            nfc_app::TransportEndpoint ep;
            ep.kind = nfc_app::TransportKind::SpiBus;
            ep.path = spi_path;
            ep.label = "SPI " + spi_path;
            nfc_automation_service_.select_spi_endpoint(ep);

            if (!nfc_automation_service_.connect_current()) {
                const auto conn = nfc_automation_service_.connection_state();
                emit_err(conn.detail.empty() ? "SPI connect failed" : conn.detail);
                return;
            }

            if (!nfc_automation_service_.start_scan()) {
                const auto scan = nfc_automation_service_.scan_state();
                const std::string msg = scan.error.empty() ? scan.status : scan.error;
                emit_err(msg.empty() ? "SPI scan start failed" : msg);
                return;
            }

            const auto deadline = std::chrono::steady_clock::now() +
                                  std::chrono::milliseconds(2500);
            while (std::chrono::steady_clock::now() < deadline) {
                const auto scan = nfc_automation_service_.scan_state();
                if (!scan.running) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
            }

            const auto scan = nfc_automation_service_.scan_state();
            if (scan.running) {
                emit_err("SPI scan timeout");
            } else if (scan.has_result) {
                std::ostringstream oss;
                oss << "SPI card found uid=" << scan.last_record.tag.uid;
                emit_ok(oss.str());
            } else {
                const std::string msg = scan.error.empty() ? scan.status : scan.error;
                emit_err(msg.empty() ? "SPI no card" : msg);
            }
            return;
        }

        // GEN1A [spi_path]
        // Scan card on SPI HAT, detect Gen1A magic, dump all 64 blocks.
        if (verb_upper == "GEN1A") {
            const std::string spi_path = arg.empty() ? "/dev/spidev0.2" : arg;

            nfc_app::TransportEndpoint ep;
            ep.kind  = nfc_app::TransportKind::SpiBus;
            ep.path  = spi_path;
            ep.label = "SPI " + spi_path;
            nfc_automation_service_.select_spi_endpoint(ep);

            if (!nfc_automation_service_.connect_current()) {
                const auto conn = nfc_automation_service_.connection_state();
                emit_err(conn.detail.empty() ? "SPI connect failed" : conn.detail);
                return;
            }

            nfc_app::I2cCardInfo card_info;
            std::vector<std::vector<uint8_t>> blocks;
            std::string gen1a_err;

            const bool ok = nfc_automation_service_.spi_scan_gen1a(&blocks, &card_info, &gen1a_err);
            if (!ok) {
                emit_err(gen1a_err.empty() ? "gen1a failed" : gen1a_err);
                return;
            }

            std::ostringstream oss;
            oss << "gen1a uid=" << card_info.uid;
            for (int blk = 0; blk < static_cast<int>(blocks.size()); ++blk) {
                oss << "\n" << blk << ":";
                for (uint8_t b : blocks[blk]) {
                    char hex[3];
                    std::snprintf(hex, sizeof(hex), "%02X", b);
                    oss << " " << hex;
                }
            }
            if (!gen1a_err.empty()) oss << "\n# " << gen1a_err;
            emit_ok(oss.str());
            return;
        }

        // SPI_EMU_START [uid_hex] [atqa_hex] [sak_hex] [spi_path]
        //   uid_hex : 8 or 14 hex digits (4 or 7 bytes)
        //   atqa_hex: 4 hex digits (e.g. 0004, 0042)
        //   sak_hex : 2 hex digits
        //   spi_path: optional, default /dev/spidev0.2
        // Or SPI_EMU_START [profile] [spi_path], e.g. SPI_EMU_START NTAG216
        // Example: SPI_EMU_START 01020304 0004 08
        if (verb_upper == "SPI_EMU_START") {
            // Parse arguments: uid atqa sak [path]
            std::istringstream args_ss(arg);
            std::string uid_hex, atqa_hex, sak_hex, emu_path;
            args_ss >> uid_hex >> atqa_hex >> sak_hex >> emu_path;

            if (is_iso15693_token(uid_hex)) {
                const std::string iso_path = atqa_hex.empty() ? "/dev/spidev0.2" : atqa_hex;
                std::string emu_err;
                if (!ensure_spi_connected_for_automation(iso_path, &emu_err)) {
                    emit_err(emu_err.empty() ? "SPI connect failed" : emu_err);
                    return;
                }
                if (!nfc_automation_service_.spi_start_iso15693_emulation(&emu_err)) {
                    emit_err(emu_err.empty() ? "SPI ISO15693 emulation unsupported" : emu_err);
                    return;
                }
                emit_ok("spi emu started profile=ISO15693");
                return;
            }

            const int profile = spi_profile_index_from_token(uid_hex);
            if (profile >= 0) {
                const std::string profile_path = atqa_hex.empty() ? "/dev/spidev0.2" : atqa_hex;
                std::string emu_err;
                if (!ensure_spi_connected_for_automation(profile_path, &emu_err)) {
                    emit_err(emu_err.empty() ? "SPI connect failed" : emu_err);
                    return;
                }
                nfc_automation_service_.set_spi_profile_index(profile);
                if (!nfc_automation_service_.spi_start_current_profile(&emu_err)) {
                    emit_err(emu_err.empty() ? "spi emu start failed" : emu_err);
                    return;
                }

                std::ostringstream oss;
                oss << "spi emu started profile=" << nfc_automation_service_.spi_profile_label();
                emit_ok(oss.str());
                return;
            }

            if (emu_path.empty()) emu_path = "/dev/spidev0.2";

            auto hex_to_bytes = [](const std::string &hex) -> std::vector<uint8_t> {
                std::vector<uint8_t> out;
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    char buf[3] = {hex[i], hex[i+1], '\0'};
                    out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
                }
                return out;
            };

            const auto uid_bytes = hex_to_bytes(uid_hex);
            if (uid_bytes.size() != 4 && uid_bytes.size() != 7) {
                emit_err("SPI_EMU_START: uid must be 4 or 7 bytes (8 or 14 hex digits)");
                return;
            }
            if (atqa_hex.size() < 4) {
                emit_err("SPI_EMU_START: atqa must be 4 hex digits");
                return;
            }
            if (sak_hex.size() < 2) {
                emit_err("SPI_EMU_START: sak must be 2 hex digits");
                return;
            }

            char *atqa_end = nullptr;
            const unsigned long atqa_ul = std::strtoul(atqa_hex.c_str(), &atqa_end, 16);
            if (atqa_end == nullptr || *atqa_end != '\0' || atqa_ul > 0xFFFFul) {
                emit_err("SPI_EMU_START: invalid atqa value");
                return;
            }
            const uint16_t atqa = static_cast<uint16_t>(atqa_ul);
            const uint8_t sak = hex_to_bytes(sak_hex)[0];

            std::string connect_err;
            if (!ensure_spi_connected_for_automation(emu_path, &connect_err)) {
                emit_err(connect_err.empty() ? "SPI connect failed" : connect_err);
                return;
            }

            std::string emu_err;
            if (!nfc_automation_service_.spi_start_listener_a(uid_bytes, atqa, sak, &emu_err)) {
                emit_err(emu_err.empty() ? "spi emu start failed" : emu_err);
                return;
            }

            std::ostringstream oss;
            oss << "spi emu started uid=" << uid_hex << " atqa=" << atqa_hex << " sak=" << sak_hex;
            emit_ok(oss.str());
            return;
        }

        if (verb_upper == "SPI_EMU_STOP") {
            nfc_automation_service_.spi_stop_listener();
            emit_ok("spi emu stopped");
            return;
        }

        emit_err("unknown command: " + command);
    }

    static void nfc_automation_timer_cb(lv_timer_t *timer)
    {
        auto *self = static_cast<app_launch_S *>(lv_timer_get_user_data(timer));
        if (!self) return;
        self->process_nfc_automation_command();
    }

    ~app_launch_S();
};

// ============================================================
// app 构造函数的实现(放到 app_launch_S 定义之后)
// ============================================================
inline app::app(std::string name,
                std::string icon,
                std::string exec,
                bool terminal)
    : Name(std::move(name)), Icon(std::move(icon))
{
    launch = [exec = std::move(exec), terminal](app_launch_S *ctx)
    {
        if (terminal)
            ctx->launch_Exec_in_terminal(exec);
        else
            ctx->launch_Exec(exec);
    };
}

inline app::app(std::string name,
                std::string icon,
                std::string exec,
                bool terminal,
                bool sysplause)
    : Name(std::move(name)), Icon(std::move(icon))
{
    launch = [exec = std::move(exec), terminal, sysplause](app_launch_S *ctx)
    {
        if (terminal)
            ctx->launch_Exec_in_terminal(exec, sysplause);
        else
            ctx->launch_Exec(exec);
    };
}

template <class PageT>
app::app(std::string name,
         std::string icon,
         page_t<PageT> /*tag*/)
    : Name(std::move(name)), Icon(std::move(icon))
{
    launch = [](app_launch_S *self)
    {
        /* Instant feedback: show the overlay, then force an immediate
         * redraw so it actually paints BEFORE the (sometimes slow) page
         * construction starts. Without lv_refr_now() the overlay would
         * only hit the framebuffer after the constructor returns, which
         * defeats the whole point. */
        ui_loading_show("Loading...");
        lv_refr_now(NULL);
        auto p = std::make_shared<PageT>();
        self->app_Page = p;
        lv_disp_load_scr(p->get_ui());
        lv_indev_set_group(lv_indev_get_next(NULL),
                           p->get_key_group());
        p->go_back_home =
            std::bind(&app_launch_S::go_back_home, self);
        /* Page is now attached and drawable; hide the overlay. The
         * next LVGL frame will paint the new page without it. */
        ui_loading_hide();
    };
}

// ============================================================
// app_launch_S 析构函数实现
// ============================================================
app_launch_S::~app_launch_S()
{
    if (nfc_automation_timer)
    {
        lv_timer_delete(nfc_automation_timer);
        nfc_automation_timer = nullptr;
    }
    if (status_timer)
    {
        lv_timer_delete(status_timer);
        status_timer = nullptr;
    }
    if (watch_timer)
    {
        lv_timer_delete(watch_timer);
        watch_timer = nullptr;
    }
    if (dir_watcher)
    {
        hal_dir_watch_stop(dir_watcher);
        dir_watcher = NULL;
    }
}

// ============================================================
std::unique_ptr<app_launch_S> app_launch_Ser;

extern "C"
{

    void ui_info_bind()
    {
        app_launch_Ser = std::make_unique<app_launch_S>();
    }
    void cpp_app_zuo(lv_obj_t *panel, lv_obj_t *label)
    {
        app_launch_Ser->zuo(panel, label);
    }
    void cpp_app_you(lv_obj_t *panel, lv_obj_t *label)
    {
        app_launch_Ser->you(panel, label);
    }
    void cpp_app_launch()
    {
        app_launch_Ser->launch_app();
    }
}
