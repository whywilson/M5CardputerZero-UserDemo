#include "../hal_paths.h"
#include "../hal_process.h"
#include "../hal_pty.h"
#include "../hal_filesystem.h"
#include "../hal_network.h"

/* Paths */
void        hal_paths_init(const char *d) { (void)d; }
const char *hal_path_data_dir(void)         { return "/"; }
const char *hal_path_applications_dir(void) { return "/applications"; }
const char *hal_path_store_cache_dir(void)  { return "/store_cache"; }
const char *hal_path_lock_file(void)        { return "/tmp/lock"; }
const char *hal_path_font_dir(void)         { return "/font"; }
const char *hal_path_font_regular(void)     { return "/font/regular.ttf"; }
const char *hal_path_font_mono(void)        { return "/font/mono.ttf"; }
const char *hal_path_keyboard_device(void)  { return 0; }
const char *hal_path_keyboard_map(void)     { return 0; }
const char *hal_path_store_sync_cmd(void)   { return ""; }
const char *hal_path_nfc_dumps_dir(void)    { return "/nfc_data/records"; }

/* Process */
int  hal_process_exec_blocking(const char *p, volatile int *f) { (void)p; (void)f; return -1; }
int  hal_process_check_lock(const char *p, int *pid) { (void)p; *pid = 0; return 0; }
void hal_process_kill(int pid, int g) { (void)pid; (void)g; }

/* PTY */
hal_pty_t hal_pty_open(const char *c, const char *const *a, int co, int ro) { (void)c; (void)a; (void)co; (void)ro; return 0; }
int       hal_pty_read(hal_pty_t p, char *b, size_t s) { (void)p; (void)b; (void)s; return -1; }
int       hal_pty_write(hal_pty_t p, const char *b, size_t l) { (void)p; (void)b; (void)l; return -1; }
int       hal_pty_check_child(hal_pty_t p, int *e) { (void)p; (void)e; return -1; }
void      hal_pty_close(hal_pty_t p) { (void)p; }

/* Filesystem */
int           hal_dir_list(const char *p, hal_dirent_t *e, int m, int *c) { (void)p; (void)e; (void)m; *c = 0; return -1; }
hal_watcher_t hal_dir_watch_start(const char *p) { (void)p; return 0; }
int           hal_dir_watch_poll(hal_watcher_t w) { (void)w; return 0; }
void          hal_dir_watch_stop(hal_watcher_t w) { (void)w; }

/* Network */
int hal_network_list(hal_netif_info_t *e, int m, int *c) { (void)e; (void)m; *c = 0; return 0; }
