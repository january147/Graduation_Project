#ifndef EVMONITOR_HEADFILE
#define EVMONITOR_HEADFILE
#include<cstddef>
namespace art{
//EvMonitor--native
class EvMonitor {
  public:
    // log file max set to 4M
    const static int LOG_MAX = 4 * 1024 * 1024;
    const static int LOG_FILE_MAX = 100;
    std::string app_root;
    std::string log_dir_root;
    std::string current_log_dir;
    std::string target_app_name;
    std::string file_dump_dir;

    bool monitor_enabled = false;
    bool embeded_log_enabled = false;
    bool not_report_full = true;
    bool dex_dump_enabled = false;
    
    char* log_base = NULL;
    char* log_data = NULL;
    volatile int log_spare_space = LOG_MAX;
    volatile int log_file_amount = 0;

    std::mutex mutex_lock;

    EvMonitor();
    void setTargetApp(std::string app_name);
    void enableMonitor(bool enable);
    bool enableEmbedLog(bool enable); 
    bool enableDexDump(bool enable);

    void log(const char* tag, const char* log);
    void writeLog();
    void dumpDex(const void* base, long size);
    inline bool dumpFile(const void* buff, long size, std::string file_path);

    std::string getTime();
    std::string getRandomStr(int len);

  private:
    bool setLogFilePath();
};
}
#endif