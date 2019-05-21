#ifndef EVMONITOR_HEADFILE
#define EVMONITOR_HEADFILE
#include<cstddef>
#include "em_agent.h"

#define LOG_MAX  4*1024*1024
#define LOG_FILE_MAX 100
#define CMD_MAX_LEN  50
#define DISCONNECTED -1
namespace art{
//EvMonitor--native
class EvMonitor {
  public:
    // log buff set to 4M

    // state
    bool not_report_full = true;
    bool agent_connected = false;
    
    // config
    CONFIG config_buff;
    bool monitor_enabled = false;
    bool embeded_log_enabled = false;
    bool dex_dump_enabled = false;
    bool remote_ctrl_enabled = false;
    bool only_native = false;
    bool only_method_name = false;

    // config file for EvMonitor
    std::string config_file_path;
    // the dir app can access
    std::string app_root;
    // the root log file dir
    std::string log_dir_root;
    // the log file dir for this execution
    std::string current_log_dir;
    // app name
    std::string target_app_name;
    // the dir for extra file EvMonitor creates
    std::string file_dump_dir_root;
    std::string file_dump_dir;

    // log system
    char* log_base = NULL;
    char* log_data = NULL;
    volatile int log_spare_space = LOG_MAX;
    volatile int log_file_amount = 0;

    // remote control
    int rm_sock = DISCONNECTED;
    std::string agent_sock_path = "/data/local/tmp/EvMonitor_agent/sock";
    
    std::mutex mutex_lock;

    EvMonitor();
    void init(std::string app_name);
    void setTargetApp(std::string app_name);
    bool enableMonitor(bool enable);
    bool enableEmbedLog(bool enable); 
    bool enableDexDump(bool enable);
    bool enableRemoteCtrl(bool enable);
    bool connectToAgent(bool enable);
    bool readConfigFromAgent();

    void log(const char* tag, const char* log);
    bool writeLog();
    void dumpDex(const void* base, long size);
    

    //utils
    std::string getTime();
    std::string getRandomStr(int len);

  private:
    bool setLogFilePath();
    bool setDumpFilePath();
    inline bool dumpFile(const void* buff, long size, std::string file_path);
    
};

void* commandHandler(void* args);
}
#endif