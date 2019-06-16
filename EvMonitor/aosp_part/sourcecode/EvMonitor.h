#ifndef EVMONITOR_HEADFILE
#define EVMONITOR_HEADFILE
#include <cstddef>
#include "base/bit_utils.h"
#include "base/casts.h"
#include "base/enums.h"
#include "base/logging.h"
#include "dex_file.h"
#include "gc_root.h"
#include "modifiers.h"
#include "obj_ptr.h"
#include "offsets.h"
#include "primitive.h"
#include "read_barrier_option.h"
// 包含了从EvMonitor_agent读取的配置结构体定义
#include "em_agent.h"

// log buff set to 4M
#define LOG_MAX  4*1024*1024
// 单次运行日志文件最大数量设置为100
#define LOG_FILE_MAX 100
// 远程控制命令最大长度设置为50
#define CMD_MAX_LEN  50
#define DISCONNECTED -1
#define TRUE 1
#define FALSE 0
#define UNKNOWN -1

// 输出DEBUG信息
#define EM_DEBUG
// 宏函数
#define gettid() syscall(SYS_gettid)
#define getpid() syscall(SYS_getpid)
#define EMLOGE(log_info, ...) __android_log_print(ANDROID_LOG_ERROR, "EvMonitor", log_info, ##__VA_ARGS__)
#define EMLOGD(log_info, ...) __android_log_print(ANDROID_LOG_DEBUG, "EvMonitor", log_info, ##__VA_ARGS__)
#define ISCMD(cmd_str) (strcmp(cmd, cmd_str) == 0)

namespace art{
//EvMonitor--native
class EvMonitor {
  public:
    // config
    // 从EvMonitor_agent接收的配置信息结构体
    CONFIG config_buff;
    // 是否启动监控
    bool monitor_enabled = false;
    // 是否连接到EvMonitor_agent
    bool agent_connected = false;
    // log系统是否初始化并启动
    bool embeded_log_enabled = false;
    // dex文件抓取功能是否启动
    bool dex_dump_enabled = false;
    // 远程控制功能是否启动
    bool remote_ctrl_enabled = false;
    // 是否只记录本地方法
    bool only_native = false;
    // 是否只记录方法名
    bool only_method_name = false;

    // app可以读写文件的目录(/data/data/<app_name>), 用来生成日志文件目录等
    std::string app_root;
    // 所有日志文件的主目录
    std::string log_dir_root;
    // 本次运行日志文件目录
    std::string current_log_dir;
    // app名称(用来生成app_root)
    std::string target_app_name;
    // 从内存中dump文件的保存的总目录(dex文件)
    std::string file_dump_dir_root;
    // 本次运行dump的文件保存目录
    std::string file_dump_dir;

    // log system
    char* log_base = NULL;
    char* log_data = NULL;
    volatile int log_spare_space = LOG_MAX;
    volatile int log_file_amount = 0;

    // 连接到EvMonitor_agent后的代表连接的文件描述符编号
    int rm_sock = DISCONNECTED;
    // EvMonitor_agent监听的sock地址
    std::string agent_sock_path = "/data/local/tmp/EvMonitor_agent/sock";
    // 线程互斥锁
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
    // 返回当前时间字符串
    std::string getTime();
    // 返回随机字符串
    std::string getRandomStr(int len);

  private:
    // 配置日志文件路径
    bool setLogFilePath();
    bool setDumpFilePath();
    inline bool dumpFile(const void* buff, long size, std::string file_path);
    
};

void* commandHandler(void* args);
}
#endif