#ifndef EM_AGENT
#define EM_AGENT

// 配置项结构, 用于保存从文件中读取的配置项并传递给监控系统
typedef struct config{
    char only_native;
    char only_method_name;
    char enable_dex_dump;
    char log_dir[30];
    char file_dump_dir[30];
}CONFIG;
#endif