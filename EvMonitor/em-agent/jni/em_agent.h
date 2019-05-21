#ifndef EM_AGENT
#define EM_AGENT
typedef struct config{
    char only_native;
    char only_method_name;
    char enable_dex_dump;
    char log_dir[30];
    char file_dump_dir[30];
}CONFIG;
#endif