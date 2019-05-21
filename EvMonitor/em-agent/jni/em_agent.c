#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<unistd.h>
#include<sys/un.h>
#include "em_agent.h"
#define CMD_MAX_LEN 50
#define EQUALSTR(str_input) (strcmp(str, str_input) == 0)
#define EQUALKEY(key_input) (strcmp(key, key_input) == 0)
#define TRUE 1
#define FALSE 0
#define UNKNOWN -1

const char* sock_path = "/data/local/tmp/EvMonitor_agent/sock";
const char* config_path = "/data/local/tmp/EvMonitor_agent/em.config";



// 打印读取到内存的配置信息
void printConfig(CONFIG* config) {
    printf("######EvMonitor Config########\n"
    "only_native       [%d]\n"
    "only_method_name  [%d]\n"
    "enable_dex_dump   [%d]\n"
    "log_dir           [%s]\n"
    "file_dump_dir     [%s]\n", 
    config->only_native, 
    config->only_method_name, 
    config->enable_dex_dump,
    config->log_dir,
    config->file_dump_dir);
}

char strToBool(const char* str) {
    if (EQUALSTR("true")) {
        return TRUE;
    } else if (EQUALSTR("false")) {
        return FALSE;
    }
    printf("warning:unknown Bool value\n");
    return UNKNOWN;
}

int readLineNoBlank(FILE* file, char* buff) {
    char c;
    int tmp;
    char* p = buff;
    while( (tmp = fgetc(file)) != EOF) {
        // 使用ndk编译时若使用char类型保存fgetc结果则上面的条件判断会始终为true造成死循环 -> 读取到不可读的内存 -> 段错误
        c = tmp;
        if (c == '\n') {
            //若此行为空行则继续读取直到获取到有内容的行或者到文件末尾
            if (p == buff) {
                continue;
            } else {
                break;
            }
        }
        if (c == ' ') {
            continue;
        }
        *p = c;
        p++;
    }
    *p = '\0';
    return (int)(p - buff);
}

void sepetateKeyValue(char* line, char** key_output, char** value_output) {
    char* tmp = NULL;

    tmp = strtok(line, "=");
    *key_output = tmp;
    tmp = strtok(NULL, "=");
    *value_output = tmp;
    tmp = strtok(NULL, "=");
    if (tmp != NULL) {
        printf("warning: invalid config item\n");
    }
}

void readConfigFile(const char* config_filename, CONFIG* config) {
    FILE* config_file = NULL;
    char config_line[100];
    char* key;
    char* value;

    config_file = fopen(config_filename, "r");
    if (config_file == NULL) {
        printf("warning:no config file\n");
        return;
    }
    printf("config file open success\n");
    while(readLineNoBlank(config_file, config_line) != 0) {
        //printf("%s\n", config_line);
        //skip comments line
        if (config_line[0] == '#') {
            continue;
        }
        sepetateKeyValue(config_line, &key, &value);
        //printf("key is [%s], value is [%s]\n", key, value);
        if (EQUALKEY("only_native")) {
            config->only_native = strToBool(value);
        } else if(EQUALKEY("only_method_name")) {
            config->only_method_name = strToBool(value);
        } else if(EQUALKEY("enable_dex_dump")) {
            config->enable_dex_dump = strToBool(value);
        } else if(EQUALKEY("log_dir")) {
            strcpy(config->log_dir, value);
        } else if(EQUALKEY("file_dump_dir")) {
            strcpy(config->file_dump_dir, value);
        } else {
            printf("unknown config key[%s]\n", key);
        }
    }
}

void sendConfig(int connect_fd) {
    CONFIG test_config;
        initConfig(&test_config);
        readConfigFile("test.config", &test_config);
        if (write(connect_fd, &test_config, sizeof(test_config)) < 0){
            perror("write error");
        } else {
            printf("object sended\n");
        }
}

void initConfig(CONFIG* config) {
    config->only_method_name = TRUE;
    config->only_native = FALSE;
    config->enable_dex_dump = FALSE;
    strcpy(config->log_dir, "log_dir");
    strcpy(config->file_dump_dir, "dumped_file");
}

void em_agent_main() {
    struct sockaddr_un listen_addr, client_addr;
    int listen_fd, connect_fd;
    socklen_t client_addr_len;
    char buff[CMD_MAX_LEN + 1];
    char input_buff[50];

    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sun_family = AF_UNIX;
    strcpy(listen_addr.sun_path, sock_path);
    unlink(sock_path);
    if (bind(listen_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind error");
        exit(1);
    }

    if (listen(listen_fd, 20) < 0) {
        perror("listen error");
        exit(1);
    }
    sendConfig(connect_fd);
    while(1) {
        printf("waiting for client\n");
        connect_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (connect_fd < 0) {
            perror("accept error");
            break;
        } 

        if (connect_fd == 0) {
            printf("read EOF\n");
            continue;
        }
        printf("client connected, addr[%s]\n", client_addr.sun_path);
        
        while(1) {
            scanf("%s", input_buff);
            if (input_buff[0] == 'q') {
                break;
            }
            if(input_buff[0] == 't') {
                sendConfig(connect_fd);
                continue;
            }
            if (write(connect_fd, input_buff, strlen(input_buff) + 1) < 0) {
                perror("write error");
            }
        }
        close(connect_fd);
    }
    close(listen_fd);
}

void read_config_test_main() {
    CONFIG test_config;
    initConfig(&test_config);
    readConfigFile("test.config", &test_config);
    printConfig(&test_config);
}

int main() {
    em_agent_main();
    return 0;
}