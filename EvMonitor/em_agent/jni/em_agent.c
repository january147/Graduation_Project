#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<pthread.h>
#include<unistd.h>
#include<sys/un.h>
#include<sys/select.h>
#include "em_agent.h"

#define CMD_MAX_LEN 50
#define EQUALSTR(str_input) (strcmp(str, str_input) == 0)
#define EQUALKEY(key_input) (strcmp(key, key_input) == 0)
#define TRUE 1
#define FALSE 0
#define UNKNOWN -1
#define ARRAY_MAX 20

#define EQUALSTR(str_input) (strcmp(str, str_input) == 0)
#define EQUALKEY(key_input) (strcmp(key, key_input) == 0)

typedef int BOOL;

// 保存文件描述符的数组类型
typedef struct array{
    int data[20];
    int size;
}Array;

// 传递给connectStateListener的参数类型
typedef struct handler_arg{
    Array* client_fds;
    int connect_fd;
}HArg;

const char* sock_path = "/data/local/tmp/EvMonitor_agent/sock";
const char* config_path = "em.config";

//用于管理连接文件描述符的数组的相关操作函数             
void ArrayInit(Array* arr) {
    arr->size = 0;
}

int ArrayAdd(Array* arr, int item) {
    if (arr->size < ARRAY_MAX) {
        arr->data[arr->size] = item;
    }
    arr->size++;
    return (arr->size - 1);
}

int ArrayFind(Array* arr, int item) {
    int i;
    for(i=0; i<arr->size; i++) {
        if (arr->data[i] == item) {
            return i;
        }
    }
    return -1;
}

BOOL ArrayPop(Array* arr) {
    if (arr->size <= 0) {
        return FALSE;
    }
    arr->size--;
    return TRUE;
}

BOOL ArrayDelete(Array* arr, int item) {
    int i;
    i = ArrayFind(arr, item);
    if (i == -1) {
        return FALSE;
    }
    arr->size--;
    for(; i<arr->size; i++) {
        arr->data[i] = arr->data[i+1];
    }
    return TRUE;
}

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

// 字符串转换成用char类型表示的布尔类型, 用1表示true,用0表示false, 用于读取配置文件中的值
char strToBool(const char* str) {
    if (EQUALSTR("true")) {
        return TRUE;
    } else if (EQUALSTR("false")) {
        return FALSE;
    }
    printf("warning:unknown Bool value\n");
    return UNKNOWN;
}

// 从配置文件中读取一个非空行
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

// 读取配置文件的函数,用于分离配置项名和值
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

// 初始化配置默认配置项
void initConfig(CONFIG* config) {
    config->only_method_name = TRUE;
    config->only_native = FALSE;
    config->enable_dex_dump = FALSE;
    strcpy(config->log_dir, "log_dir");
    strcpy(config->file_dump_dir, "dumped_file");
}

// 从文件中读取配置项
void readConfigFile(const char* config_filename, CONFIG* config) {
    FILE* config_file = NULL;
    char config_line[100];
    char* key;
    char* value;

    initConfig(config);
    config_file = fopen(config_filename, "r");
    if (config_file == NULL) {
        printf("warning:no config file\n");
        return;
    }
    printf("config file open success\n");
    while(readLineNoBlank(config_file, config_line) != 0) {
        //printf("%s\n", config_line);
        //skip comments line(跳过配置文件中的注释)
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

// 向一个文件描述符描述的连接发送配置文件信息
void sendConfig(int connect_fd) {
    CONFIG test_config;
    readConfigFile("test.config", &test_config);
    if (write(connect_fd, &test_config, sizeof(test_config)) < 0){
        perror("write error");
    } else {
        printf("object sended\n");
    }
}

// 向一个文件描述符描述的连接发送字符串命令
void sendCmd(int connect_fd, const char* cmd) {
    if (write(connect_fd, cmd, strlen(cmd) + 1) < 0) {
        perror("write error");
    }
} 

// 接收用户输入并向所有连接到EvMonitor_agent的进程发送命令
void* commandSender(void* args) {
    int i;
    Array* client_fds = (Array*)args;
    char cmd_buff[CMD_MAX_LEN + 1];
    // 测试部分
    while(1) {
        printf("[CS]Please input command\n");
        scanf("%s", cmd_buff);
        // 没有进程连接上
        if (client_fds->size <= 0) {
            printf("[CS]no client connected");
            continue;
        }

        // 退出
        if (strcmp(cmd_buff, "quit") == 0) {
            break;
        }

        // 发送配置文件
        if(strcmp(cmd_buff, "send_config") == 0) {
            for(i=0; i<client_fds->size; i++) {
                sendConfig(client_fds->data[i]);
            }
            continue;
        }

        // 发送其他命令
        for(i=0; i<client_fds->size; i++) {
            sendCmd(client_fds->data[i], cmd_buff);
        }
    }
    // 退出时关闭所有连接
    for(i=0; i<client_fds->size; i++) {
        close(client_fds->data[i]);
    }
    return NULL;
}

// 每一个进程连接上后会开一个该函数的线程用于监听是否有进程断开连接
void* connectStateListener(void* args) {
    char fake_buff[10];
    HArg* arg = (HArg*)args;
    Array* client_fds = arg->client_fds;
    int connect_fd = arg->connect_fd;
    int len;
    while(1) {
        len = read(connect_fd, fake_buff, 10);
        // 在某一段断开连接时, 另外一端的read函数返回值会为0, 以此可以判断连接被对方断开
        if (len <= 0) {
            ArrayDelete(client_fds, connect_fd);
            printf("[CSL]fd %d disconnected\n", connect_fd);
            break;
        }
    }
    return NULL;
}

// EvMonitor_agent主函数
void em_agent_main() {
    pthread_t tid;
    struct sockaddr_un listen_addr, client_addr;
    int listen_fd, connect_fd;
    socklen_t client_addr_len;
    // 传递给connectStateListener的参数
    HArg h_arg;
    Array client_fds;

    ArrayInit(&client_fds);
    h_arg.client_fds = &client_fds;
    listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sun_family = AF_UNIX;
    strcpy(listen_addr.sun_path, sock_path);
    unlink(sock_path);
    if (bind(listen_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("[server]bind error");
        exit(1);
    }

    if (listen(listen_fd, 20) < 0) {
        perror("[server]listen error");
        exit(1);
    }
    // 创建接收用户输入命令并发送的线程, 主线程监听socket等待进程连接
    if (pthread_create(&tid, NULL, commandSender, &client_fds) != 0) {
        perror("[server]commandSender failed to start");
    }
    printf("[server]em_agent server started\n");
    while(1) {
        connect_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_addr_len);
        if (connect_fd < 0) {
            perror("[server]accept error");
            break;
        } 

        if (connect_fd == 0) {
            printf("read EOF\n");
            continue;
        }
        printf("[server]client connected, addr[%s]\n", client_addr.sun_path);
        // 进程刚连接时发送配置文件数据
        sendConfig(connect_fd);
        // 把该连接的文件描述符添加到连接数组中
        ArrayAdd(&client_fds, connect_fd);
        h_arg.connect_fd = connect_fd;
        // 创建一个线程监听该连接的状态, 在连接被对方断开时将其从连接数组中删除
        if (pthread_create(&tid, NULL, connectStateListener, &h_arg) != 0) {
            perror("[server]connectStateListener failed to start");
        }
    }
    close(listen_fd);
}

// 测试读取配置文件
void read_config_test_main() {
    CONFIG test_config;
    initConfig(&test_config);
    readConfigFile(config_path, &test_config);
    printConfig(&test_config);
}

int main() {
    em_agent_main();
    return 0;
}