#include <cstddef>
#include <unistd.h>
#include <ctime>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include "android/log.h"
#include <sys/mman.h>
#include "EvMonitor.h"
#include <errno.h>
#include <sys/syscall.h>
#include <pthread.h>
 
namespace art{

// 监控熊本地模块实例
EvMonitor em;

// 打印读取到内存的配置信息
void printConfig(CONFIG* config) {
    EMLOGD("######EvMonitor Config########\n"
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

// 处理EvMonitor发送的命令
void* commandHandler(void* args) {
  EvMonitor* mEm = (EvMonitor*)args;
  int error_count = 0;
  int cmd_len;
  int sock_fd = mEm->rm_sock;
  char cmd[CMD_MAX_LEN + 1];

  mEm->remote_ctrl_enabled = true;
  while (mEm->remote_ctrl_enabled) {
    cmd_len = read(sock_fd, cmd, CMD_MAX_LEN);
    cmd[cmd_len] = '\0';

    if (cmd_len == 0) {
      EMLOGE("agent stoped the connection");
      mEm->remote_ctrl_enabled = false;
      return NULL;
    }

    if (cmd_len < 0) {
      if (error_count > 10) {
        mEm->remote_ctrl_enabled = false;
        return NULL;
      }
      EMLOGE("commandHanlder failed to read cmd, error[%s]", strerror(errno));
      error_count++;
      continue;
    }
#ifdef EM_DEBUG
  EMLOGD("cmdHandler getcmd[%s], size[%d]", cmd, cmd_len);
#endif
    if (ISCMD("write_log")) {
      mEm->mutex_lock.lock();
      mEm->writeLog();
      mEm->mutex_lock.unlock();
#ifdef EM_DEBUG
      EMLOGD("cmd[%s] finished", cmd);
#endif
    } else if(ISCMD("read_config")) {
      mEm->readConfigFromAgent();
    }
    // 此处添加其他控制命令
  }
  return NULL;
}

// 返回随机字符串
std::string EvMonitor::getRandomStr(int len) {
  int size;
  int i = 0;
  char tmp[21];
  char init = 'a';
  size = (len < 20)? len : 20;
  for(i=0; i<len; i++){
    tmp[i] = init + rand() % 26;
  }
  tmp[i] = '\0';
  return tmp;
}

// 返回当前时间字符串
std::string EvMonitor::getTime() {
  time_t timep;
  time (&timep);
  char tmp[64];
  strftime(tmp, sizeof(tmp), "%Y-%m-%d_%H:%M:%S",localtime(&timep));
  return tmp;
}

// EvMonitor类构造函数, 设置随机数种子用于后面生成随机字符串
EvMonitor::EvMonitor() {
  srand((unsigned)time(NULL));
  
}

// 设置当前监控app的名字, app名字在Java层读取, 通过JNI机制传递到本地模块中, 用于设置日志文件等的保存路径
// 因为app在没有特殊权限时只能写/data/data/<app_name>目录
void EvMonitor::setTargetApp(std::string app_name) {
  target_app_name = app_name;
  // 设置app的可写文件目录用于之后保存文件
  app_root = "/data/data/" + app_name; 
}

// 设置监控系统是否工作, 返回值为操作是否成功
bool EvMonitor::enableMonitor(bool enable) {
  // 关闭监控系统
  if (!enable) {
    monitor_enabled = false;
    return true;
  }

  //监控系统已经启动
  if (monitor_enabled) {
    return true;
  }
  //启动监控系统
  monitor_enabled = enable;
  // 初始化日志系统
  return enableEmbedLog(true);

}

// 初始化并启动日志功能
bool EvMonitor::enableEmbedLog(bool enable) {
  if (!enable) {
    embeded_log_enabled = false;
    if (log_base != NULL) {
      munmap(log_base, LOG_MAX);
      log_base = NULL;
      log_data = NULL;
    }
    return true;
  }
 
  if (embeded_log_enabled) {
    return true;
  } 

  // 设置日志文件目录
  if (!setLogFilePath()) {
    EMLOGE("no log file dir");
    return false;
  }

  // 创建日志缓冲区
  log_data = (char*)mmap(NULL, LOG_MAX, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if ((void*)log_data == (void*)-1) {
    EMLOGE("can't allocate log buff, error[%s]", strerror(errno));
    return false;
  }
  log_base = log_data;
  embeded_log_enabled = true;
#ifdef EM_DEBUG
  EMLOGD("embeded log enabled, log buff address[%p]", log_base);
  EMLOGD("log buff size[%d]", LOG_MAX);
#endif
  return true;
}

// 连接到EvMonitor_agent或者从EvMonitor_agent断开连接
bool EvMonitor::connectToAgent(bool enable) {
  int sock_fd;
  struct sockaddr_un agent_addr;

  // 关闭连接
  if (!enable) {
    agent_connected = false;
    if (rm_sock != DISCONNECTED) {
      close(rm_sock);
      rm_sock = DISCONNECTED;
    }
    return true;
  }

  // 已经连接上
  if (agent_connected) {
    return true;
  }

  sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock_fd == -1) {
    EMLOGE("can't create domain socket, error[%s]", strerror(errno));
    return false;
  }

  memset(&agent_addr, 0, sizeof(agent_addr));
  agent_addr.sun_family = AF_UNIX;
  strcpy(agent_addr.sun_path, agent_sock_path.c_str());

  if (connect(sock_fd, (struct sockaddr *)&agent_addr, sizeof(agent_addr)) < 0) {
    EMLOGE("can't connect to control agent, error[%s]", strerror(errno));
    return false;
  }
#ifdef EM_DEBUG
  EMLOGD("agent connected");
#endif
  rm_sock = sock_fd;
  agent_connected = true;
  return true;
}

// 从EvMonitor_agent读取系统配置信息
bool EvMonitor::readConfigFromAgent() {
  int config_len = read(rm_sock, &config_buff, sizeof(CONFIG));
      if (config_len != sizeof(CONFIG)) {
        EMLOGE("bad config");
        return false;
      }
#ifdef EM_DEBUG
      printConfig(&config_buff);
#endif
      return true;
}

// 启动一个线程来读取EvMonitor的命令
bool EvMonitor::enableRemoteCtrl(bool enable) {
  pthread_t mtid;
  if (!enable) {
    remote_ctrl_enabled = false;
    return true;
  }
  if (remote_ctrl_enabled) {
    return true;
  }

  if (rm_sock == DISCONNECTED) {
    EMLOGE("not connect to agent");
    return false;
  }
  // 启动线程commandHandle来读取EvMonitor_agent的命令
  if (pthread_create(&mtid, NULL, commandHandler, this) != 0) {
    EMLOGE("can't create remote command handler thread");
    return false;
  }
#ifdef EM_DEBUG
  EMLOGD("commandHandler started");
#endif
  return true;
}

// EvMonitor初始化
void EvMonitor::init(std::string app_name) {
  // 设置监控的app名称(从Java层获取)
  setTargetApp(app_name);

  //连接到EvMonitor_agent
  if (!connectToAgent(true)) {
    EMLOGE("can't connect to agent, monitor stoped");
    return;
  }

  //从EvMonitor_agent读取配置信息
  if (!readConfigFromAgent()) {
    EMLOGE("can't read config, monitor stoped");
    return;
  }

  // 根据获取配置信息设置EvMonitor的各项参数, 启动各项功能
  // 脱壳功能
  if (config_buff.enable_dex_dump) {
    enableDexDump(true);
  }

  // 设置是否只记录本地方法调用
  if (config_buff.only_native) {
    only_native = true;
  }

  // 设置是否只记录方法名
  if (config_buff.only_method_name) {
    only_method_name = true;
  }

  // 启动运行时从EvMonitor_agent读取命令的功能
  if (!enableRemoteCtrl(true)) {
    EMLOGD("remote control failed to start");
  }

  // 设置监控系统启动
  if (!enableMonitor(true)) {
    EMLOGE("Monitor failed to start");
  }
  
}

// 初始化并启动脱壳功能
bool EvMonitor::enableDexDump(bool enable) {
  if (!enable) {
    dex_dump_enabled = false;
    return true;
  }

  if (dex_dump_enabled) {
    return true;
  }

  if (!setDumpFilePath()) {
    EMLOGE("no dump file dir");
    return false;
  }

  dex_dump_enabled = true;
#ifdef EM_DEBUG
  EMLOGD("dex file dump enabled");
#endif
  return true;
}

// 写入日志, 参数为(日志标签, 日志内容)
void EvMonitor::log(const char* tag, const char* log_content) {
  int log_item_len= strlen(tag) + strlen(log_content) + 9;
  mutex_lock.lock();
  if (log_spare_space < log_item_len) {
    // 内存缓冲区满时写入文件
    writeLog();
  } 
  log_item_len = sprintf(log_data, "%6ld %s %s\n", gettid(), tag, log_content);
  log_data += log_item_len;
  log_spare_space -= log_item_len;
  mutex_lock.unlock();
}

// 设置脱壳得到的dex文件保存路径
bool EvMonitor::setDumpFilePath() {
  std::stringstream file_name_builder;
  if (app_root.length() == 0) {
    EMLOGE("no app root dir");
    return false;
  }

  file_name_builder << app_root << "/" << config_buff.file_dump_dir;
  file_dump_dir_root = file_name_builder.str();
  if (access(file_dump_dir_root.c_str(), F_OK) < 0) {
    if (mkdir(file_dump_dir_root.c_str(), 0755) < 0) {
      EMLOGE("can't create root dumped file dir[%s], error[%s]", file_dump_dir_root.c_str(), strerror(errno));
      return false;
    }
  }
  #ifdef EM_DEBUG
  EMLOGD("file_dump_dir_root[%s]", file_dump_dir_root.c_str());
  #endif

  file_name_builder << "/" << getpid();
  file_dump_dir = file_name_builder.str();
  if (access(file_dump_dir_root.c_str(), F_OK) < 0) {
    if (mkdir(file_dump_dir_root.c_str(), 0755) < 0) {
      EMLOGE("can't create dumped file dir[%s] for current process, error[%s]", file_dump_dir.c_str(), strerror(errno));
      return false;
    }
  }
  #ifdef EM_DEBUG
  EMLOGD("file_dump_dir[%s]", file_dump_dir.c_str());
  #endif
  return true;
}

// 设置日志文件保存路径
bool EvMonitor::setLogFilePath() {
  std::stringstream file_name_builder;
  //return false if no target_app_name specified.
  if(app_root.length() == 0){
    EMLOGE("no target_app specified");
    return false;
  }
  file_name_builder << app_root << "/" << config_buff.log_dir;
  log_dir_root = file_name_builder.str();
  if (access(log_dir_root.c_str(), F_OK) < 0) {
    if (mkdir(log_dir_root.c_str(), 0755) < 0) {
      EMLOGE("can't create root log dir[%s], error[%s]", log_dir_root.c_str(), strerror(errno));
      return false;
    }
  }

  file_name_builder << "/" << getpid() << "_" <<getRandomStr(5);
  current_log_dir = file_name_builder.str();
  if (access(current_log_dir.c_str(), F_OK) < 0) {
    if (mkdir(current_log_dir.c_str(), 0755) < 0) {
      EMLOGE("can't create log dir[%s] for current process, error[%s]", current_log_dir.c_str(), strerror(errno));
      return false;
    }
  }
#ifdef EM_DEBUG
  EMLOGD("log file dir[%s]", current_log_dir.c_str());
#endif
  return true;
}

// 把缓冲区数据写入文件
bool EvMonitor::writeLog() {
  std::stringstream file_name_builder;
  if (log_spare_space >= LOG_MAX) {
    EMLOGE("no log to write");
    return false;
  }

  if (log_file_amount > LOG_FILE_MAX) {
    EMLOGE("log file reached max size");
    return false;
  }

  file_name_builder << current_log_dir << "/em_" << log_file_amount << ".log";
  if (!dumpFile(log_base, LOG_MAX - log_spare_space, file_name_builder.str())) {
    EMLOGE("can't save log file, error[%s]", strerror(errno));
    return false;
  }
  log_file_amount++;
  log_data = log_base;
  log_spare_space = LOG_MAX;
  return true;
}

// 从内存中dump dex文件, 参数为(起始地址, 文件大小)
void EvMonitor::dumpDex(const void* base, long size) {
  std::stringstream file_name_builder;
  if (dex_dump_enabled) {
    file_name_builder << file_dump_dir << "/" << getRandomStr(6) << ".dex";
    if (!dumpFile(base, size, file_name_builder.str())) {
      __android_log_print(ANDROID_LOG_DEBUG, "EvMonitor", "can't dump dex file, error[%s]", strerror(errno));
    }else{
      __android_log_print(ANDROID_LOG_DEBUG, "EvMonitor", "file dumped, path[%s]", file_name_builder.str().c_str());
    }
  }
}

// 保存内存数据到文件
inline bool EvMonitor::dumpFile(const void* base, long size, std::string file_path) {
  int fd;
  fd = open(file_path.c_str(), O_WRONLY|O_CREAT, 0644);
  if (fd < 0) {
    return false;
  }
  if (write(fd, base, size) < 0 ){
    return false;
  };
  close(fd);
  return true;
}
}//end namespace
