/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "art_method.h"

#include <cstddef>
//EvMonitor--head file
#define EM_DEBUG
#include<unistd.h>
#include <ctime>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/un.h>
#include<sys/stat.h>
#include<fcntl.h> 
#include "android/log.h"
#include<sys/mman.h>
#include "EvMonitor.h"
#include<errno.h>
#include <sys/syscall.h>
#include <pthread.h>

#define gettid() syscall(SYS_gettid)
#define getpid() syscall(SYS_getpid)
#define EMLOGE(log_info, ...) __android_log_print(ANDROID_LOG_ERROR, "EvMonitor", log_info, ##__VA_ARGS__)
#define EMLOGD(log_info, ...) __android_log_print(ANDROID_LOG_DEBUG, "EvMonitor", log_info, ##__VA_ARGS__)
#define ISCMD(cmd_str) (strcmp(cmd, cmd_str) == 0)
//end EvMonitor

#include "android-base/stringprintf.h"
#include "arch/context.h"
#include "art_method-inl.h"
#include "base/stringpiece.h"
#include "class_linker-inl.h"
#include "debugger.h"
#include "dex_file-inl.h"
#include "dex_file_annotations.h"
#include "dex_instruction.h"
#include "entrypoints/runtime_asm_entrypoints.h"
#include "gc/accounting/card_table-inl.h"
#include "interpreter/interpreter.h"
#include "jit/jit.h"
#include "jit/jit_code_cache.h"
#include "jit/profiling_info.h"
#include "jni_internal.h"
#include "mirror/class-inl.h"
#include "mirror/class_ext.h"
#include "mirror/executable.h"
#include "mirror/object_array-inl.h"
#include "mirror/object-inl.h"
#include "mirror/string.h"
#include "oat_file-inl.h"
#include "runtime_callbacks.h"
#include "scoped_thread_state_change-inl.h"
#include "vdex_file.h"
#include "well_known_classes.h"

namespace art {

using android::base::StringPrintf;

extern "C" void art_quick_invoke_stub(ArtMethod*, uint32_t*, uint32_t, Thread*, JValue*,
                                      const char*);
extern "C" void art_quick_invoke_static_stub(ArtMethod*, uint32_t*, uint32_t, Thread*, JValue*,
                                             const char*);

DEFINE_RUNTIME_DEBUG_FLAG(ArtMethod, kCheckDeclaringClassState);

// Enforce that we he have the right index for runtime methods.
static_assert(ArtMethod::kRuntimeMethodDexMethodIndex == DexFile::kDexNoIndex,
              "Wrong runtime-method dex method index");

//EvMonitor--native
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

EvMonitor::EvMonitor() {
  srand((unsigned)time(NULL));
}

void EvMonitor::setTargetApp(std::string app_name) {
  target_app_name = app_name;
  app_root = "/data/data/" + app_name; 
}

bool EvMonitor::enableMonitor(bool enable) {
  if (!enable) {
    monitor_enabled = false;
    return true;
  }

  if (monitor_enabled) {
    return true;
  }
  monitor_enabled = enable;
  return enableEmbedLog(true);

}

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

  if (!setLogFilePath()) {
    EMLOGE("no log file dir");
    return false;
  }

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

bool EvMonitor::connectToAgent(bool enable) {
  int sock_fd;
  struct sockaddr_un agent_addr;

  if (!enable) {
    agent_connected = false;
    if (rm_sock != DISCONNECTED) {
      close(rm_sock);
      rm_sock = DISCONNECTED;
    }
    return true;
  }

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

bool EvMonitor::readConfigFromAgent() {
  int config_len = read(rm_sock, &config_buff, sizeof(CONFIG));
      if (config_len != sizeof(CONFIG)) {
        EMLOGE("bad config");
        return false;
      }
      printConfig(&config_buff);
      return true;
}

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

  if (pthread_create(&mtid, NULL, commandHandler, this) != 0) {
    EMLOGE("can't create remote command handler thread");
    return false;
  }
#ifdef EM_DEBUG
  EMLOGD("commandHandler started");
#endif
  return true;
}

void EvMonitor::init(std::string app_name) {
  setTargetApp(app_name);
  if (!connectToAgent(true)) {
    EMLOGE("can't connect to agent, monitor stoped");
    return;
  }
  if (!readConfigFromAgent()) {
    EMLOGE("can't read config, monitor stoped");
    return;
  }

  if (config_buff.enable_dex_dump) {
    enableDexDump(true);
  }

  if (config_buff.only_native) {
    only_native = true;
  }

  if (config_buff.only_method_name) {
    only_method_name = true;
  }
  if (!enableRemoteCtrl(true)) {
    EMLOGD("remote control failed to start");
  }

  if (!enableMonitor(true)) {
    EMLOGE("Monitor failed to start");
  }
  
}

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

void EvMonitor::log(const char* tag, const char* log_content) {
  int log_item_len= strlen(tag) + strlen(log_content) + 9;
  mutex_lock.lock();
  if (log_spare_space < log_item_len) {
    writeLog();
  } 
  log_item_len = sprintf(log_data, "%6ld %s %s\n", gettid(), tag, log_content);
  log_data += log_item_len;
  log_spare_space -= log_item_len;
  mutex_lock.unlock();
}

std::string EvMonitor::getTime() {
  time_t timep;
  time (&timep);
  char tmp[64];
  strftime(tmp, sizeof(tmp), "%Y-%m-%d_%H:%M:%S",localtime(&timep));
  return tmp;
}

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

//deprecated
int my_target_pid = 0;
void setMonitorPid(int pid){
  my_target_pid = pid;
}
//main native component
EvMonitor em;

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
    if (ISCMD("FL")) {
      mEm->mutex_lock.lock();
      mEm->writeLog();
      mEm->mutex_lock.unlock();
#ifdef EM_DEBUG
      EMLOGD("cmd[%s] finished", cmd);
#endif
    } else if(ISCMD("RC")) {
      mEm->readConfigFromAgent();
    }
  }
  return NULL;
}

extern "C" void ex_log_em(const char* tag, const char* log_info){
  if (em.embeded_log_enabled) {
    em.log(tag, log_info);
  }
}
extern "C" void ex_dump_log_buff_em(){
  if (em.embeded_log_enabled) {
    em.writeLog();
  }
}
//end EvMonitor


ArtMethod* ArtMethod::GetCanonicalMethod(PointerSize pointer_size) {
  if (LIKELY(!IsDefault())) {
    return this;
  } else {
    mirror::Class* declaring_class = GetDeclaringClass();
    DCHECK(declaring_class->IsInterface());
    ArtMethod* ret = declaring_class->FindInterfaceMethod(declaring_class->GetDexCache(),
                                                          GetDexMethodIndex(),
                                                          pointer_size);
    DCHECK(ret != nullptr);
    return ret;
  }
}

ArtMethod* ArtMethod::GetNonObsoleteMethod() {
  DCHECK_EQ(kRuntimePointerSize, Runtime::Current()->GetClassLinker()->GetImagePointerSize());
  if (LIKELY(!IsObsolete())) {
    return this;
  } else if (IsDirect()) {
    return &GetDeclaringClass()->GetDirectMethodsSlice(kRuntimePointerSize)[GetMethodIndex()];
  } else {
    return GetDeclaringClass()->GetVTableEntry(GetMethodIndex(), kRuntimePointerSize);
  }
}

ArtMethod* ArtMethod::GetSingleImplementation(PointerSize pointer_size) {
  if (!IsAbstract()) {
    // A non-abstract's single implementation is itself.
    return this;
  }
  return reinterpret_cast<ArtMethod*>(GetDataPtrSize(pointer_size));
}

ArtMethod* ArtMethod::FromReflectedMethod(const ScopedObjectAccessAlreadyRunnable& soa,
                                          jobject jlr_method) {
  ObjPtr<mirror::Executable> executable = soa.Decode<mirror::Executable>(jlr_method);
  DCHECK(executable != nullptr);
  return executable->GetArtMethod();
}

mirror::DexCache* ArtMethod::GetObsoleteDexCache() {
  DCHECK(!Runtime::Current()->IsAotCompiler()) << PrettyMethod();
  DCHECK(IsObsolete());
  ObjPtr<mirror::ClassExt> ext(GetDeclaringClass()->GetExtData());
  CHECK(!ext.IsNull());
  ObjPtr<mirror::PointerArray> obsolete_methods(ext->GetObsoleteMethods());
  CHECK(!obsolete_methods.IsNull());
  DCHECK(ext->GetObsoleteDexCaches() != nullptr);
  int32_t len = obsolete_methods->GetLength();
  DCHECK_EQ(len, ext->GetObsoleteDexCaches()->GetLength());
  // Using kRuntimePointerSize (instead of using the image's pointer size) is fine since images
  // should never have obsolete methods in them so they should always be the same.
  PointerSize pointer_size = kRuntimePointerSize;
  DCHECK_EQ(kRuntimePointerSize, Runtime::Current()->GetClassLinker()->GetImagePointerSize());
  for (int32_t i = 0; i < len; i++) {
    if (this == obsolete_methods->GetElementPtrSize<ArtMethod*>(i, pointer_size)) {
      return ext->GetObsoleteDexCaches()->Get(i);
    }
  }
  LOG(FATAL) << "This method does not appear in the obsolete map of its class!";
  UNREACHABLE();
}

uint16_t ArtMethod::FindObsoleteDexClassDefIndex() {
  DCHECK(!Runtime::Current()->IsAotCompiler()) << PrettyMethod();
  DCHECK(IsObsolete());
  const DexFile* dex_file = GetDexFile();
  const dex::TypeIndex declaring_class_type = dex_file->GetMethodId(GetDexMethodIndex()).class_idx_;
  const DexFile::ClassDef* class_def = dex_file->FindClassDef(declaring_class_type);
  CHECK(class_def != nullptr);
  return dex_file->GetIndexForClassDef(*class_def);
}

mirror::String* ArtMethod::GetNameAsString(Thread* self) {
  CHECK(!IsProxyMethod());
  StackHandleScope<1> hs(self);
  Handle<mirror::DexCache> dex_cache(hs.NewHandle(GetDexCache()));
  auto* dex_file = dex_cache->GetDexFile();
  uint32_t dex_method_idx = GetDexMethodIndex();
  const DexFile::MethodId& method_id = dex_file->GetMethodId(dex_method_idx);
  return Runtime::Current()->GetClassLinker()->ResolveString(*dex_file, method_id.name_idx_,
                                                             dex_cache);
}

void ArtMethod::ThrowInvocationTimeError() {
  DCHECK(!IsInvokable());
  // NOTE: IsDefaultConflicting must be first since the actual method might or might not be abstract
  //       due to the way we select it.
  if (IsDefaultConflicting()) {
    ThrowIncompatibleClassChangeErrorForMethodConflict(this);
  } else {
    DCHECK(IsAbstract());
    ThrowAbstractMethodError(this);
  }
}

InvokeType ArtMethod::GetInvokeType() {
  // TODO: kSuper?
  if (IsStatic()) {
    return kStatic;
  } else if (GetDeclaringClass()->IsInterface()) {
    return kInterface;
  } else if (IsDirect()) {
    return kDirect;
  } else {
    return kVirtual;
  }
}

size_t ArtMethod::NumArgRegisters(const StringPiece& shorty) {
  CHECK_LE(1U, shorty.length());
  uint32_t num_registers = 0;
  for (size_t i = 1; i < shorty.length(); ++i) {
    char ch = shorty[i];
    if (ch == 'D' || ch == 'J') {
      num_registers += 2;
    } else {
      num_registers += 1;
    }
  }
  return num_registers;
}

bool ArtMethod::HasSameNameAndSignature(ArtMethod* other) {
  ScopedAssertNoThreadSuspension ants("HasSameNameAndSignature");
  const DexFile* dex_file = GetDexFile();
  const DexFile::MethodId& mid = dex_file->GetMethodId(GetDexMethodIndex());
  if (GetDexCache() == other->GetDexCache()) {
    const DexFile::MethodId& mid2 = dex_file->GetMethodId(other->GetDexMethodIndex());
    return mid.name_idx_ == mid2.name_idx_ && mid.proto_idx_ == mid2.proto_idx_;
  }
  const DexFile* dex_file2 = other->GetDexFile();
  const DexFile::MethodId& mid2 = dex_file2->GetMethodId(other->GetDexMethodIndex());
  if (!DexFileStringEquals(dex_file, mid.name_idx_, dex_file2, mid2.name_idx_)) {
    return false;  // Name mismatch.
  }
  return dex_file->GetMethodSignature(mid) == dex_file2->GetMethodSignature(mid2);
}

ArtMethod* ArtMethod::FindOverriddenMethod(PointerSize pointer_size) {
  if (IsStatic()) {
    return nullptr;
  }
  mirror::Class* declaring_class = GetDeclaringClass();
  mirror::Class* super_class = declaring_class->GetSuperClass();
  uint16_t method_index = GetMethodIndex();
  ArtMethod* result = nullptr;
  // Did this method override a super class method? If so load the result from the super class'
  // vtable
  if (super_class->HasVTable() && method_index < super_class->GetVTableLength()) {
    result = super_class->GetVTableEntry(method_index, pointer_size);
  } else {
    // Method didn't override superclass method so search interfaces
    if (IsProxyMethod()) {
      result = GetInterfaceMethodIfProxy(pointer_size);
      DCHECK(result != nullptr);
    } else {
      mirror::IfTable* iftable = GetDeclaringClass()->GetIfTable();
      for (size_t i = 0; i < iftable->Count() && result == nullptr; i++) {
        mirror::Class* interface = iftable->GetInterface(i);
        for (ArtMethod& interface_method : interface->GetVirtualMethods(pointer_size)) {
          if (HasSameNameAndSignature(interface_method.GetInterfaceMethodIfProxy(pointer_size))) {
            result = &interface_method;
            break;
          }
        }
      }
    }
  }
  DCHECK(result == nullptr ||
         GetInterfaceMethodIfProxy(pointer_size)->HasSameNameAndSignature(
             result->GetInterfaceMethodIfProxy(pointer_size)));
  return result;
}

uint32_t ArtMethod::FindDexMethodIndexInOtherDexFile(const DexFile& other_dexfile,
                                                     uint32_t name_and_signature_idx) {
  const DexFile* dexfile = GetDexFile();
  const uint32_t dex_method_idx = GetDexMethodIndex();
  const DexFile::MethodId& mid = dexfile->GetMethodId(dex_method_idx);
  const DexFile::MethodId& name_and_sig_mid = other_dexfile.GetMethodId(name_and_signature_idx);
  DCHECK_STREQ(dexfile->GetMethodName(mid), other_dexfile.GetMethodName(name_and_sig_mid));
  DCHECK_EQ(dexfile->GetMethodSignature(mid), other_dexfile.GetMethodSignature(name_and_sig_mid));
  if (dexfile == &other_dexfile) {
    return dex_method_idx;
  }
  const char* mid_declaring_class_descriptor = dexfile->StringByTypeIdx(mid.class_idx_);
  const DexFile::TypeId* other_type_id = other_dexfile.FindTypeId(mid_declaring_class_descriptor);
  if (other_type_id != nullptr) {
    const DexFile::MethodId* other_mid = other_dexfile.FindMethodId(
        *other_type_id, other_dexfile.GetStringId(name_and_sig_mid.name_idx_),
        other_dexfile.GetProtoId(name_and_sig_mid.proto_idx_));
    if (other_mid != nullptr) {
      return other_dexfile.GetIndexForMethodId(*other_mid);
    }
  }
  return DexFile::kDexNoIndex;
}

uint32_t ArtMethod::FindCatchBlock(Handle<mirror::Class> exception_type,
                                   uint32_t dex_pc, bool* has_no_move_exception) {
  const DexFile::CodeItem* code_item = GetCodeItem();
  // Set aside the exception while we resolve its type.
  Thread* self = Thread::Current();
  StackHandleScope<1> hs(self);
  Handle<mirror::Throwable> exception(hs.NewHandle(self->GetException()));
  self->ClearException();
  // Default to handler not found.
  uint32_t found_dex_pc = DexFile::kDexNoIndex;
  // Iterate over the catch handlers associated with dex_pc.
  for (CatchHandlerIterator it(*code_item, dex_pc); it.HasNext(); it.Next()) {
    dex::TypeIndex iter_type_idx = it.GetHandlerTypeIndex();
    // Catch all case
    if (!iter_type_idx.IsValid()) {
      found_dex_pc = it.GetHandlerAddress();
      break;
    }
    // Does this catch exception type apply?
    mirror::Class* iter_exception_type = GetClassFromTypeIndex(iter_type_idx, true /* resolve */);
    if (UNLIKELY(iter_exception_type == nullptr)) {
      // Now have a NoClassDefFoundError as exception. Ignore in case the exception class was
      // removed by a pro-guard like tool.
      // Note: this is not RI behavior. RI would have failed when loading the class.
      self->ClearException();
      // Delete any long jump context as this routine is called during a stack walk which will
      // release its in use context at the end.
      delete self->GetLongJumpContext();
      LOG(WARNING) << "Unresolved exception class when finding catch block: "
        << DescriptorToDot(GetTypeDescriptorFromTypeIdx(iter_type_idx));
    } else if (iter_exception_type->IsAssignableFrom(exception_type.Get())) {
      found_dex_pc = it.GetHandlerAddress();
      break;
    }
  }
  if (found_dex_pc != DexFile::kDexNoIndex) {
    const Instruction* first_catch_instr =
        Instruction::At(&code_item->insns_[found_dex_pc]);
    *has_no_move_exception = (first_catch_instr->Opcode() != Instruction::MOVE_EXCEPTION);
  }
  // Put the exception back.
  if (exception != nullptr) {
    self->SetException(exception.Get());
  }
  return found_dex_pc;
}

// add by myself
void ArtMethod::log_em(const char* info) {
  if(em.monitor_enabled){
    em.log(info, PrettyMethod(true).c_str());
  }
}

void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,
                       const char* shorty) {
  // EvMonitor(log method in)
  this->log_em("II--");
  // end
  if (UNLIKELY(__builtin_frame_address(0) < self->GetStackEnd())) {
    ThrowStackOverflowError(self);
    return;
  }

  if (kIsDebugBuild) {
    self->AssertThreadSuspensionIsAllowable();
    CHECK_EQ(kRunnable, self->GetState());
    CHECK_STREQ(GetInterfaceMethodIfProxy(kRuntimePointerSize)->GetShorty(), shorty);
  }

  // Push a transition back into managed code onto the linked list in thread.
  ManagedStack fragment;
  self->PushManagedStackFragment(&fragment);

  Runtime* runtime = Runtime::Current();
  // Call the invoke stub, passing everything as arguments.
  // If the runtime is not yet started or it is required by the debugger, then perform the
  // Invocation by the interpreter, explicitly forcing interpretation over JIT to prevent
  // cycling around the various JIT/Interpreter methods that handle method invocation.
  if (UNLIKELY(!runtime->IsStarted() || Dbg::IsForcedInterpreterNeededForCalling(self, this))) {
    if (IsStatic()) {
      art::interpreter::EnterInterpreterFromInvoke(
          self, this, nullptr, args, result, /*stay_in_interpreter*/ true);
    } else {
      mirror::Object* receiver =
          reinterpret_cast<StackReference<mirror::Object>*>(&args[0])->AsMirrorPtr();
      art::interpreter::EnterInterpreterFromInvoke(
          self, this, receiver, args + 1, result, /*stay_in_interpreter*/ true);
    }
  } else {
    DCHECK_EQ(runtime->GetClassLinker()->GetImagePointerSize(), kRuntimePointerSize);

    constexpr bool kLogInvocationStartAndReturn = false;
    bool have_quick_code = GetEntryPointFromQuickCompiledCode() != nullptr;
    if (LIKELY(have_quick_code)) {
      if (kLogInvocationStartAndReturn) {
        LOG(INFO) << StringPrintf(
            "Invoking '%s' quick code=%p static=%d", PrettyMethod().c_str(),
            GetEntryPointFromQuickCompiledCode(), static_cast<int>(IsStatic() ? 1 : 0));
      }

      // Ensure that we won't be accidentally calling quick compiled code when -Xint.
      if (kIsDebugBuild && runtime->GetInstrumentation()->IsForcedInterpretOnly()) {
        CHECK(!runtime->UseJitCompilation());
        const void* oat_quick_code =
            (IsNative() || !IsInvokable() || IsProxyMethod() || IsObsolete())
            ? nullptr
            : GetOatMethodQuickCode(runtime->GetClassLinker()->GetImagePointerSize());
        CHECK(oat_quick_code == nullptr || oat_quick_code != GetEntryPointFromQuickCompiledCode())
            << "Don't call compiled code when -Xint " << PrettyMethod();
      }

      if (!IsStatic()) {
        (*art_quick_invoke_stub)(this, args, args_size, self, result, shorty);
      } else {
        (*art_quick_invoke_static_stub)(this, args, args_size, self, result, shorty);
      }
      if (UNLIKELY(self->GetException() == Thread::GetDeoptimizationException())) {
        // Unusual case where we were running generated code and an
        // exception was thrown to force the activations to be removed from the
        // stack. Continue execution in the interpreter.
        self->DeoptimizeWithDeoptimizationException(result);
      }
      if (kLogInvocationStartAndReturn) {
        LOG(INFO) << StringPrintf("Returned '%s' quick code=%p", PrettyMethod().c_str(),
                                  GetEntryPointFromQuickCompiledCode());
      }
    } else {
      LOG(INFO) << "Not invoking '" << PrettyMethod() << "' code=null";
      if (result != nullptr) {
        result->SetJ(0);
      }
    }
  }

  // Pop transition.
  self->PopManagedStackFragment(fragment);
  // EvMonitor(log method out)
  this->log_em("OI--");
}

const void* ArtMethod::RegisterNative(const void* native_method, bool is_fast) {
  CHECK(IsNative()) << PrettyMethod();
  CHECK(!IsFastNative()) << PrettyMethod();
  CHECK(native_method != nullptr) << PrettyMethod();
  if (is_fast) {
    AddAccessFlags(kAccFastNative);
  }
  void* new_native_method = nullptr;
  Runtime::Current()->GetRuntimeCallbacks()->RegisterNativeMethod(this,
                                                                  native_method,
                                                                  /*out*/&new_native_method);
  SetEntryPointFromJni(new_native_method);
  return new_native_method;
}

void ArtMethod::UnregisterNative() {
  CHECK(IsNative() && !IsFastNative()) << PrettyMethod();
  // restore stub to lookup native pointer via dlsym
  SetEntryPointFromJni(GetJniDlsymLookupStub());
}

bool ArtMethod::IsOverridableByDefaultMethod() {
  return GetDeclaringClass()->IsInterface();
}

bool ArtMethod::IsAnnotatedWithFastNative() {
  return IsAnnotatedWith(WellKnownClasses::dalvik_annotation_optimization_FastNative,
                         DexFile::kDexVisibilityBuild,
                         /* lookup_in_resolved_boot_classes */ true);
}

bool ArtMethod::IsAnnotatedWithCriticalNative() {
  return IsAnnotatedWith(WellKnownClasses::dalvik_annotation_optimization_CriticalNative,
                         DexFile::kDexVisibilityBuild,
                         /* lookup_in_resolved_boot_classes */ true);
}

bool ArtMethod::IsAnnotatedWith(jclass klass,
                                uint32_t visibility,
                                bool lookup_in_resolved_boot_classes) {
  Thread* self = Thread::Current();
  ScopedObjectAccess soa(self);
  StackHandleScope<1> shs(self);

  ObjPtr<mirror::Class> annotation = soa.Decode<mirror::Class>(klass);
  DCHECK(annotation->IsAnnotation());
  Handle<mirror::Class> annotation_handle(shs.NewHandle(annotation));

  return annotations::IsMethodAnnotationPresent(
      this, annotation_handle, visibility, lookup_in_resolved_boot_classes);
}

static uint32_t GetOatMethodIndexFromMethodIndex(const DexFile& dex_file,
                                                 uint16_t class_def_idx,
                                                 uint32_t method_idx) {
  const DexFile::ClassDef& class_def = dex_file.GetClassDef(class_def_idx);
  const uint8_t* class_data = dex_file.GetClassData(class_def);
  CHECK(class_data != nullptr);
  ClassDataItemIterator it(dex_file, class_data);
  it.SkipAllFields();
  // Process methods
  size_t class_def_method_index = 0;
  while (it.HasNextDirectMethod()) {
    if (it.GetMemberIndex() == method_idx) {
      return class_def_method_index;
    }
    class_def_method_index++;
    it.Next();
  }
  while (it.HasNextVirtualMethod()) {
    if (it.GetMemberIndex() == method_idx) {
      return class_def_method_index;
    }
    class_def_method_index++;
    it.Next();
  }
  DCHECK(!it.HasNext());
  LOG(FATAL) << "Failed to find method index " << method_idx << " in " << dex_file.GetLocation();
  UNREACHABLE();
}

// We use the method's DexFile and declaring class name to find the OatMethod for an obsolete
// method.  This is extremely slow but we need it if we want to be able to have obsolete native
// methods since we need this to find the size of its stack frames.
//
// NB We could (potentially) do this differently and rely on the way the transformation is applied
// in order to use the entrypoint to find this information. However, for debugging reasons (most
// notably making sure that new invokes of obsolete methods fail) we choose to instead get the data
// directly from the dex file.
static const OatFile::OatMethod FindOatMethodFromDexFileFor(ArtMethod* method, bool* found)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  DCHECK(method->IsObsolete() && method->IsNative());
  const DexFile* dex_file = method->GetDexFile();

  // recreate the class_def_index from the descriptor.
  std::string descriptor_storage;
  const DexFile::TypeId* declaring_class_type_id =
      dex_file->FindTypeId(method->GetDeclaringClass()->GetDescriptor(&descriptor_storage));
  CHECK(declaring_class_type_id != nullptr);
  dex::TypeIndex declaring_class_type_index = dex_file->GetIndexForTypeId(*declaring_class_type_id);
  const DexFile::ClassDef* declaring_class_type_def =
      dex_file->FindClassDef(declaring_class_type_index);
  CHECK(declaring_class_type_def != nullptr);
  uint16_t declaring_class_def_index = dex_file->GetIndexForClassDef(*declaring_class_type_def);

  size_t oat_method_index = GetOatMethodIndexFromMethodIndex(*dex_file,
                                                             declaring_class_def_index,
                                                             method->GetDexMethodIndex());

  OatFile::OatClass oat_class = OatFile::FindOatClass(*dex_file,
                                                      declaring_class_def_index,
                                                      found);
  if (!(*found)) {
    return OatFile::OatMethod::Invalid();
  }
  return oat_class.GetOatMethod(oat_method_index);
}

static const OatFile::OatMethod FindOatMethodFor(ArtMethod* method,
                                                 PointerSize pointer_size,
                                                 bool* found)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  if (UNLIKELY(method->IsObsolete())) {
    // We shouldn't be calling this with obsolete methods except for native obsolete methods for
    // which we need to use the oat method to figure out how large the quick frame is.
    DCHECK(method->IsNative()) << "We should only be finding the OatMethod of obsolete methods in "
                               << "order to allow stack walking. Other obsolete methods should "
                               << "never need to access this information.";
    DCHECK_EQ(pointer_size, kRuntimePointerSize) << "Obsolete method in compiler!";
    return FindOatMethodFromDexFileFor(method, found);
  }
  // Although we overwrite the trampoline of non-static methods, we may get here via the resolution
  // method for direct methods (or virtual methods made direct).
  mirror::Class* declaring_class = method->GetDeclaringClass();
  size_t oat_method_index;
  if (method->IsStatic() || method->IsDirect()) {
    // Simple case where the oat method index was stashed at load time.
    oat_method_index = method->GetMethodIndex();
  } else {
    // Compute the oat_method_index by search for its position in the declared virtual methods.
    oat_method_index = declaring_class->NumDirectMethods();
    bool found_virtual = false;
    for (ArtMethod& art_method : declaring_class->GetVirtualMethods(pointer_size)) {
      // Check method index instead of identity in case of duplicate method definitions.
      if (method->GetDexMethodIndex() == art_method.GetDexMethodIndex()) {
        found_virtual = true;
        break;
      }
      oat_method_index++;
    }
    CHECK(found_virtual) << "Didn't find oat method index for virtual method: "
                         << method->PrettyMethod();
  }
  DCHECK_EQ(oat_method_index,
            GetOatMethodIndexFromMethodIndex(*declaring_class->GetDexCache()->GetDexFile(),
                                             method->GetDeclaringClass()->GetDexClassDefIndex(),
                                             method->GetDexMethodIndex()));
  OatFile::OatClass oat_class = OatFile::FindOatClass(*declaring_class->GetDexCache()->GetDexFile(),
                                                      declaring_class->GetDexClassDefIndex(),
                                                      found);
  if (!(*found)) {
    return OatFile::OatMethod::Invalid();
  }
  return oat_class.GetOatMethod(oat_method_index);
}

bool ArtMethod::EqualParameters(Handle<mirror::ObjectArray<mirror::Class>> params) {
  auto* dex_cache = GetDexCache();
  auto* dex_file = dex_cache->GetDexFile();
  const auto& method_id = dex_file->GetMethodId(GetDexMethodIndex());
  const auto& proto_id = dex_file->GetMethodPrototype(method_id);
  const DexFile::TypeList* proto_params = dex_file->GetProtoParameters(proto_id);
  auto count = proto_params != nullptr ? proto_params->Size() : 0u;
  auto param_len = params != nullptr ? params->GetLength() : 0u;
  if (param_len != count) {
    return false;
  }
  auto* cl = Runtime::Current()->GetClassLinker();
  for (size_t i = 0; i < count; ++i) {
    auto type_idx = proto_params->GetTypeItem(i).type_idx_;
    auto* type = cl->ResolveType(type_idx, this);
    if (type == nullptr) {
      Thread::Current()->AssertPendingException();
      return false;
    }
    if (type != params->GetWithoutChecks(i)) {
      return false;
    }
  }
  return true;
}

const uint8_t* ArtMethod::GetQuickenedInfo(PointerSize pointer_size) {
  if (kIsVdexEnabled) {
    const DexFile& dex_file = GetDeclaringClass()->GetDexFile();
    const OatFile::OatDexFile* oat_dex_file = dex_file.GetOatDexFile();
    if (oat_dex_file == nullptr || (oat_dex_file->GetOatFile() == nullptr)) {
      return nullptr;
    }
    return oat_dex_file->GetOatFile()->GetVdexFile()->GetQuickenedInfoOf(
        dex_file, GetCodeItemOffset());
  } else {
    bool found = false;
    OatFile::OatMethod oat_method = FindOatMethodFor(this, pointer_size, &found);
    if (!found || (oat_method.GetQuickCode() != nullptr)) {
      return nullptr;
    }
    return oat_method.GetVmapTable();
  }
}

const OatQuickMethodHeader* ArtMethod::GetOatQuickMethodHeader(uintptr_t pc) {
  // Our callers should make sure they don't pass the instrumentation exit pc,
  // as this method does not look at the side instrumentation stack.
  DCHECK_NE(pc, reinterpret_cast<uintptr_t>(GetQuickInstrumentationExitPc()));

  if (IsRuntimeMethod()) {
    return nullptr;
  }

  Runtime* runtime = Runtime::Current();
  const void* existing_entry_point = GetEntryPointFromQuickCompiledCode();
  CHECK(existing_entry_point != nullptr) << PrettyMethod() << "@" << this;
  ClassLinker* class_linker = runtime->GetClassLinker();

  if (class_linker->IsQuickGenericJniStub(existing_entry_point)) {
    // The generic JNI does not have any method header.
    return nullptr;
  }

  if (existing_entry_point == GetQuickProxyInvokeHandler()) {
    DCHECK(IsProxyMethod() && !IsConstructor());
    // The proxy entry point does not have any method header.
    return nullptr;
  }

  // Check whether the current entry point contains this pc.
  if (!class_linker->IsQuickResolutionStub(existing_entry_point) &&
      !class_linker->IsQuickToInterpreterBridge(existing_entry_point)) {
    OatQuickMethodHeader* method_header =
        OatQuickMethodHeader::FromEntryPoint(existing_entry_point);

    if (method_header->Contains(pc)) {
      return method_header;
    }
  }

  // Check whether the pc is in the JIT code cache.
  jit::Jit* jit = runtime->GetJit();
  if (jit != nullptr) {
    jit::JitCodeCache* code_cache = jit->GetCodeCache();
    OatQuickMethodHeader* method_header = code_cache->LookupMethodHeader(pc, this);
    if (method_header != nullptr) {
      DCHECK(method_header->Contains(pc));
      return method_header;
    } else {
      DCHECK(!code_cache->ContainsPc(reinterpret_cast<const void*>(pc)))
          << PrettyMethod()
          << ", pc=" << std::hex << pc
          << ", entry_point=" << std::hex << reinterpret_cast<uintptr_t>(existing_entry_point)
          << ", copy=" << std::boolalpha << IsCopied()
          << ", proxy=" << std::boolalpha << IsProxyMethod();
    }
  }

  // The code has to be in an oat file.
  bool found;
  OatFile::OatMethod oat_method =
      FindOatMethodFor(this, class_linker->GetImagePointerSize(), &found);
  if (!found) {
    if (class_linker->IsQuickResolutionStub(existing_entry_point)) {
      // We are running the generic jni stub, but the entry point of the method has not
      // been updated yet.
      DCHECK_EQ(pc, 0u) << "Should be a downcall";
      DCHECK(IsNative());
      return nullptr;
    }
    if (existing_entry_point == GetQuickInstrumentationEntryPoint()) {
      // We are running the generic jni stub, but the method is being instrumented.
      // NB We would normally expect the pc to be zero but we can have non-zero pc's if
      // instrumentation is installed or removed during the call which is using the generic jni
      // trampoline.
      DCHECK(IsNative());
      return nullptr;
    }
    // Only for unit tests.
    // TODO(ngeoffray): Update these tests to pass the right pc?
    return OatQuickMethodHeader::FromEntryPoint(existing_entry_point);
  }
  const void* oat_entry_point = oat_method.GetQuickCode();
  if (oat_entry_point == nullptr || class_linker->IsQuickGenericJniStub(oat_entry_point)) {
    DCHECK(IsNative()) << PrettyMethod();
    return nullptr;
  }

  OatQuickMethodHeader* method_header = OatQuickMethodHeader::FromEntryPoint(oat_entry_point);
  if (pc == 0) {
    // This is a downcall, it can only happen for a native method.
    DCHECK(IsNative());
    return method_header;
  }

  DCHECK(method_header->Contains(pc))
      << PrettyMethod()
      << " " << std::hex << pc << " " << oat_entry_point
      << " " << (uintptr_t)(method_header->GetCode() + method_header->GetCodeSize());
  return method_header;
}

const void* ArtMethod::GetOatMethodQuickCode(PointerSize pointer_size) {
  bool found;
  OatFile::OatMethod oat_method = FindOatMethodFor(this, pointer_size, &found);
  if (found) {
    return oat_method.GetQuickCode();
  }
  return nullptr;
}

bool ArtMethod::HasAnyCompiledCode() {
  if (IsNative() || !IsInvokable() || IsProxyMethod()) {
    return false;
  }

  // Check whether the JIT has compiled it.
  Runtime* runtime = Runtime::Current();
  jit::Jit* jit = runtime->GetJit();
  if (jit != nullptr && jit->GetCodeCache()->ContainsMethod(this)) {
    return true;
  }

  // Check whether we have AOT code.
  return GetOatMethodQuickCode(runtime->GetClassLinker()->GetImagePointerSize()) != nullptr;
}

void ArtMethod::CopyFrom(ArtMethod* src, PointerSize image_pointer_size) {
  memcpy(reinterpret_cast<void*>(this), reinterpret_cast<const void*>(src),
         Size(image_pointer_size));
  declaring_class_ = GcRoot<mirror::Class>(const_cast<ArtMethod*>(src)->GetDeclaringClass());

  // If the entry point of the method we are copying from is from JIT code, we just
  // put the entry point of the new method to interpreter. We could set the entry point
  // to the JIT code, but this would require taking the JIT code cache lock to notify
  // it, which we do not want at this level.
  Runtime* runtime = Runtime::Current();
  if (runtime->UseJitCompilation()) {
    if (runtime->GetJit()->GetCodeCache()->ContainsPc(GetEntryPointFromQuickCompiledCode())) {
      SetEntryPointFromQuickCompiledCodePtrSize(GetQuickToInterpreterBridge(), image_pointer_size);
    }
  }
  // Clear the profiling info for the same reasons as the JIT code.
  if (!src->IsNative()) {
    SetProfilingInfoPtrSize(nullptr, image_pointer_size);
  }
  // Clear hotness to let the JIT properly decide when to compile this method.
  hotness_count_ = 0;
}

bool ArtMethod::IsImagePointerSize(PointerSize pointer_size) {
  // Hijack this function to get access to PtrSizedFieldsOffset.
  //
  // Ensure that PrtSizedFieldsOffset is correct. We rely here on usually having both 32-bit and
  // 64-bit builds.
  static_assert(std::is_standard_layout<ArtMethod>::value, "ArtMethod is not standard layout.");
  static_assert(
      (sizeof(void*) != 4) ||
          (offsetof(ArtMethod, ptr_sized_fields_) == PtrSizedFieldsOffset(PointerSize::k32)),
      "Unexpected 32-bit class layout.");
  static_assert(
      (sizeof(void*) != 8) ||
          (offsetof(ArtMethod, ptr_sized_fields_) == PtrSizedFieldsOffset(PointerSize::k64)),
      "Unexpected 64-bit class layout.");

  Runtime* runtime = Runtime::Current();
  if (runtime == nullptr) {
    return true;
  }
  return runtime->GetClassLinker()->GetImagePointerSize() == pointer_size;
}

std::string ArtMethod::PrettyMethod(ArtMethod* m, bool with_signature) {
  if (m == nullptr) {
    return "null";
  }
  return m->PrettyMethod(with_signature);
}

std::string ArtMethod::PrettyMethod(bool with_signature) {
  ArtMethod* m = this;
  if (!m->IsRuntimeMethod()) {
    m = m->GetInterfaceMethodIfProxy(Runtime::Current()->GetClassLinker()->GetImagePointerSize());
  }
  std::string result(PrettyDescriptor(m->GetDeclaringClassDescriptor()));
  result += '.';
  result += m->GetName();
  if (UNLIKELY(m->IsFastNative())) {
    result += "!";
  }
  if (with_signature) {
    const Signature signature = m->GetSignature();
    std::string sig_as_string(signature.ToString());
    if (signature == Signature::NoSignature()) {
      return result + sig_as_string;
    }
    result = PrettyReturnType(sig_as_string.c_str()) + " " + result +
        PrettyArguments(sig_as_string.c_str());
  }
  return result;
}

std::string ArtMethod::JniShortName() {
  return GetJniShortName(GetDeclaringClassDescriptor(), GetName());
}

std::string ArtMethod::JniLongName() {
  std::string long_name;
  long_name += JniShortName();
  long_name += "__";

  std::string signature(GetSignature().ToString());
  signature.erase(0, 1);
  signature.erase(signature.begin() + signature.find(')'), signature.end());

  long_name += MangleForJni(signature);

  return long_name;
}

// AssertSharedHeld doesn't work in GetAccessFlags, so use a NO_THREAD_SAFETY_ANALYSIS helper.
// TODO: Figure out why ASSERT_SHARED_CAPABILITY doesn't work.
template <ReadBarrierOption kReadBarrierOption>
ALWAYS_INLINE static inline void DoGetAccessFlagsHelper(ArtMethod* method)
    NO_THREAD_SAFETY_ANALYSIS {
  CHECK(method->IsRuntimeMethod() ||
        method->GetDeclaringClass<kReadBarrierOption>()->IsIdxLoaded() ||
        method->GetDeclaringClass<kReadBarrierOption>()->IsErroneous());
}

template <ReadBarrierOption kReadBarrierOption> void ArtMethod::GetAccessFlagsDCheck() {
  if (kCheckDeclaringClassState) {
    Thread* self = Thread::Current();
    if (!Locks::mutator_lock_->IsSharedHeld(self)) {
      if (self->IsThreadSuspensionAllowable()) {
        ScopedObjectAccess soa(self);
        CHECK(IsRuntimeMethod() ||
              GetDeclaringClass<kReadBarrierOption>()->IsIdxLoaded() ||
              GetDeclaringClass<kReadBarrierOption>()->IsErroneous());
      }
    } else {
      // We cannot use SOA in this case. We might be holding the lock, but may not be in the
      // runnable state (e.g., during GC).
      Locks::mutator_lock_->AssertSharedHeld(self);
      DoGetAccessFlagsHelper<kReadBarrierOption>(this);
    }
  }
}
template void ArtMethod::GetAccessFlagsDCheck<ReadBarrierOption::kWithReadBarrier>();
template void ArtMethod::GetAccessFlagsDCheck<ReadBarrierOption::kWithoutReadBarrier>();

}  // namespace art
