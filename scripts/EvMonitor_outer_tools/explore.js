//hook指定函数
/*
function hookFunctionByName(module, func, hook_code){
    var func_addr = Module.findExportByName(module, func);
    if(func_addr==null){
        send('no func');
        return;
    }
    Interceptor.attach(func_addr, hook_code);
}
*/
/*
log_file = new File('/data/data/top.january147.noticer/test.log', 'a+');
log_file.write('pid is' + Process.id + '\n');
log_file.close();
*/
console.log('EvMonitor:frida log system');
/*
hook_code={
    onEnter:function(args){
        name = Memory.readUtf8String(args[0])
        log_file.write('load library:' + name + '\n');
        log_file.flush();
    }
}

hookFunctionByName('libc.so', 'dlopen', hook_code);
*/