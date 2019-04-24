//获取所有导出函数
function listExportFunction(module_name){
    var module = Process.findModuleByName(module_name);
    send(module.name);
    var exports = module.enumerateExports();
    for(var i=0;i<exports.length;i++){
        send(exports[i].name);
    }
}
//获取所有导入函数
function listImportFunction(module_name){
    var module = Process.findModuleByName(module_name);
    send(module.name);
    var exports = module.enumerateImports();
    for(var i=0;i<exports.length;i++){
        send(exports[i].name);
    }
}
//简单的hook逻辑
simple_hook_code = {
    onEnter:function(args){
        send(func + ' called');
    }
}

//hook指定函数
function hookFunctionByName(module, func, hook_code){
    var func_addr = Module.findExportByName(module, func);
    if(func_addr==null){
        send('no func');
        return;
    }
    Interceptor.attach(func_addr, hook_code);
}
//读取String类型字符串
function readStdString (str) {
    const isTiny = (Memory.readU8(str) & 1) === 0;
    if (isTiny) {
      return Memory.readUtf8String(str.add(1));
    }  
    return Memory.readUtf8String(Memory.readPointer(str.add(2 * Process.pointerSize)));
}

function listModules(){
    modules = Process.enumerateModules();
    for(var i=0;i<modules.length;i++){
        send(modules[i].name);
    }
}


options = {
    events: {
        exec:true
    },
    onReceive: function (events) {
        send(Stalker.parse(events, {
          annotate: true, // to display the type of event
          stringify: true
            // to format pointer values as strings instead of `NativePointer`
            // values, i.e. less overhead if you're just going to `send()` the 
            // thing not actually parse the data agent-side
        }));
      },
    
};
    

code = {
    onEnter: function(args){
        Stalker.follow(Process.getCurrentThreadId(), options);
    },
    onLeave: function(ret){
        Stalker.unfollow();
        Interceptor.detachAll();
    }
}

Java.perform(function(){
    mainact = Java.use('top.january147.noticer.MainActivity');
    mainact.onButton1Click.implementation = function(view){
        Stalker.follow(Process.getCurrentThreadId(), options);
        send('stalker on');
        this.onButton1Click(view);
        Stalker.unfollow();
        send('stalker off');
    }
})
