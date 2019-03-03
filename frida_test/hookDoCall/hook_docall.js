//获取所有导出函数
function listFunction(module_name){
    var module = Process.findModuleByName(module_name);
    send(module.name);
    var exports = module.enumerateExports();
    for(var i=0;i<exports.length;i++){
        send(exports[i].name);
    }
}

//简单hook
function hookFunctionByName(module, func){
    var func_addr = Module.findExportByName(module, func)
    Interceptor.attach(func_addr,{
        onEnter:function(args){
            send(func + ' called');
        }
    })
}

hookFunctionByName('libc.so','write')
//listFunction('libc++.so');

/*
do_call_funcs = ['_ZN3art11interpreter6DoCallILb1ELb0EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE',
'_ZN3art11interpreter6DoCallILb1ELb1EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE'];

pretty_method_funcs = ['_ZN3art9ArtMethod12PrettyMethodEPS0_b', '_ZNK3art7DexFile12PrettyMethodEjb', '_ZN3art9ArtMethod12PrettyMethodEb'];

notice = ['docall0', 'docall1'];

lib = 'libart.so';

index = 0;

pretty_method_address = Module.findExportByName(lib, pretty_method_funcs[0]);
send('pretty_method at ' + pretty_method_address);
pretty_method = new NativeFunction(pretty_method_address, 'pointer', ['pointer','pointer','uint8'], 'default');

var docall = Module.findExportByName(lib, do_call_funcs[0]);
if(docall != null){
    send('docall at ' + docall);
}else{
    send('no func');
}

function readStdString (str) {
  const isTiny = (Memory.readU8(str) & 1) === 0;
  if (isTiny) {
    return Memory.readUtf8String(str.add(1));
  }

  return Memory.readUtf8String(Memory.readPointer(str.add(2 * Process.pointerSize)));
}

Interceptor.attach(docall, {
    onEnter:function(args){
        send('arg0 ' + args[0].toString());
        var method = pretty_method(args[0], ptr(args[0]), 0);
        send(readStdString(method))
        Thread.sleep(2)
    },
    onLeave:function(args){
        send('docall end');
    }
});
*/