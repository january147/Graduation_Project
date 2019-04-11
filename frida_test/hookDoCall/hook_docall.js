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
//读取String类型字符串
function readStdString (str) {
    const isTiny = (Memory.readU8(str) & 1) === 0;
    if (isTiny) {
      return Memory.readUtf8String(str.add(1));
    }
  
    return Memory.readUtf8String(Memory.readPointer(str.add(2 * Process.pointerSize)));
  }

function getPrettyMethod(){
    pretty_method_funcs = ['_ZN3art9ArtMethod12PrettyMethodEPS0_b', '_ZNK3art7DexFile12PrettyMethodEjb', '_ZN3art9ArtMethod12PrettyMethodEb'];
    lib = 'libart.so';
    pretty_method_address = Module.findExportByName(lib, pretty_method_funcs[0]);
    pretty_method = new NativeFunction(pretty_method_address, 'pointer', ['pointer', 'pointer', 'bool'])
    return pretty_method
}

function hook(){
    invoke_address = Module.findExportByName('libart.so','_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc')
    pretty_method = getPrettyMethod()
    Interceptor.attach(invoke_address, {
        onEnter:function(args){
            send('ArtMethod is at '+args[0])
            var method = pretty_method(args[0], args[0], 1);
            send(readStdString(method))
        },
        onLeave:function(retval){
            
        }

    });
/*
    do_call_funcs = ['_ZN3art11interpreter6DoCallILb1ELb0EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE',
'_ZN3art11interpreter6DoCallILb1ELb1EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE'];
    var docall = Module.findExportByName('libart.so', do_call_funcs[0]);
    Interceptor.attach(docall, {
        onEnter:function(args){
            send('ArtMethod is at '+args[0])
            //var method = pretty_method(args[0], args[0], 1);
            //send(readStdString(method))
        },
    });
*/
}
hook()

/*
do_call_funcs = ['_ZN3art11interpreter6DoCallILb1ELb0EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE',
'_ZN3art11interpreter6DoCallILb1ELb1EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE'];

pretty_method_funcs = ['_ZN3art9ArtMethod12PrettyMethodEPS0_b', '_ZNK3art7DexFile12PrettyMethodEjb', '_ZN3art9ArtMethod12PrettyMethodEb'];

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



printf_address = Module.findExportByName('libc.so', 'printf')
printf = new NativeFunction(printf_address, 'pointer', ['pointer'])
msg = Memory.allocUtf8String('hello\n')

Interceptor.attach(docall, {
    onEnter:function(args){
        send('arg0 ' + args[0].toString());
        var method = pretty_method(args[0], args[0], 0);
        send(readStdString(method))
    },
    onLeave:function(args){
        send('docall end');
    }
});
*/
