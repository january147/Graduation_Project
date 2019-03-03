import frida
import sys
import time

jscode = """
var f = new NativeFunction(ptr('%s'), 'bool', ['int']);
f(1);
/*
Interceptor.attach(ptr(%s), {
    onEnter: function(args) {
        send('the arg is ' + args[0].toInt32());
    },
    onLeave: function(retval) {
        send('leave this function');
    }
});
*/
"""
hookPrintfcode="""
var write_address = Module.findExportByName('libc.so.6', 'write');
var st = Memory.allocUtf8String('你的write函数已经被劫持了\\n');
if(write_address != null){
    send('write is at' + write_address)
    Interceptor.attach(write_address, {
        onEnter: function(args) {
            send(args[0].toString()+ ' ' + args[1].toString() + ' ' + args[2].toString());
            args[1] = st;
            args[2] = ptr('36');
          
        },
        onLeave: function(retval) {
            
        }
        
    });
}else{
    send('no such function');
}
"""

session = frida.attach(int(sys.argv[1]))
# script = session.create_script(hookPrintfcode)
script = session.create_script(jscode % (int(sys.argv[2], 16),int(sys.argv[2], 16)))
def on_message(message, data):
    if message['type'] == 'send':
        print(message['payload'])
    else:
        print(message['stack'])
script.on('message', on_message)
script.load()
while True:
    time.sleep(1000)
#sys.stdin.read()
