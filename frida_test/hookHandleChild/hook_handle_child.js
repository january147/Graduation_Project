/*
Java.perform(function(){

    var zygoteConnection = Java.use("com.android.internal.os.ZygoteConnection");
    zygoteConnection.handleChildProc.implementation = function(parsedArgs, descriptors, pipeFd){
        send(parsedArgs.niceName);
        return this.handleChildProc(parsedArgs, descriptors, pipeFd)
    };

});
*/


classes = Java.enumerateLoadedClassesSync();
for(var i=0;i<classes.length;i++){
    send(classes[i]);
}
