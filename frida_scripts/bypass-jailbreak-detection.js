// Script for bypassing jailbreak detection in iOS apps. Not finihed yet.
// Forked from https://github.com/rubaljain/frida-jb-bypass

if (ObjC.available) {
    try {
        //Your class name here - This is the class which contains the method you want to hook
        // Should be found dynamically or from a list of known classes

        var className = "";
        //Your function name here
        //Same as above, should be found dynamically or from a list of known functions

        var funcName = "";
        var hook = eval('ObjC.classes.' + className + '["' + funcName + '"]');
        Interceptor.attach(hook.implementation, {
            onLeave: function (retval) {
                console.log("[*] Class Name: " + className);
                console.log("[*] Method Name: " + funcName);
                console.log("\t[-] Return Value: " + retval);


                //For modifying the return value
                newretval = ptr("0x0") //your new return value here
                retval.replace(newretval)
                console.log("\t[-] New Return Value: " + newretval)
            }
        });
    }
    catch (err) {
        console.log("[!] Exception2: " + err.message);
    }
}
else {
    console.log("Objective-C Runtime is not available!");
}
