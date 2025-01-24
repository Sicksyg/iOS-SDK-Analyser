
function run_show_classes_of_app(){
    if (ObjC.available) { // Checks for ObjC codebase

        console.log("[F] Started: Find Classes")
        var count = 0
        var list = []
        for (var className in ObjC.classes)
        {
            if (ObjC.classes.hasOwnProperty(className))
            {   
                // console.log("[+] Class: " + className);
                list.push(className)
                count = count + 1
            }
        }
        send(list)
        // console.log(list)
        console.log("\n[F] Classes found: " + count);
        console.log("[F] Completed: Find Classes")
    
    } else {
        if (Swift.available) {
            console.log("Swift runtime IS available.")
        } else {
            console.log("[F] ERROR: Objective-C runtime is not available.")
        }
    };
}

function show_classes_of_app()
{
	setImmediate(run_show_classes_of_app)
}

show_classes_of_app()