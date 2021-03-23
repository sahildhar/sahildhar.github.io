---
layout: default
tag: frida_snippets
title: Frida snippets I wrote in past
---

Following are some of the frida snippets I have written in past to bypass some of the client-side checks in android apps.

#### **Decrypting SQLCipher Encrypted Databases**

```js

/*
Modifications: Change <app_name> accordingly
*/

Java.perform(function () {
    var random_name = function (length) {
        var result = '';
        var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var charactersLength = characters.length;
        for (var i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
    Java.choose("net.sqlcipher.database.SQLiteDatabase", {
        onMatch: function (ins) {
            console.log(ins.getPath());
            console.log(ins.isOpen());
            var dbName = random_name(5);
            var sql1 = String.$new("ATTACH DATABASE '/data/user/0/<app_name>/databases/" + dbName + ".sql.plaintext' as " + dbName + " KEY '';");
            var sql2 = String.$new("SELECT sqlcipher_export('" + dbName + "');");
            var sql3 = String.$new("DETACH DATABASE " + dbName);
            ins.rawExecSQL(sql1);
            ins.rawExecSQL(sql2);
            ins.rawExecSQL(sql3);
            console.log("Found SqlCipherDatabaseProvider instance");
        },
        onComplete: function (ins) { }
    });
})
```

#### **SSL pinning bypass implemented via okhttp3**

```js
Java.perform(function(){

    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check$okhttp.overload('java.lang.String', 'kotlin.jvm.functions.Function0').implementation = function(x, y) {
        console.log("[+] OkHTTP 3 check$okhttp() bypassed.");
        
    };
})
```


#### **Detect keystore access without authentication**

```js
/*
Modifications: <keystore class> : Change keystore class name accordingly
Output: prints keys stored in keystore in a device's locked state 
*/

function hookCipherInit(){
    var _cipher = Java.use("javax.crypto.Cipher")
    _cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function(mode, key){
        console.log(printModes(mode));
        hookGetkey();
        return this.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").apply(this, arguments);
    }
}

function printModes(mode){
    if (mode == 1){
        return "\nEncrypt Mode"
    } else if(mode == 2){  
        return "\nDecrypt Mode"
    }
}

function hookGetkey(){
    var secretStore = Java.use("<keystore class>")
    secretStore.getKey.implementation = function(keyName){
        console.log(keyName);
        return this.getKey.apply(this,arguments)
    }
}

function hookCipherDoFinal() {
    var _cipher = Java.use('javax.crypto.Cipher');
    _cipher.doFinal.overload("[B").implementation = function (byteArr) {
        var result = this.doFinal(byteArr);
        javaHexdump(result);
        return result;
    }
}

function javaHexdump(array) {
    var ptr = Memory.alloc(array.length);
    for(var i = 0; i < array.length; ++i)
        Memory.writeS8(ptr.add(i), array[i]);
    console.log(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: true}));
}

Java.perform(function(){
    hookCipherInit()
    hookCipherDoFinal();
});
```

#### **SSL pinning bypass for CURL specific implementation**

```js
/*
- Steps:
- Obtain the base address of example_so_lib
- Obtain the binary offset from IDA pro
- add the binary offset to lib base to obtain the function pointer for function curl_easy_setopt()
- Based on the second argument / curl setting passed overwite the third argument passed to the function
*/
function dump_address(addr) {
    var i = 0;
    var pc = ptr(addr)
    console.log("Dumping addr: " + addr);
    while (i < 20) {
        var instr = Instruction.parse(pc);
        var caddr = instr['address'];
        var cinstr = instr.toString();
        console.log(caddr + " " + cinstr);
        pc = ptr(instr['next'])
        i += 1;
    }
}


function disableSSLPinning() {
    var libProcess = Process.findModuleByName("example_so_lib.so");
    var curl_opt_offset = libProcess.base.add(0x1AFFFFF);
    console.log("libProcess module is loaded at " + libProcess.base.toString())
    var verifyPeerEnabled = libProcess.base.add(0x02BFFFFF);
    var verifyPeerDisabled = libProcess.base.add(0x03BFFFFF);
    var verifyHostEnabled = libProcess.base.add(0x04CFFFFF);
    var verifyHostDisabled = libProcess.base.add(0x05DFFFFF);


    Interceptor.attach(curl_opt_offset, {
        onEnter: function (args) {
            this.arg1 = args[1];
            this.arg2 = args[2];

        },
        onLeave: function (retval) {
            // CURLOPT_SSL_CIPHER_LIST = 0x2763
            if (this.arg1.toString() == "0x2763") {
                console.log("[+] Patching curl_easy_setopt:CURLOPT_SSL_CIPHER_LIST");
                console.log(ptr(this.arg2).readUtf8String())
                console.log("[+] arg2 is referenced from: " + this.arg2);
                console.log("[+] Previous Cipher suite value: " + ptr(this.arg2).readCString());
                if (ptr(this.arg2).readCString() == "<cipher_name>") {
                    ptr(this.arg2).writeUtf8String("DEFAULT\x00");
                    console.log("[+] Replaced cipher suite to default");
                }else{
                    console.log("[I] Priting second argument anyway");
                    console.log(ptr(this.arg2).readCString());
                }
            }

            if (this.arg1 == 0x40) {

                console.log("[+] Patching curl_easy_setopt:CURLOPT_SSL_VERIFYPEER");
                Memory.protect(verifyPeerEnabled, 4, 'rwx');
                var b_array = verifyPeerEnabled.readByteArray(4);
                console.log(b_array);
                verifyPeerEnabled.writeByteArray(verifyPeerDisabled.readByteArray(4));
                console.log('[+] Patched state peer verification');
                var b_array = verifyPeerEnabled.readByteArray(4);
                console.log(b_array);
                Memory.protect(verifyPeerEnabled, 4, 'r-x');
            }
            if (this.arg1 == 0x51) {
                console.log("[+] Patching curl_easy_setopt:CURLOPT_SSL_VERIFYHOST");
                Memory.protect(verifyHostEnabled, 4, 'rwx');
                var b_array = verifyHostEnabled.readByteArray(4);
                console.log(b_array);
                verifyHostEnabled.writeByteArray(verifyHostDisabled.readByteArray(4));
                console.log('[+] Patched state host verification');
                var b_array = verifyHostEnabled.readByteArray(4);
                console.log(b_array);
                Memory.protect(verifyHostEnabled, 4, 'r-x');
            }
            return retval;
        }
    });
}

Java.perform(function () {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const VMStack = Java.use('dalvik.system.VMStack');

    System.loadLibrary.implementation = function (library) {
        try {
            if (library == "<another_lib>") {
                // Ensuring that example_so_lib.so is being loaded
                disableSSLPinning()
            }
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
            return loaded;
        } catch (ex) {
            console.log(ex);
        }
    };
});
```

