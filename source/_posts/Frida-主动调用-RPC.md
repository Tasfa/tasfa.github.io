---
title: Frida-主动调用(RPC)
date: 2021-05-10 14:16:34
tags: Frida
categories:
	- 代码干预
	- Hook
	- Frida
---

### 概述

此Post讲述如何利用Frida主动调用Java函数以及Native函数。

- Context获取
- 类新构造
- Native指针构造
- ...

<!-- more -->

### Frida主动调用Java函数
js脚本:

```javascript
rpc.exports = {
    myfunc: function(queryId){
        Java.perform(function(){
            try{
                var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
                var context = currentApplication.getApplicationContext();

                var classJq = Java.use("a.b.c.jq");
                var objJq = classJq.a(context,"param");

                var HashSet = Java.use("java.util.HashSet");
                var idSet = HashSet.$new();

                var Integer = Java.use("java.lang.Integer");
                idSet.add(Integer.valueOf(queryId));       
            }catch(e){
                console.log(e)
            }
        });
    }
}
```

py脚本

```python
#coding:utf-8

import time,os
import frida

def adb_forward():
    os.system("adb forward tcp:27042 tcp:27042")
    os.system("adb forward tcp:27043 tcp:27043")

def my_message_handler(message, payload):
    print(message)
    print(payload)

adb_forward()
rdev = frida.get_remote_device()
session = rdev.attach("com.xxx.xx")

with open("rpcCall.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)
script.load()

idList = [1234]
idList.sort()

for idx in idList:
    rel = script.exports.myfunc(idx)
```


### frida主动调用Native函数
待解决