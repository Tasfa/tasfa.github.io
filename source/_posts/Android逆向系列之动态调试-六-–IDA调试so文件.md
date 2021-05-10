---
title: Android逆向系列之动态调试-六-–IDA调试so文件
date: 2016-06-07 09:49:25
tags: Android逆向
categories: 逆向分析
---

### 一、Android Server 准备工作

1. 根据手机位数,选择对应的android_server(ida/dbgsrv)
2. 将其push到手机(adb push android_server /data/local/tmp)
3. 赋予执行权限(adb shell chmod 777 an_ser)


### 二、直接附加调试

1. 启动Android_server
2. 端口转发(adb forward tcp:23946 tcp:23946) 
3. 启动欲调试APK(adb shell am start -n {pkgname}/{Activity}) 
4. 启动IDA，打开debugger->attach->remote Armlinux/andoid debugger
5. 填写host和端口，选择进程，attach

### 二、反反调试调试
1. 启动Android_server
2. 端口转发(adb forward tcp:23946 tcp:23946)
3. 调试模式启动Apk(adb shell am start -D -n {pkgname}/{Activity}) 
4. 启动IDA，打开debugger->attach->remote Armlinux/andoid debugger
5. 填写host和端口,选择进程,attach
7. 端口转发(adb forward tcp:8700 jdwp:{pid}) 或者 打开DDMS,选择对应进程
8. JDB桥接(jdb -connect "com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8700")
6. 下断点,按F9运行


RUN -- 启动一个新的进程 调试比如 Android下的二进制程序
ATTACH -- 附加到一个已经运行到进程 调试比如 运行的APK

