---
title: Jeb分析总结
date: 2021-05-10 14:44:59
tags: jeb
categories:
	- 代码分析
	- 静态分析
---

### JEB使用

#### 整体界面:

![](https://www.pnfsoftware.com/jeb/manual/img/jeb-raasta-apk.png)

<!--more-->

#### 整体UI名词解释:

![](https://www.pnfsoftware.com/jeb/manual/img/jeb-raasta.png)

#### Action & Hotkey:

![](https://www.pnfsoftware.com/jeb/manual/img/jeb-menu-actions-basic.png)

**Tip:** 

* Ctrl+Space 查看历史命名.
* None input 修改为原始名称

#### Navigating & Hotkey

![](https://www.pnfsoftware.com/jeb/manual/img/jeb-menu-nav.png)


#### Native Code Actions

![](https://www.pnfsoftware.com/jeb/manual/img/jeb-menu-actions-native.png)

### 静态分析

#### 什么是静态分析
<p>静态分析是指在不运行代码的情况下，采用词法分析、语法分析等各种技术手段对程序文件进行扫描从而生成程序的反汇编代码，然后阅读反汇编代码来掌握程序功能的一种技术。</p>

静态分析Android程序分以下几种:

Java层:

(1)阅读baksmali反汇编生成的Dalvik字节码，即分析smali文件

(2)阅读dex2jar/jd-gui反汇编生成的Java源码

Native层:

(3)阅读IDA Pro反汇编生成的SO文件ARM汇编代码

(4)阅读IDA Pro(F5)反汇编生成的so文件的c/c++源码


#### 定位关键代码
##### AndroidManifest.xml文件
该文件记录着软件的一些基本信息，包括软件的包名、运行的系统版、用到的组件等等

##### 信息反馈法
指先运行目标程序，然后根据程序运行时给出的反馈信息作为突破口寻找关键代码
一般情况下，字符串会存储在String.xml文件或者硬编码到程序代码中，可用ID形式访问或直接搜索字符串

(A)IDA下搜索特定字符串方法:

Ctrl+s 打开段选择对话框->双击String段跳转到字符串段->search-text（ALT+T）

(B)APKIDE下搜索特定字符串方法:

直接在右边窗口输入字符串进行搜寻，同时右键可对其进行编码或转换进制

##### 特征函数法
所谓特征函数法，意思就是我们根据程序的执行行为来判断程序可能调用了哪些函数。这一方法需要我们对于 Android 中的 API 比较熟悉。一般来说，我们可能会关注以下方面

* 控件的事件函数
*     onclick
*     show
*     Toast
* 网络函数
*     HttpGet
*     HttpPost
*     HttpUriRequest
*     socket
* 发送短信
* 打电话
* 定位
* 等等

##### 顺序查看法
从OnCreate()函数切入，如果没有混淆可从main()函数切入，弄清程序的流程，IDA提供强大的帮助界面

##### log信息法

所谓 log 信息就是 Android 程序在运行时输出的字符串信息，这部分信息不会在我们的界面上体现，因而我们需要使用其它辅助工具来分析，比如说，我们可以使用 ddms 来辅助分析。对于 log 信息来说，我们可以从两个方面考虑

* 利用程序本身产生的 log 信息
* 自己对代码反编译，插入 log 信息，并重打包来进行分析。

##### 栈跟踪法

我们可以用 ddms 提供的方法调用链的信息来判断程序目前的调用关系如何。

##### 钩子(Hook)法

* xposed
* cydia

##### monitor方法

* 运行 log，程序运行产生的，系统运行产生的
* 线程跟踪
* 方法调用链


### JEB静态分析实战
 
2014 ASIS Cyber Security Contest Finals Numdroid

#### 判断文件类型

首先利用 file 命令判断一下文件类型，发现是个压缩包，解压缩一下，得到对应的文件，然后继续看一下，发现该文件是 apk 文件。

#### 安装程序

安装一下程序。简单看一下页面，可以发现程序主要是输入0-9数字密码，然后登陆。如果输入错的话会爆出 "Wrong Password" 的信息。

#### 分析程序

1、根据相应的字符串来定位一下源程序中的关键函数。根据 strings.xml 可以发现该字符串的变量名为 wrong，继而我们找到了如下代码。

2、也可以直接切入入口函数OnCreate函数进行流程分析。


``` java
    protected void ok_clicked() {
        DebugTools.log("clicked password: " + this.mScreen.getText());
        boolean result = Verify.isOk(this, this.mScreen.getText().toString());
        DebugTools.log("password is Ok? : " + result);
        if (result) {
            Intent i = new Intent(this, LipSum.class);
            Bundle b = new Bundle();
            b.putString("flag", this.mScreen.getText().toString().substring(0, 7));
            i.putExtras(b);
            startActivity(i);
            return;
        }
        Toast.makeText(this, R.string.wrong, 1).show();
        this.mScreen.setText("");
    }
```

继续定位到 Verify.isOk 中。如下

```java
    public static boolean isOk(Context c, String _password) {
        String password = _password;
        if (_password.length() > 7) {
            password = _password.substring(0, 7);
        }
        String r = OneWayFunction(password);
        DebugTools.log("digest: " + password + " => " + r);
        if (r.equals("be790d865f2cea9645b3f79c0342df7e")) {
            return true;
        }
        return false;
    }
```

可以发现程序主要是取 password 的前 7 位进行 OneWayFunction 加密，然后与 be790d865f2cea9645b3f79c0342df7e 进行比较。如果相等就会返回 true。这里我们再看一下 OneWayFunction，如下

```java
    private static String OneWayFunction(String password) {
        List<byte[]> bytes = ArrayTools.map(ArrayTools.select(ArrayTools.map(new String[]{"MD2", "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"}, new AnonymousClass1(password)), new SelectAction<byte[]>() {
            public boolean action(byte[] element) {
                return element != null;
            }
        }), new MapAction<byte[], byte[]>() {
            public byte[] action(byte[] element) {
                int i;
                byte[] b = new byte[8];
                for (i = 0; i < b.length / 2; i++) {
                    b[i] = element[i];
                }
                for (i = 0; i < b.length / 2; i++) {
                    b[(b.length / 2) + i] = element[(element.length - i) - 2];
                }
                return b;
            }
        });
        byte[] b2 = new byte[(bytes.size() * 8)];
        for (int i = 0; i < b2.length; i++) {
            b2[i] = ((byte[]) bytes.get(i % bytes.size()))[i / bytes.size()];
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            digest.update(b2);
            byte[] messageDigest = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte aMessageDigest : messageDigest) {
                String h = Integer.toHexString(aMessageDigest & MotionEventCompat.ACTION_MASK);
                while (h.length() < 2) {
                    h = "0" + h;
                }
                hexString.append(h);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return "";  // 注意这里，如果算法不存在的话，应该是会返回空字符串
        }
    }
```

函数大概就是执行了几个hash函数，由于Hash函数是不可逆的，因此这道题的唯一解法必然是爆破，这是很明显的一道爆破题。

由于代码中没有过度混淆且逻辑比较清晰，以及Hash算法并非自定义算法，涉及到的主要流程比较少，因此我们可以直接把Verify类抠出来直接跑。

#### 构造程序
提取出 java 程序之后，在 Verify 类中添加 main 函数并修复部分错误，从而得到对应的答案。

需要注意的点是，由于Hash算法不存在的话，会返回空字符串，因此PC端和Android可能出现相同算法出现不同的结果，原因就在这里。

输入之后得到结果

然后我们计算对应的 MD 值，从而获得 flag 为 ASIS_{3c56e1ed0597056fef0006c6d1c52463}


### 参考
IDA使用,参考书籍<a href="http://bbs.pediy.com/showthread.php?t=187367" target="_blank">《IDA Pro权威指南》</a> 

<a href="http://www.360doc.com/content/06/0821/08/1130_186349.shtml" target="_blank">查看IDA简易教程</a>

JEB官网: [JEB](https://www.pnfsoftware.com/jeb/)

JEB用户手册: [Manual](https://www.pnfsoftware.com/jeb/manual/)

JEB Api: [Apidoc](https://www.pnfsoftware.com/jeb/apidoc/reference/packages.html)（a developer portal for advanced users who will want to use the JEB API to script tasks, develop plugins, or even craft their own front-ends）

JEB Blog: [Blog](https://www.pnfsoftware.com/blog/category/jeb2/api-jeb2/)
(We recommend visiting our blog for additional, pointed resources describing a variety of use cases.)

本文属学习笔记原创，转载请注明出处tasfa.cn,如有问题，请联系管理员root@tasfa.cn
