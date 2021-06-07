---
title: IDA分析总结
date: 2021-05-10 14:45:11
tags: ida
categories:
	- 代码分析
	- 动态调试
---

### 整体界面
![](/Users/tasfa/Desktop/桌面/android培训&分享/部门培训/class3/ida_main.png)

**File , Edit , Jump , Search , View , Debugger , Options , Windows , Help** 9个Tab菜单

* 1.File 文件操作相关、脚本操作相关、snapshot相关操作
* 2.Edit 功能比较多，主要涉及修改查询注释等
* 3.Jump 是用来跳转的，可以有很多种类型的跳转，比如跳转到上一个位置或者下一个位置，跳转到某个指定的地址。还可以根据名字，函数来进行跳转，跳转到一个新的窗口，跳转某一个偏移量等等
* 4.Serach 搜索相关操作
* 5.View 是用来选择显示方式的，或者显示某一特定模块信息的。比如以树形逻辑图显示，或者16进制形式显示。还可以单独显示某一特定信息，比如输入或者输出表等。
* 6.Debugger 动态调试
* 7.Options 在这里可以进行一下常规性的设置
* 8.Windows 窗口相关的一些操作
* 9.Help 使用IDA的一些帮助文档，检查更新等等。

<!-- more -->

### 加载文件界面

![](/Users/tasfa/Desktop/桌面/android培训&分享/部门培训/class3/load_file.png)

### 加载后界面

![](/Users/tasfa/Desktop/桌面/android培训&分享/部门培训/class3/ida_load_in.png)

* Function window:列举了IDA识别的每一个函数，**双击**函数可实现跳转。
* IDA View-A:反汇编窗口，分为图形模式与文本模式，通过**空格(space)**可以进行切换。
* Hex View-1:十六进制窗口，与IDA View进行配套，通过右键可以调整数据展示，**F2快捷键**可以修改数据（常用于动态调试 nop 命令 – 00 00 A0 E1）。
* Structures:数据结构窗口，主要是应用自定义实现的一些数据结构体
* Enums:枚举数窗口，显示一些枚举值
* Imports:导入窗口，列出文件导入的函数，即调用的外部函数
* Exports:导出窗口，列出文件的入口点，双击导出条目可实现跳转。
* Strings:字符串窗口，**Shift + F12** 显示从文件中提取出来的字符串以及字符串所在地址，双击导出条目可实现跳转。右键Setup 可以修改匹配条件（Ignore instructions/data definitions 忽略指令/数据定义，勾选此项，会使IDA扫描指令和现有数据定义中的字符串）
* Function Calls:函数调用窗口，可以看到所有调用该函数的位置和当前函数做出的全部调用
* Output window:日志输出窗口，命令结果输出窗口，脚本结果输出窗口等
* 其他子窗口:

![](/Users/tasfa/Desktop/桌面/android培训&分享/部门培训/class3/view.png)

### ToolBar工具栏

![](/Users/tasfa/Desktop/桌面/android培训&分享/部门培训/class3/tab_bar.png)

主要涉及一些快捷操作，方便使用者进行快捷操作

可在**Edit-->Toolbar**中选择自定义的工具栏

### Navigation Band导航条

![](/Users/tasfa/Desktop/桌面/android培训&分享/部门培训/class3/fastNavbar.png)

* 颜色条对应下面有颜色的注释，如蓝色:常规函数等
* 最右边为可选择的匹配和标记项，可标记如入口点等等
* Options-->colos-->Navigation Band可更改自定义的颜色


### IDA实战分析

### 基本方法

静态分析原生层程序基本的过程如下

1. 直接解压提取 so 文件(/lib文件夹)
2. ida 反编译 so 文件阅读Arm汇编or反汇编代码
3. 根据 java 层的代码来分析 so 代码。
4. 根据 so 代码的逻辑辅助整个程序的分析。

### 原生层静态分析例子

#### 2015-福建海峡两岸CTF-APK逆向,逆向试试吧

#### 反编译

利用jadx反编译apk，确定应用的主活动

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:app="http://schemas.android.com/apk/res-auto" android:versionCode="1" android:versionName="1.0" package="com.example.mobicrackndk">
    <uses-sdk android:minSdkVersion="8" android:targetSdkVersion="17" />
    <application android:theme="@style/AppTheme" android:label="@string/app_name" android:icon="@drawable/ic_launcher" android:allowBackup="true">
        <activity android:label="@string/app_name" android:name="com.example.mobicrackndk.CrackMe">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

程序的主活动为 com.example.mobicrackndk.CrackMe。

#### 分析主活动

程序的基本情况就是利用 native 函数 testFlag 判断用户传入的 pwdEditText 是否满足要求。

```java
public native boolean testFlag(String str);

static {
  System.loadLibrary("mobicrackNDK");
}

protected void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView((int) R.layout.activity_crack_me);
  this.inputButton = (Button) findViewById(R.id.input_button);
  this.pwdEditText = (EditText) findViewById(R.id.pwd);
  this.inputButton.setOnClickListener(new OnClickListener() {
    public void onClick(View v) {
      CrackMe.this.input = CrackMe.this.pwdEditText.getText().toString();
      if (CrackMe.this.input == null) {
        return;
      }
      if (CrackMe.this.testFlag(CrackMe.this.input)) {
        Toast.makeText(CrackMe.this, CrackMe.this.input, 1).show();
      } else {
        Toast.makeText(CrackMe.this, "Wrong flag", 1).show();
      }
    }
  });
}
```

#### 分析so文件

自然我们首先会去直接找 testFlag 函数，凡是并没有直接找到。我们只好首先分析 JNI_Onload 函数，如下

```c
signed int __fastcall JNI_OnLoad(JNIEnv *a1)
{
  JNIEnv *v1; // r4
  JNIEnv *env; // r5
  char *v3; // r7
  int class_; // r1
  const char *v5; // r1
  JNIEnv *v7; // [sp+Ch] [bp-1Ch]

  v1 = a1;
  v7 = 0;
  printf("JNI_OnLoad");
  if ( ((int (__fastcall *)(JNIEnv *, JNIEnv **, signed int))(*v1)->FindClass)(v1, &v7, 65540) )
    goto LABEL_7;
  env = v7;
  v3 = classPathName[0];
  fprintf((FILE *)((char *)&_sF + 168), "RegisterNatives start for '%s'", classPathName[0]);
  class_ = ((int (__fastcall *)(JNIEnv *, char *))(*env)->FindClass)(env, v3);
  if ( !class_ )
  {
    v5 = "Native registration unable to find class '%s'";
LABEL_6:
    fprintf((FILE *)((char *)&_sF + 168), v5, v3);
LABEL_7:
    fputs("GetEnv failed", (FILE *)((char *)&_sF + 168));
    return -1;
  }
  if ( ((int (__fastcall *)(JNIEnv *, int, char **, signed int))(*env)->RegisterNatives)(env, class_, off_400C, 2) < 0 )
  {
    v5 = "RegisterNatives failed for '%s'";
    goto LABEL_6;
  }
  return 65540;
}
```

可以发现，程序在这里动态注册了类和相应的函数 off_400C。仔细看一下该函数

```text
.data:0000400C off_400C        DCD aTestflag           ; DATA XREF: JNI_OnLoad+68↑o
.data:0000400C                                         ; .text:off_1258↑o
.data:0000400C                                         ; "testFlag"
.data:00004010                 DCD aLjavaLangStrin_0   ; "(Ljava/lang/String;)Z"
.data:00004014                 DCD abcdefghijklmn+1
.data:00004018                 DCD aHello              ; "hello"
.data:0000401C                 DCD aLjavaLangStrin_1   ; "()Ljava/lang/String;"
.data:00004020                 DCD native_hello+1
.data:00004020 ; .data         ends
```

可以发现，确实就是 testflag 函数，其对应的函数名为 abcdefghijklmn。

#### 分析abcdefghijklmn

可以发现，程序主要在三个部分对输入进行判断和计算

```c
bool __fastcall abcdefghijklmn(JNIEnv *a1, int a2, void *a3)
{
  void *input; // r6
  JNIEnv *env; // r7
  _BOOL4 rel; // r4
  size_t i; // r6
  const char *v7; // r2
  jmethodID clackeyID; // r2
  int keyID; // r4
  void *key_; // r0
  const char *key; // r5
  jclass class_calc; // [sp+4h] [bp-C4h]
  const char *password; // [sp+8h] [bp-C0h]
  char firstPart[8]; // [sp+14h] [bp-B4h]
  char v16; // [sp+1Ch] [bp-ACh]
  char secondPart[8]; // [sp+20h] [bp-A8h]
  char v18; // [sp+28h] [bp-A0h]
  char s; // [sp+2Ch] [bp-9Ch]

  input = a3;
  env = a1;
  if ( !jniEnv )
    jniEnv = a1;
  memset(&s, 0, 0x80u);
  password = (*jniEnv)->GetStringUTFChars(jniEnv, input, 0);
  rel = 0;
  if ( strlen(password) == 16 )
  {
    i = 0;
    do
    {
      firstPart[i] = password[i] - i;
      ++i;
    }
    while ( i != 8 );                           // i==8的时候退出
    rel = 0;
    v16 = 0;
    if ( !strcmp(seed[0], firstPart) )          // QflMn`fH
    {
      class_calc = (*jniEnv)->FindClass(jniEnv, "com/example/mobicrackndk/Calc");
      if ( !class_calc )
      {
        v7 = "class,failed";
LABEL_11:
        _android_log_print(4, "log", v7);
        exit(1);
      }
      clackeyID = (*jniEnv)->GetStaticMethodID(jniEnv, class_calc, "calcKey", "()V");
      if ( !clackeyID )
      {
        v7 = "method,failed";
        goto LABEL_11;
      }
      _JNIEnv::CallStaticVoidMethod(jniEnv, class_calc, clackeyID);
      keyID = ((int (__fastcall *)(JNIEnv *, jclass, const char *, const char *))(*env)->GetStaticFieldID)(
                env,
                class_calc,
                "key",
                "Ljava/lang/String;");
      if ( !keyID )
        _android_log_print(4, "log", "fid,failed");
      key_ = (void *)((int (__fastcall *)(JNIEnv *, jclass, int))(*env)->GetStaticObjectField)(env, class_calc, keyID);// forceCallType
      key = (*jniEnv)->GetStringUTFChars(jniEnv, key_, 0);// ,ZHVW^7c
      while ( i < strlen(key) + 8 )
      {
        secondPart[i - 8] = password[i] - i;
        ++i;
      }
      v18 = 0;
      rel = (unsigned int)strcmp(key, secondPart) <= 0;
    }
  }
  return rel;                                   
 }
```

并在之后获得了key的内容。

```Java
    public static String key;

    public static void calcKey() {
        key = new StringBuffer("c7^WVHZ,").reverse().toString();
    }
}
```

#### 获取flag

根据这三个判断，我们可以得到输入的字符串内容

```python
s = "QflMn`fH,ZHVW^7c"
flag = ""
for idx,c in enumerate(s):
    flag +=chr(ord(c)+idx)
print flag
```

结果如下

```shell
QgnPrelO4cRackEr
```

输入之后并不对。

#### 再次分析

想到这里就要考虑下，程序是不是在哪里修改了对应的字符串。这里首先看一下seed。按 x 进行交叉引用，发现其在 _init_my 中使用了，如下

```c
size_t _init_my()
{
  size_t i; // r7
  char *v1; // r4
  size_t result; // r0

  for ( i = 0; ; ++i )
  {
    v1 = seed[0];
    result = strlen(seed[0]);
    if ( i >= result )
      break;
    t[i] = v1[i] - 3;
  }
  seed[0] = t;
  byte_4038 = 0;
  return result;
}
```

所以最初程序对 seed 进行了修改。

#### 再次获取flag

修改脚本如下

```python
s = "QflMn`fH,ZHVW^7c"
 
flag=""
for i in xrange(0,8):
	flag = flag + chr(ord(s[i]) - 3 + i)
for i in xrange(8,16):
	flag = flag + chr(ord(s[i])  + i)

print "flag: " + flag
```

flag 如下

```
➜  2015-海峡两岸一个APK，逆向试试吧 python exp.py
NdkMobiL4cRackEr
```
### 参考
《IDA Pro权威指南》