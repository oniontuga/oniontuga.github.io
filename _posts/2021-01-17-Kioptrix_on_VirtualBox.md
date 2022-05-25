---
title: "How-To: Run Kioptrix On VirtualBox"
categories: [Tutorials]     # Up to two elements only
tags: [tutorial, how-to, kioptrix]     # TAG names should always be lowercase, infinite number of elements
image: /assets/img/posts/How_to_kioptrix_on_virtualbox/HowTo-Kioptrix_on_VBox.webp    # If you want to add an image to the top of the post contents
# toc: false    # table of content - overwrite global configuration from _config.yml
# comments: false       # overwrite global configuration from _config.yml
# pin: true     # pin one or more posts to the top of the home page
excerpt_separator: <!--exc-->
permalink: /:categories/:year/:month/:day/:title:output_ext
published: true
---

Kioptrix virtual machine (by Vulnhub) was designed to run using VMware. In this How-To we'll learn how it can be run on VirtualBox instead.
<!--exc-->

## Video
If you prefer to follow a video instead, please see my [video tutorial](https://youtu.be/-3GeOXwfSyU). 

## Download
Download the[virtual machine](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/) (VM) from [Vulnhub](https://www.vulnhub.com/).
![How to kioptrix on virtualbox Vulnhub Download page](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-download-page.webp) _Vulnhub Download page_


## Extract
The downloaded `.rar` file is an archive containing multiple files which we need to extract. Depending on your Operating System and installed applications, extract the files into a folder and remember it's path.
* [Extract on Windows](https://support.microsoft.com/en-us/windows/zip-and-unzip-files-8d28fa72-f2f9-712f-67df-f80cf89fd4e5)
* [Extract on Linux OS](https://www.ezyzip.com/how-to-unzip-files-linux.html)
* [Extract Using WinRAR](https://www.win-rar.com/open-zip-file.html?&L=0)

Here are the files after extraction:
![How to kioptrix on virtualbox extract files](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-extracted-files.webp) _Extracted files in folder_


## VirtualBox Configuration
* Open VirtualBox
![How to kioptrix on virtualbox main screen](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-open-virtualbox.webp) _VirtualBox main screen_

* On the top menu select **Machine** -> **New**
* Put in a name, choose path the machine files to be stored in (or leave unchanged), select **Type**: **Linux** and **Version**: **Other Linux 32-bit**.
![How to kioptrix on virtualbox new machine](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-new-machine.webp) _VirtualBox new machine screen_

* Click **Next**
* Select the appropriate memory size for the machine (anything above 512M is sufficient)
![How to kioptrix on virtualbox memory capacity](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-choose-memory.webp) _VirtualBox select memory capacity_

* Click **Next**
* Choose **Use an existing virtual hard disk file** and click the folder icon to choose the path
![How to kioptrix on virtualbox use existing](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-use-existing.webp) _VirtualBox select memory capacity_

* Click **Add** on the top menu, choose the path to the directory where the extracted files are and select the `.vmdk` file
![How to kioptrix on virtualbox select hard disk](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-choose-hardisk.webp) _VirtualBox select hard disk_

* Click **Create** to finish the process.
* Configure the correct **Network Settings** according to your needs (Out of this tutorial scope as it is a topic by itself)


## Run
* Start the machine
* You'll see a blue screen from Kudzu. Don't press any key and wait for time run out
![How to kioptrix on virtualbox select hard disk](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-wait-for-screen.webp) _VirtualBox blue screen_


* Once you see the **Kioptrix login:** text, the machine is running

![How to kioptrix on virtualbox kioptrix machine runnung](/assets/img/posts/How_to_kioptrix_on_virtualbox/Kioptrix-on-virtualbox-machine-is-running.webp) _Kioptrix machine running_

