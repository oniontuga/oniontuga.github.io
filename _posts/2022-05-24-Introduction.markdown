
---
layout: post
title: Linux - Introduction
date: 2020-03-16 22:11:22 +0100
description: Lame is a beginner level machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.

fig-caption: Lame
categories: Linux
tags: [Easy, Linux, Retired, CVE]
---

# Introduction
Linux is the kernel of one of the most popular operating system. Its development was started in 1991 by Linus Torvalds. The operating system was inspired by Unix, another operating system developed in the 1970s by AT&T Laboratories. Unix was geared towards small computers. At the time, “small” computers were considered machines that don’t need an entire hall with air conditioning and cost
less than one million dollars. Later, they were considered as the machines that can be lifted by two people. By that time, Unix was not available on small computers like office computers based on the x86 platform. Therefore Linus, who was a student by that time, started to implement a Unix-like operating system which was supposed to run on this platform.

## Distribution
A Linux distribution is a bundle that consists of a Linux kernel and a selection of applications that are maintained by a company or user community.

Most know distros:
*  Debian - is the biggest distribution of the Debian distribution family;
* Ubuntu -  was created by Mark Shuttleworth and his team in 2004, with the mission to bring an easy to use Linux desktop environment. 
* Arch Linux - A simple, lightweight distribution.
* Red Hat - It is provided to companies as a reliable enterprise solution that is supported by Red Hat and comes with software that aims to ease the use of Linux in professional server environments. Some of its components
require fee-based subscriptions or licenses. The CentOS project uses the freely available source code of Red Hat Enterprise Linux and compiles it to a distribution which is available completely free of charge, but in return does not come with commercial support. Both RHEL and CentOS are optimized for use in server environments. 
* Android - mainly a mobile operating system developed by Google. 
* Raspbian and the Raspberry Pi - Raspberry Pi is a low cost, credit-card sized computer that can function as a full-functionality desktop computer, but it can be used within an embedded Linux system.
* Linux and the Cloud - Linux runs 90% of the public cloud workload. Every cloud provider, from Amazon Web Services (AWS) to Google Cloud Platform (GCP), offers different forms of Linux. Even Microsoft, a company whose former CEO compared Linux to cancer, offers Linux-based virtual machines in their Azure cloud today.
***

## Major Open Source Applications
### Package Installation

**Debian Based Distros**
- apt + function + package. Ex: apt install vim; apt search vim; apt remove vim.
**RPM Based Distros (Centoos)
- yum + function + package. Ex: yum install vim, yum remove vim; yum search vim.
**Arch Based Distros
- pacman + function + package. Ex: pacman -S vim; pacman -R vim.

### Applications 
* Text Editor - Vim
* Office - Libreoffice
* Web browsers - Firefox
* Multimedia - Gimp
* Data sharing - NFS 
* Network Administration - DHCP; DNS


### Open Source Software and Licensing

#### Definition of Free Software and Open Source Software
First of all, “free” in the context of free software has nothing to do with “free of charge”, or as the founder of the Free Software Foundation (FSF), Richard Stallman, succinctly puts it:
- "To understand the concept, you should think of “free” as in “free speech,” not as in “free beer”.

#### Licenses 
The already mentioned Free Software Foundation (FSF) has formulated the GNU General Public License (GPL) as one of the most important licenses for free software, which is used by many projects, e.g. the Linux kernel. In addition, it has released licenses with case-specific customizations, such as the GNU Lesser General Public License (LGPL), which governs the combination of free software with modifications made to code where the source code for the modifications do not have to be released to the public, the GNU Affero General Public License (AGPL), which covers selling
access to hosted software, or the GNU Free Documentation License (FDL), which extends freedom principles to software documentation. In addition, the FSF makes recommendations for or against third-party licenses, and affiliated projects such as GPL-Violations.org investigate suspected
violations of free licenses.

