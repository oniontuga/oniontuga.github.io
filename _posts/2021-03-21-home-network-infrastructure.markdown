---
layout: post
title: Home Network - Infrastructure
date: 2021-03-21 16:08:22 +0100
description: This series of articles will take you through the process of design through to implementation of a Raspberry Pi private cloud home network setup. This article will focus on the infrastructure setup, before later moving on to the applications that will be deployed.
img: home-network-infra-background.jpg
fig-caption: Pi Infra
categories: HomeNetwork
tags: [Infrastructure, Pi]
---
## Overview
This series of articles will take you through the process of design through to implementation of a Raspberry Pi private cloud home network setup. This first article will focus on the infrastructure side, before later moving on to the applications that will be deployed.

The trigger for embarking on this project, was due to frequently racking up large bills through cloud providers, when wanting to either play with or deploy even the most simple of applications. There are obviously ways to reduce costs in the cloud but even then, none of them are quite as simple as flicking a power switch, at least not without the loss of data. There is also something satisfying about being able to see the fruits of your labour in the physical form and design your private cloud from the ground up.

## Design
To start with some of the requirements I had for this setup, or with regards to noise my partner had, are that it is:
* Easily extensible
* Low cost
* Fault tolerant
* Secure
* Discreet and quiet

The network topology would be simple enough with each of the servers going through the switch in order to network together and reach the outside internet. 

![image](/assets/img/home-network-infra.png){: width="75%" }

In order to keep costs low and ensure the setup is discreet and quiet, raspberry pi's would seem like a good candidate. If I ever wanted to extend it in the future as well it would be simple enough just to purchase another one and plug it into the network.

With that decided we now need to purchase the parts, I went for the following:
* [Raspberry Pi 4 Model B 8GB](https://thepihut.com/collections/raspberry-pi/products/raspberry-pi-4-model-b?variant=31994565689406) x 4
* [8-Slot Cloudlet Cluster Case - Clear](https://thepihut.com/products/8-slot-cloudlet-cluster-case?variant=37531942355139) x 1
* [Micro SD Card 32GB](https://thepihut.com/products/noobs-preinstalled-sd-card?variant=20649315598398) x 4
* [Raspberry Pi 4 Power Supply - White](https://thepihut.com/products/raspberry-pi-psu-uk?variant=20064004505662) x 4
* [RJ45 Ethernet Cable 2m](https://thepihut.com/products/rj45-cat5e-ethernet-lan-cable-2m-red) x 5
* [TP-Link 5-Port Gigabit Network Switch](https://thepihut.com/products/tp-link-5-port-gigabit-network-switch) x 1
* [Integral Micro SD Card Reader](https://thepihut.com/products/integral-micro-sd-card-reader) x 1

Unpacking and assembling was a little fiddly with the small parts though simple enough. If I had to do this again I may have gone for flat cables for the ethernet cables but it could be organised to be tidy nonetheless.

![image](/assets/img/home-network-rack.jpeg){: width="50%" }

To allow for easy extensibility and fault tolerance setting up a kubernetes cluster on the raspberry pi's seems like a good idea. Allowing us not to have to worry about on which server services are deployed onto. The application stack for a kubernetes cluster is outlined below.

![image](/assets/img/kubernetes-application-stack.png){: width="75%" }

To set up the OS image on the SD card I used [rpi-imager](https://www.raspberrypi.org/software/) and burned Raspbian OS Lite onto the card. Then the following changed need to be made:
* Create empty file named `ssh` in boot partition
* Set custom hostname in `/etc/hostname` in the rootfs partition
* Append `cgroup_enable=cpuset cgroup_memory=1 cgroup_enable=memory` to `cmdline.txt` in the boot partition
* Prepend `gpu_mem=16` to the start of `config.txt` in the boot partition

In order to speed this process up I created a script that can be found [here](https://gist.github.com/calxus/699a8e55616403590ad4c052f6f8d041)

Once this is done the kubernetes cluster can be deployed. To carry this out I used ansible playbooks that can be found [here](https://github.com/calxus/ansible-home-network). They need to be executed in the following order and manner replacing the user_name for whatever you want the user to be called:
* `sudo ansible-playbook playbooks/0_base.yaml --extra-vars "user_name=calxus"`
* `sudo ansible-playbook playbooks/1_master.yaml --extra-vars "user_name=calxus"`
* `sudo ansible-playbook playbooks/2_node.yaml --extra-vars "user_name=calxus"`