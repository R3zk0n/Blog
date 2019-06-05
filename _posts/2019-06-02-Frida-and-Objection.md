---
layout: post
title:  "Frida and Objection"
date:   2019-06-01 07:10:14 +0000
categories: Mobile Security
tags:
    - mobile
    - hacking
    - penetration testing
thumbnail: mobile
---

# Frida
Frida is a Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.

The Frida framework allows dynamic introspection of running applications and resources. It also has the ability to inject JavaScript in to a black box process, allowing you to hook functions, apis and trace sensitive functions such as cryptographic API’s.

Frida uses ```Gadget``` to hook to the required processes. This is in either the form of a ```.so``` file or a ```.dylib``` file, for mobile devices.


## Using Frida.
To use Frida, the device that is being targeted must either have the frida-server installed on the device to allow communication to the device or a “Gadget” embedded in the application. There is two different methods for this.

### Jailbroken Device - (iOS)

### Non Jailbroken Device - (iOS)

### Android Emulator/Rooted Device - (Android)
I typically for most testing purposes use a [Genymotion](https://www.genymotion.com/) emulator. These run on a x86 architecture so uploading the arm version WILL NOT work. Instead there is a quiet simple process. The script provided below will push a Frida server which will act a “Gadget” to a rooted android device.

There is a slight mod to the script which allows it to upload and detect the architecture that the emulator is running and upload the file directory to the device using ```android debug bridge``` or ```adb``` for short.

{% highlight python %}
#!/usr/bin/env python3

""" This script aims to automate the process of starting frida-server
on an Android device (for now). The script is a part of AndroidTamer
project and is based on this issue:
https://github.com/AndroidTamer/Tools_Repository/issues/234.

This script performs following things:
1. Try to determine the device architecture
2. Download the frida-server and extract it
3. Push it to the device and execute it
4. Save the PID of the process and write it to 'frida.pid' file.

#Todo:
* Better exception handling.
* Implement better/robust architecture detection code
* Implement for more devices
* Implement the feature to kill frida-server afterwards
"""

import sys
import subprocess
import os
from backports import lzma
import requests

try:
    from frida import __version__ as FRIDA_VERSION
except ImportError:
    print("[-] Frida not found. Please run `pip install frida` to proceed.")
    sys.exit(1)

__version__ = 0.1
__author__ = "c0dist@Garage4Hackers"

# Just put "adb" below, if adb exists in your system path.
adb_path = "adb"

def device_exists():
    """ This functions checks if any device is connected or not.
    """
    cmd = '{} devices -l | grep -v "List of devices attached"'.format(adb_path)
    # We know shell=True is bad, but should be fine here.
    output = subprocess.check_output(cmd, shell=True).strip().decode("utf-8")
    if output:
        print("\t[+] Found following device:")
        print("\t{}".format(output))
        return True
    return False


def get_device_arch():
    """ This function tries to determine the architecture of the device, so that
    the correct version of Frida-server can be downloaded. The function, first,
    tries to get the output of `uname -m` and then it tries to matches it against
    some known values. If not, then it tries `getprop ro.product.cpu.abi`.

    This function is probably the weakest part of the code. If you know of more
    Arch names from uname output, please contribute.

    :returns either "arch" that Frida release page understands or None.
    """
    arch = None

    uname_cmd = "{} shell uname -m".format(adb_path)
    uname_archs = ["i386", "i686", "arm64", "arm", "x86_64"]
    # We know shell=True is bad, but should be fine here.
    output = subprocess.check_output(uname_cmd, shell=True).lower().strip().decode("utf-8")

    if output in uname_archs:
        if output in ["i386", "i686"]:
            arch = "x86"
        else:
            arch = output
    else:
        getprop_cmd = "{} shell getprop ro.product.cpu.abi".format(adb_path)
        getprop_archs = ["armeabi", "armeabi-v7a", "arm64-v8a", "x86", "x86_64"]
        # We know shell=True is bad, but should be fine here.
        output = subprocess.check_output(getprop_cmd, shell=True).lower().strip().decode("utf-8")

        if output in getprop_archs:
            if output in ["armeabi", "armeabi-v7a"]:
                arch = "x86"
            elif output == "arm64-v8a":
                arch = "x86"
            elif output == "x86":
                arch = "x86"
            else:
                arch = output
    return arch

def prepare_download_url(arch):
    """ Depending upon the arch provided, the function returns the download URL.
    """
    base_url = "https://github.com/frida/frida/releases/download/{}/frida-server-{}-android-{}.xz"
    return base_url.format(FRIDA_VERSION, FRIDA_VERSION, arch)

def download_and_extract(url, fname):
    """ This function downloads the given URL, extracts .xz archive
    as given file name.

    :returns True if successful, else False.
    """
    data = None

    print("\t[+] Downloading: {}".format(url))
    req = requests.get(url, stream=True)
    if req.status_code == 200:
        # Downloading and writing the archive.
        archive_name = fname + ".xz"

        req.raw.decode_content = True
        with open(archive_name, "wb") as fh:
            for chunk in req.iter_content(1024):
                fh.write(chunk)

        with lzma.open(archive_name ) as fh:
            data = fh.read()
    else:
        print("\t[-] Error downloading frida-server.")
        print("\t[-] Got HTTP status code {} from server.".format(req.status_code))

    if data:
        print("\t[+] Writing file as: {}.".format(fname))
        with open(fname, "wb") as frida_server:
            frida_server.write(data)
        return True
    return False

def push_and_execute(fname):
    """This function pushes the file to device, makes it executable,
    and then finally runs the binary. The function also saves the PID
    of process in 'frida.pid' file.
    """
    push_cmd = "{} push {} /data/local/tmp/frida-server".format(adb_path, fname)
    chmod_cmd = "{} shell chmod 0755 /data/local/tmp/frida-server".format(adb_path)
    kill_cmd = "{} shell su 0 'killall frida-server'".format(adb_path)
    execute_cmd = "{} shell su 0 '/data/local/tmp/frida-server' &".format(adb_path)
    ps_cmd = "%s shell 'su 0 ps' | grep frida-server | awk '{print $2}' > frida.pid" % (adb_path)

    status_code = os.system(push_cmd)
    if status_code == 0:
        print("\t[+] File pushed to device successfully.")
        os.system(chmod_cmd)
        if os.path.exists('frida.pid'):
            print("\t[+] Killing all frida-server on device.")
            os.system(kill_cmd)
        print("\t[+] Executing frida-server on device.")
        os.system(execute_cmd)
        print("\t[+] Fetching the PID of frida-server and saving it to file.")
        os.system(ps_cmd)

    else:
        print("[-] Could not push the binary to device.")

def main():
    """ This function is where the magic happens.
    """
    if not device_exists():
        print("[-] No device found. Exiting.")
        sys.exit(1)

    print("[*] Current installed Frida version: {}".format(FRIDA_VERSION))
    print("[*] Trying to determine device's arch.")
    arch = get_device_arch()
    if arch:
        print("\t[+] Found arch: {}".format(arch))
        url = prepare_download_url(arch)
        fname = "frida-server-{}-android-{}".format(FRIDA_VERSION, arch)
        if download_and_extract(url, fname):
            push_and_execute(fname)
    else:
        print("\t[-] Could not determine device's arch. Exiting.")

if __name__ == "__main__":
    main()

{% endhighlight %}

There is a slight mod to the script which allows it to upload and detect the architecture that the emulator is running and upload the file directory to the device using android debug bridge or ```adb``` for short.


##Non Rooted - (Android)

### Tips:
Set alias to route
{% highlight bash %} alias frida_open=frida-trace -U -p [PID] "Open*"{% endhighlight %} This alias will trace the open calls that frida uses.

{% highlight bash %}alias frida_recv=frida-trace -U -p [PID] "*recv"{% endhighlight %} This will track the recv function calls

###Tip:
```using wifi adb and adb connect <deviceIP>:5555 ``` makes some debugging processes less of a hassle.

# Objection

Objection is a dynamic instrumentation framework which heavily uses the Frida framework.
Developed and maintained by [leonza](www.github.com/leonza/sensepost)

Can be downloaded here [objection](github.com/sensepost/objection)

## Installing Objection
Installing objection is extremely simple as ```pip3 install objection```. This will install objection and Frida.




## Method Hooking Objection.

There are a number of functions and features objection has one such is the way Objection is able to dynamically hook methods and back trace allowing in runtime. This can allow a researcher to bypass jailbreak and root protections, as well as a many of functions
```ios hooking class list``` will list all the available classes with the assoicated application.

![Classes](https://i.imgur.com/aTCL6gL.png)
Using the identified classes we can look at the class methods and use objection to hook those and tamper with them

Locating the Jailbroken class by saving output and using grep to find the JailbrokenVC 
![JailBroken](https://imgur.com/K13gdG7.png)


```ios hooking class_method <class>``` this command will then list the class methods associated to the previously identified classes.
![Class Method](https://i.imgur.com/8ujBmg1.png)

Now we have the knowledge the class method to use for hooking purposes would end up being 
```+[JailBreakDetection isJailBroken]```. This is made up of the + being assoicated with the class method and the class is called first followed by the method.

Now we can use this too hook the class to watch and modify its value using the command
```ios hooking watch method "+[JailBreakDetection isJailBroken]" --dump-args --dump-return --dump-backtrace```
![Watch class](https://i.imgur.com/rHddZtJ.png)

Now we can see the return value being set to ```0x1``` which is causes the application to display the device is "Jailbroken" however, we can set the value to ```0x0```. This will change the return value to the application, causing it to bypass the jailbroken detection and display "This is not jailbroken"
![Bypass](https://i.imgur.com/X3sjtAp.png)







# Plugin Code
Writing plugin code for objection is extremely simple the code below, will enumerate the files listed in the directories and download them to the local environment.
{% highlight python %}
import os
import glob
import click
from objection.utils.plugin import Plugin
from objection.commands.ios.hooking import show_ios_classes, show_ios_class_methods
from objection.commands.filemanager import _ls_ios, _get_short_ios_listing
from objection.commands.device import _get_android_environment, _get_ios_environment
from objection.state.connection import state_connection
import json
import glob

import paramiko
localpwd = ''
host = 'HOST'

class FileList(Plugin):
    """ Loads directoy's and files  """

    def __init__(self, ns):
        """
            Creates a new instance of the plugin
            :param ns:
        """

        # self.script_path = os.path.join(os.path.dirname(__file__), "script.js")

        implementation = {
            'meta': 'Work with Frida file information',
            'commands': {
                'info': {
                    'meta': 'Get the current file path',
                    'exec': Pentest_Suite(self)
                }
            }
        }

        super().__init__(__file__, ns, implementation)

        self.inject()


def Pentest_Suite(self):
    f = open("Classes_dump.txt", "w+")
    agent = state_connection.get_api()
    env_path = state_connection.get_api().env_ios_paths()
    iOS_files = agent.env_ios_paths()
    api = state_connection.get_api()
   # for class_name in sorted(classes):
    paths = []
    for key, val in iOS_files.items():
        print(key+val)
        list_files = _ls_ios(val)
        directories = val
        paths.append(directories)
        print("Path: ", directories)
        try:
            print(list_files)
        except TypeError as e:
            print("Not Mutable")
    for i in paths:
        glob_files(i)

def glob_files(directories):
    # IT seems likes anything we gotta do on the file system that isnt supported by frida uses Paramikko?.. fuck
    plist = []
    paths = directories
    print("File Paths: ", paths)
    client = paramiko.SSHClient()
    host_keys = client.load_system_host_keys()
    # Connect to our client; you will need
    client.connect(host, username='USERNAME', password='PASSWORD')
    stdin, stdout, stderr = client.exec_command('ls '+paths)
    for line in stdout:
        print(line)





def file_path(self):
    agent = state_connection.get_api()
    dir_files = agent.env_android_paths()
    download = _download_android('', localpwd+'frida991356068dat')
    for key, val in dir_files.items():
        try:
            print(key+":"+val)
        except TypeError as e:
            print("Not Iternationable item")


namespace = 'Pentest_Suite'
plugin = Pentest_Suite

{% endhighlight %}




 {% highlight javascript %}
# Frida Version of bruteforce

use strict;
    interceptor.attach(){
        onMatch: function(instance)
    }
{% endhighlight %}


# Frida Objectivce C Classes.
{% highlight javascript %}
use strict;
if (Objective.C exists)
{
    Interceptor.attach(){
        onMatch: function(instance)
        console.log('Matched: ')
        else:

    }
}
```
{% endhighlight %}

