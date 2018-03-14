
# Snipher: A dead simple packet sniffer
## Synopsis
```
$> java -cp /path/to/jnetpcap.jar Snipher [-A] [-d] [-h] [-pr] [-h] [-v] [-M]
[-B=buffer_size] [-c=count] [-l=file_size] [-R=rotation_seconds] [-i=interface]
[-m=mode] [-D=direction] [-in=in_file] [-out=out_file] [-p=port] [-P=protocol]
[-src=source] [-dst=destination] [-U] [-pat=pattern] 
```
Or if you're using the precompiled JAR executable
```
$> java -jar Snipher.jar [-A] [-d] [-h] [-pr] [-h] [-v] [-M]
[-B=buffer_size] [-c=count] [-l=file_size] [-R=rotation_seconds] [-i=interface]
[-m=mode] [-D=direction] [-in=in_file] [-out=out_file] [-p=port] [-P=protocol]
[-src=source] [-dst=destination] [-U] [-pat=pattern] 
```
## Description
Snipher is an easy to use packet sniffer written in Java. Snipher prints out a description of the contents of a packet on a network interface that match the given criteria. This description is preceeded by a human readable time stamp printed as ``` weekday month day hours:minutes:seconds timezone year```. When run with the **-out=*out_file*** flag it also will save the packet contents to the file *out_file*. It can also be run with the **-in=*in_file*** flag to read in packets from a previous capture called *in_file*. In all cases, only packets matching the given criteria are processed by Snipher.

When run with the **-c=*count*** flag Snipher will only capture and process *count* number of packets (or until interrupted by a SIGINT or SIGTERM signal). When run without the **-c** flag Snipher will capture packets indefinitely until interrupted by a SIGINT or SIGTERM signal.
## Options
- **-A / --ASCII**: Print each packet in ASCII.
- **-d / --devices**: Print out a list of network devices connected to this host.
- **-h / --help**: Print the text version of this README and exit.
- **-pr / --print**: Toggle packet printing. By default this setting is set to FALSE.
- **-v / --version**: Print out the version number for Snipher and libpcap/WinPcap
- **-M / --monitor_mode**: Capture in 'monitor mode.' **Not currently supported.**
- **-B=buffer_size / --buffer_size=buffer_size**: Set the size of the output buffer. **Not currently supported.**
- **-c=count / --count=count**: Only capture *count* packets and exit.
- **-l=file_size / --limit=file_size**: Before writing a packet to the save file, check whether the file is larger than *file_size*. If so, close the current save file and open a new one.
- **-R=rotation_seconds / --rotation=rotation_seconds**: Rotate the save file after *rotation_seconds* seconds have passed. **Not currently supported.**
- **-i=interface / --interface=interface**: Set the capturing interface to *interface*. This may be either a device index (starting from 0) or the name of the device you wish to capture from.
- **-m=mode / --mode=mode**: Set the capturing mode to *mode* where *mode* may be either *PROMISCUOUS* or *PASSIVE*.
- **-D=direction / --direction=direction**: Filter based on traffic direction where *direction* may be either *inbound* or *outbound*.
- **-in=in_file / --input=in_file**: Instead of capturing packets from a network device, read packets from the file *in_file*.
- **-out=out_file / --output=out_file**: Write the contents of each captured/processed packet to the file *out_file*.
- **-p=port / --port=port**: Only capture and process packets that match the given port(s). Mutliple ports may be specified as a comma separated list.
- **-P=protocol / --protocol=protocol**: Only capture and process packets that match the given *protocol*. Mutliple protocols may be specified as a comma separated list. The currently supported protocols are **ether, fddi, tr, ip, ip6, arp, rarp, decnet, tcp,** and **udp**.
- **-src=source / --source=source**: Filter packets based on their *source* where *source* may be any valid IPv4 address.
- **-dst=destination / --destination=destionation**: Filter packets based on their *destination* where *destination* may be any valid IPv4 address.
- **-U / --unbuffered**: Do not buffer the output and instead immediately print or write the packet to a save file. **Not currently supported**.
- **-pat=pattern / --pattern=pattern**: Specify a regular expression *pattern* to match/filter packets based on their content.
## Installation instructions
### Prerequisites
Snipher is built using the [jNetPcap](http://jnetpcap.com/) packet capturing library/API. jNetPcap acts as wrapper for the libpcap library so to begin you will first need to install libpcap. On Ubuntu this can be done in the following fashion:
```
$> sudo apt-get install libpcap-dev -y
```
For other Linux distributions you will need to use your appropriate package manager (yum, pacman, etc). For Windows-based operating systems the libpcap library is not available, however ther are suitable alternatives such as [WinPcap](https://www.winpcap.org/install/default.htm) and [Npcap](https://nmap.org/npcap/). Either of the two libraries should work, though Snipher has only been tested with WinPcap.

Second, if you plan on compiling Snipher from source you will need the jNetPcap library which can be found [here](http://jnetpcap.com/download). To use the library you will need to include the downloaded  JAR file into your IDE project (assuming you're using an IDE to compile Snipher). If you are instead compiling from a CLI you can do the following to compile Snipher (assuming you are on a Linux distro):
```
$> javac -g -cp /path/to/jnetpcap.jar /path/to/Snipher.java
```
Or if you're on a Windows variant:
```
C:\Users\your_name> javac -g -cp C:\path\to\jnetpcap.jar C:\path\to\Snipher.java
```
Additionally, if you are on a Windows operating system you will need to place the included .dll library (jnetpcap.dll) into somewhere in your Java path (java.library.path), system path (given by %PATH%), or in the directory where Snipher.java is located. For the sake of simplicity it is best to place the .dll into the System32 folder, i.e. C:\Windows\System32.
### Installation
Thankfully, I've designed Snipher so that no complex installation is required. You can either compile and run from source or you can download the precompiled binary found [here](https://github.com/turnerlehm/Snipher/blob/master/out/artifacts/Snipher_jar/Snipher.jar).

To download and run from source, first clone this repository by doing the following:
```
$> git clone https://github.com/turnerlehm/Snipher.git /path/to/Snipher
```
Then to compile, do the following:
```
$> cd /path/to/Snipher
$> javac -g -cp /path/to/jnetpcap.jar Snipher.java
```
And finally to run:
```
$> java -cp /path/to/jnetpcap.jar Snipher [args]
```
The precompiled binary makes things a little bit easier by effectively cutting out the compilation and jNetPcap linking steps. Effectively, once the precompiled binary has been downloaded one only needs to do the following to run Snipher:
```
$> java -jar Snipher.jar [args]
```
Additionally, Snipher was built using the IntelliJ IDE so if you're also running IntelliJ you can simply import the project into IntelliJ. Once imported all one has to do is link the JNetPcap library as a dependency, and if on Windows ensure that the jnetpcap.dll library is in System32 (or another directory listed in your PATH encironment variable).
## Usage
Using Snipher is pretty simple. After compiling from source all that one needs to do is the following to run a basic capture;
```
$> java -cp /path/to/jnetpcap.jar Snipher
```
Alternatively, if you're using the precompiled binary (I really recommend you use the precompiled binary):
```
$> java -jar Snipher.jar
```
Both of the above will launch a default packet capture. In the default packet capture the capturing interface is set to interface #0, whatever that interface may be. Additionally, no filtering or processing is performed on the packets passing through the network interface so all packets passing through the interface are captured. Furthermore, the contents of each packet are printed to STDOUT in raw hex format preceeded by a human readable timestamp.

To make a packet capture more granular, one or more options may be specified to filter packets based on certain criteria such as source/destination port number, protocol, and source/destination address. The currently supported options are specified above. The order in which options are passed to Snipher does not matter. The basic syntax for options is as follows:
```
$> java -jar Snipher.jar -option=option_param
```
In some instances an option may support multiple parameters. In this case each parameter must be separated by a comma. This would look something like the following:
```
$> java -jar Snipher.jar -option=param1,param2,param3,...,paramN
```
## Built With
- [jNetPcap](http://jnetpcap.com/) - handles raw packet capturing and packet processing
- [Git](https://git-scm.com/) - version control
- [IntelliJ](https://www.jetbrains.com/idea/) - main IDE used by the author
## Authors
- Turner Lehmbecker - *initial work* - [@mr_frosbyt](https://twitter.com/mr_frostbyt)
## License
This project is licensed under the MIT license.
> Written with [StackEdit](https://stackedit.io/).
