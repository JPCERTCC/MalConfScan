<div align="center"><img src="images/title.svg" width="800"></div>

  [![Arsenal](https://rawgit.com/toolswatch/badges/master/arsenal/usa/2019.svg)](http://www.toolswatch.org/2019/05/amazing-black-hat-arsenal-usa-2019-lineup-announced/)  

## Concept

**MalConfScan** is a [Volatility3](https://github.com/volatilityfoundation/volatility3) plugin extracts configuration data of known malware. Volatility is an open-source memory forensics framework for incident response and malware analysis. This tool searches for malware in memory images and dumps configuration data. In addition, this tool has a function to list strings to which malicious code refers.  

![MalConfScan sample](images/sample1.png)  

## Supported Malware Families

  MalConfScan can dump the following malware configuration data, decoded strings or DGA domains:

- [ ] Ursnif
- [ ] Emotet
- [ ] Smoke Loader
- [ ] PoisonIvy
- [ ] CobaltStrike
- [ ] NetWire
- [ ] PlugX
- [x] RedLeaves / Himawari / Lavender / Armadill / zark20rk
- [x] TSCookie
- [x] TSC_Loader
- [ ] xxmm
- [ ] Datper
- [ ] Ramnit
- [x] HawkEye
- [x] Lokibot
- [ ] Bebloh (Shiotob/URLZone)
- [ ] AZORult
- [x] NanoCore RAT
- [ ] AgentTesla
- [ ] FormBook
- [ ] NodeRAT (https://blogs.jpcert.or.jp/ja/2019/02/tick-activity.html)
- [ ] njRAT
- [ ] TrickBot
- [ ] Remcos
- [x] QuasarRAT
- [x] AsyncRAT
- [ ] WellMess (Windows/Linux)
- [ ] ELF_PLEAD
- [ ] Pony

## Additional Analysis

MalConfScan has a function to list strings to which malicious code refers. Configuration data is usually encoded by malware. Malware writes decoded configuration data to memory, it may be in memory. This feature may list decoded configuration data.  

## How to Install

If you want to know more details, please check [the MalConfScan wiki](https://github.com/JPCERTCC/MalConfScan/wiki).

## How to Use

MalConfScan has two functions **malconfscan**, **linux_malconfscan** and **malstrscan**.

### Export known malware configuration

```
$ python vol.py -p [plugin_directory] malconfscan -f images.mem
```

### Export known malware configuration for Linux

[TBU]

### List the referenced strings

[TBU]

## Overview & Demonstration

  Following [YouTube video](https://youtu.be/n36WAzgHldY) shows the overview of MalConfScan.

  [![MalConfScan_Overview](https://img.youtube.com/vi/n36WAzgHldY/sddefault.jpg)](https://youtu.be/n36WAzgHldY)

  And, following  [YouTube video](https://youtu.be/kPsOvoRHK3k) is the demonstration of MalConfScan.

  [![MalConfScan_Demonstration](https://img.youtube.com/vi/kPsOvoRHK3k/sddefault.jpg)](https://youtu.be/kPsOvoRHK3k)

## MalConfScan with Cuckoo
  
  ~~Malware configuration data can be dumped automatically by adding MalConfScan to Cuckoo Sandbox. If you need more details on Cuckoo and MalConfScan integration, please check [MalConfScan with Cuckoo](https://github.com/JPCERTCC/MalConfScan-with-Cuckoo).~~

  Cuckoo Sandbox does not support Python3 yet. Please use Python2 version of MalConfScan to integrate with Cuckoo Sandbox.
