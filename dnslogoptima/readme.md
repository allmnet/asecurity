#dnslogoptima
1. dnslogoptima can record all dns query. All activity log send syslog server, which you may analyze at any time.
2. reliable program that can log and analyze by malware site visit on dns server.
3. collect-ip during 10 min visit to seam site

The software can monitor your dns all query the who were visit, in an syslog.
You can easily install service or run console mode.


##Option
-server:    define Syslog server ip.
-time:  setting to delete DNS log timerDNS. if input the ‘0’ or not define  -time option, never delete DNS log.
*It’s recommand, we recommand to delete the log.
-path: define DNS log path.
-log: enable/disable send syslog server an DNS log. when use this option, disable -small option.
-block:  enable/disable block the malware URL by set DNS loopback(127.0.0.1).
-install:  Install by services type process. it’s help to process start automatically.
-uninstall: Uninstall by services type process.
-vip: Share malware site and white site information.
-live: Only read occur log at last one minite. default option is read to all log of file.
-sl: collect-ip during 10 min visit to seam site. when use this option, disable -log option.

-achive: you can choice collect log time by minite, ex -achive:2
