ElasticSearch realtime correlation analysis

The Execute option is used to specify the location of the SMTP server or Rule list file used when generating an alarm when ElasticQ detects it.

-syslog:<ip>
send to elasticq matched query log on syslog server
-smtp:<ip>
send to elasticq matched query log on smtp server
-rulefile:<path>
elasticq rule load from this file
-sender:<Email>
This address use at email sender
-es:<httpaddress>
Query on elasticsearch server
-install
install services type.
-uninstall
uninstall services type.
EX1)ElasticQ -rulefile:rule.ini -sender:<Email> -es:http://192.168.0.1:9200 -syslog:172.16.253.20 -smtp:10.0.0.5

EX2)ElasticQ -rulefile:rule.ini -sender:<Email> -es:http://192.168.0.1:9200 -syslog:172.16.253.20 -smtp:10.0.0.5\

##install

HOW to use
