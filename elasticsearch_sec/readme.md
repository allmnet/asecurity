# ElasticSearch realtime correlation analysis

The Execute option is used to specify the location of the SMTP server or Rule list file used when generating an alarm when ElasticQ detects it.
```
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
```
예제
```
EX1)ElasticQ -rulefile:rule.ini -sender:<Email> -es:http://192.168.0.1:9200 -syslog:172.16.253.20 -smtp:10.0.0.5
EX2)ElasticQ -rulefile:rule.ini -sender:<Email> -es:http://192.168.0.1:9200 -syslog:172.16.253.20 -smtp:10.0.0.5 -install
```
##HOW to use
ElasticQ는 ElasticSearch가 필요합니다. 없다면 먼저 설치하세요. 

ElasticQ를 실행하기 위해 필요한 옵션과 실행시 탐지 조건을 입력하는 탐지 파일로 구분됩니다.

###룰 생성 규칙 (Rule generation rule)
룰은 항목은 | 으로 구분합니다. 항목안에 세부 옵션은 : 로 구분합니다.

항목 구분자(Item Separator) |
항목내 옵션 구분자(Option Separator in Item) : 
```
(query:logon AND fail:>:1|time:15:@timestamp|index:logstash|timebase:true|same:procid),address:sysloghost,title:WHORUfile Detect,email:allmnet@naver.com,webhook:https://~~~~
```
####query
키바나에서 검색과 동일하게 사용하시면 됩니다. : 탐지되는 갯수의 크거나 작기를 구분함 > – 갯수로 이상을 의미 < – 갯수로 이하를 의미 : (Number) 기준이 되는 탐지 갯수
```
EX1)query:logon AND fail:>:1 –>  logon AND fail 쿼리가 1개 이상일 경우
EX2)query:ping AND n:>:5 –> ping AND n 쿼리가 5개 이상일 경우
```
####time
탐지를 진행하는 시간으로 분 단위로 계산됩니다. : 레코드의 타임 기준 값으로 시간을 계산할 때 이용되는 필드를 지정합니다.
```
EX1) time:5:createtime –> 5분 단위로 query 조건을 검색하고 타임 필드는 createtime
EX2) time:10:timestamp –> 10분 단위로 query 조건을 검색하고 타임 필드는 timestamp
```
####index
Elasticsearch 의 Query 조건을 검색할 인덱스명을 지정합니다.
```
EX1) index:logstash –> logstash 와 동일한 인덱스
EX2) index:logstash-2018* –> logstash-2018로 시작하는 모든 인덱스
```
####timebase
Elasticsearch 의 인덱스가 타임으로 생성되는지에 대한 조건을 설정합니다.

Elasticsearch의 인덱스가 타임 베이스인 경우 인덱스 명이 자동으로  -YYYY.MM.DD로 생성되어 이부분을 지원하기 위한 옵션입니다. 실시간 감시를 위해서 인덱스 명이 -YYYY.MM.DD 같이 변경되는 경우에만 사용합니다.
```
EX1) index:logstash|timebase:true –> logstash-YYYY.MM.DD 의 인덱스(현재 오늘 날짜로 인식)
EX2) index:logstash-2018*|timebase:false –> logstash-2018* 인덱스, 매 검색에 2018 전체를 검색하기 때문에 실시간 탐지에 부하가 발생 할 수 있습니다. 
```
####same

필드의 동일한 값이 탐지 조건에 필요 할 때 사용됩니다. 동일한 계정명, IP의 로그인 실패를 확인하고자 할 때 유용합니다.
```
EX1) same:procid –> procid 값이 동일한 레코드로 수집하여 탐지 합니다. query의 탐지 기준 값이 5 이상이라면 동일한 procid가 5개 이상일 경우가 탐지 조건이 됩니다.
EX2) same:sysloghost –> sysloghost값이 동일한 레코드로 수집하여 탐지 합니다. 
```
####and, not
Query 조건으로 하지 못한 보다 정밀한 조건을 넣을 때 사용됩니다.
It is used when putting more precise condition that can not be done by query condition.
and는 해당 값이 포함되어야 탐지 됩니다. and is detected until the value is included.
not는 해당 값이 포함되지 않아야 탐지 됩니다.  not is detected unless it is included.
```
EX1)and:message=network –> message필드에에 network라는 문구가 포함되어야 탐지 레코드가 됩니다.  The message field must contain the phrase network to become a detection record.
EX2)not:programname=mail –> programname필드에 mail이라는 문구가 포함되지 않은 레코드를 탐지 합니다. Detects records that do not contain the phrase mail in the programname field.
```
####address
IP가 동일한 것만 취급할 경우 사용됩니다. 탐지가 된 이벤트에 대한 IP를 확인하여 동일한 IP가 query 조건의 갯수 이상일 경우에만 탐지 됩니다. 두개 이상의 탐지 조건을 넣었을 때 동일한 서버에서 발생한 경우에 유용합니다.


###상관 조건 탐지
전체적으로 탐지 조건은 중괄호를 감싸고 콤마를 통해서 구분됩니다.

두개의 탐지 조건을 넣고자 한다면, 콤마와 중괄호 두개를 사용하면 됩니다. 탐지 조건이 모두 맞을 경우에 알람이 발생합니다.
```
탐지 조건 1개 (1 detection condition)
(query:logon AND fail:>:1|time:15:@timestamp|index:logstash|timebase:true),address:sysloghost,title:WHORUfile Detect,email:jshan@bluehole.net,webhook:https://~~~~

탐지 조건 2개 (2 detection condition)
(query:logon AND fail:>:1|time:15:@timestamp|index:logstash|timebase:true),(query:ping AND n:>:1|time:15:@timestamp|index:logstash|timebase:true),address:sysloghost,title:WHORUfile Detect,email:jshan@bluehole.net,webhook:https://~~~~

 ```

###액션 (Action)
title
탐지가 되었을 때 알람을 발생하는 제목입니다.
email
탐지가 되었을 때 알람을 전송하고자 하는 메일 주소 입니다.
webhook
탐지가 되었을 때 알람을 전송하고자 하는 웹훅 주소 입니다. Slack, Teams와 연동하여 사용이 가능합니다.
