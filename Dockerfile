FROM debian:buster

LABEL maintainer="Andrey Kuvshinov"

ENV bindaddr "127.0.0.1:9699"
ENV bindaddrssl "127.0.0.1:9799"
ENV onlyssl false
ENV readtimeout 60
ENV readheadertimeout 5
ENV writetimeout 60
ENV idletimeout 60
ENV keepalive false
ENV realheader "X-Real-IP"
ENV charset "UTF-8"
ENV debugmode false
ENV gcpercent 25
ENV freelist "hashmap"
ENV search true
ENV searchcache 134217728
ENV searchdir "/var/lib/wzd/search"
ENV searchinit 4
ENV searchindex "ram"
ENV pidfile "/run/wzd/wzd.pid"
ENV logdir "/var/log/wzd"
ENV logmode 0640
ENV defsleep 1
ENV cmpsched true
ENV cmpdir "/var/lib/wzd/compact"
ENV cmptime 7
ENV cmpcheck 1

ENV host "localhost"
ENV root "/var/storage"
ENV sslcrt ""
ENV sslkey ""
ENV getallow "/etc/wzd/get-localhost.conf"
ENV putallow "/etc/wzd/put-localhost.conf"
ENV delallow "/etc/wzd/del-localhost.conf"
ENV options "GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE"
ENV headorigin "*"
ENV xframe "sameorigin"
ENV upload true
ENV delete true
ENV compaction true
ENV writeintegrity true
ENV readintegrity true
ENV trytimes 5
ENV opentries 5
ENV locktimeout 5
ENV skeyscnt 16384
ENV smaxsize 536870912
ENV fmaxsize 1048576
ENV vmaxsize 4096
ENV args false
ENV getbolt false
ENV getkeys false
ENV getinfo false
ENV getsearch false
ENV getrecursive false
ENV getjoin false
ENV getvalue false
ENV getcount false
ENV getcache true
ENV searchthreads 4
ENV searchtimeout 10
ENV nonunique false
ENV cctrl 0
ENV minbuffer 262144
ENV lowbuffer 1048576
ENV medbuffer 67108864
ENV bigbuffer 536870912
ENV filemode 0640
ENV dirmode 0750
ENV delbolt false
ENV deldir false
ENV gzstatic false
ENV log4xx true

RUN groupadd wzd
RUN useradd wzd -g wzd

RUN mkdir -p /etc/wzd
RUN mkdir -p ${logdir}
RUN mkdir -p ${searchdir}
RUN mkdir -p ${cmpdir}
RUN mkdir -p ${root}
RUN mkdir -p `dirname ${pidfile}`

RUN chown wzd.wzd ${logdir}
RUN chown wzd.wzd ${searchdir}
RUN chown wzd.wzd ${cmpdir}
RUN chown wzd.wzd `dirname ${pidfile}`

RUN apt-get update
RUN apt-get -y install sed util-linux

COPY wzd /usr/bin/
COPY wza/wza /usr/bin/
COPY conf/wzd/docker/wzd-docker.conf /etc/wzd/wzd.conf
COPY conf/wzd/docker/get-localhost.conf /etc/wzd/get-localhost.conf
COPY conf/wzd/docker/put-localhost.conf /etc/wzd/put-localhost.conf
COPY conf/wzd/docker/del-localhost.conf /etc/wzd/del-localhost.conf
COPY scripts/docker/start.sh /
COPY LICENSE /
COPY NOTICE /

EXPOSE 80/tcp

ENTRYPOINT ["/start.sh"]
