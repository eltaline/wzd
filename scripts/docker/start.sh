#!/bin/bash

for X in `env`; do

echo "$VARKEY:$VARVAL"

VARKEY=`echo $X | awk -F "=" '{print $1}'`
VARVAL=`echo $X | awk -F "=" '{print $2}'`

sed -i -e "s#var_$VARKEY#$VARVAL#" /etc/wzd/wzd.conf

if [ "$VARKEY" == "bindaddr" ] ; then

sed -i -e "s#var_$VARKEY#$VARVAL#" /etc/nginx/sites-available/localhost.conf

fi

done

ulimit -n 131072

nginx -c /etc/nginx/nginx.conf
su wzd -c '/usr/bin/wzd --config /etc/wzd/wzd.conf'

#END