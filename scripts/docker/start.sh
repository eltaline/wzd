#!/bin/bash

for X in `env`; do

echo "$VARKEY:$VARVAL"

VARKEY=`echo $X | awk -F "=" '{print $1}'`
VARVAL=`echo $X | awk -F "=" '{print $2}'`

sed -i -e "s#\bvar_$VARKEY\b#$VARVAL#" /etc/wzd/wzd.conf

if [ "$VARKEY" == "root" ] ; then

chown -R wzd.wzd $VARVAL

fi

done

ulimit -n 131072

su wzd -c 'ulimit -n 131072 ; /usr/bin/wzd --config /etc/wzd/wzd.conf'

#END