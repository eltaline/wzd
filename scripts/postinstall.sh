#!/bin/bash

if [ -z `getent group wzd` ]; then
	groupadd wzd
fi

if [ -z `getent passwd wzd` ]; then
	useradd wzd -g wzd 
fi

install --mode=755 --owner=wzd --group=wzd --directory /var/lib/wzd
install --mode=755 --owner=wzd --group=wzd --directory /var/log/wzd

#END