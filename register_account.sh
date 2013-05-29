#!/bin/sh

swauth-prep -K swauthkey
swauth-add-user -A http://127.0.0.1:8080/auth/ -K swauthkey -a rpyaccount rpy rpykey
swauth-add-user -A http://127.0.0.1:8080/auth/ -K swauthkey -a rzhaccount rzh rzhkey
swauth-add-user -A http://127.0.0.1:8080/auth/ -K swauthkey -a xyaccount xy xykey
swift -A http://127.0.0.1:8080/auth/v1.0 -U rpyaccount:rpy -K rpykey stat
swift -A http://127.0.0.1:8080/auth/v1.0 -U rzhaccount:rzh -K rzhkey stat
swift -A http://127.0.0.1:8080/auth/v1.0 -U xyaccount:xy -K xykey stat
