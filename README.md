# FortigateApi
Access Fortigate REST API in python

Just connect to your firewall and start automating everything:
- creation (with IDEMPOTENCY if you wish)
- delete
- get info

Of theses objects:
- vdom
- user
- address / address group
- services / services group
- static routes
- firewall policy
- shapping policy
- ip pools
- vip
- VPN


For now only through HTTP access not HTTPS.


If an example is worth a thousand words:

import FortigateApi, sys

fg = FortigateApi.Fortigate(ip, vdom, user, passwd)


fg.AddVlanInterfaceIdempotent(name='myInt', interface='Internal1', vlanid=222, ip_mask='1.1.1.1 255.255.255.0', vdom='mydom', mode='static', allowaccess='ping')

fg.GetVlanInterface('myint')

fg.DelInterface('myint')

fg.AddRouterStaticIdempotent('0.0.0.0 0.0.0.0', int_name, gw_ip)

fg.AddFwAddressIdempotent(name, ip mask, interface)

...

clean and simple (at least i tried to)
