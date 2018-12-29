# FortigateApi
Access Fortigate REST API in python

Just connect to your firewall and start automating everything:
- create (with IDEMPOTENCY if you wish)
- delete
- get info
- modify existing object

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


Access to the firewall through HTTPS (tested ok fortigate firmware 5.2 or 5.4, should work for newer versions).


If an example is worth a thousand words (connect to the fw, create an fw address object, get the json definition of the object, modify the ip address and then delete the object):
```
import FortigateApi 

fg = FortigateApi.Fortigate('172.30.40.50', 'myvdom', 'admin', 'mypasswd') 

fg.AddFwAddress('srv-A','10.1.1.1/32')
200

fg.GetFwAddress('srv-A')
u'{\n  "http_method":"GET",\n  "results":[\n    {\n      "name":"srv-A",\n      "q_origin_key":"srv-A",\n      "uuid":"2103d064-d520-51e6-de84-16e9ab03b8ae",\n      "subnet":"10.1.1.1 255.255.255.255",\n      "type":"ipmask",\n      "start-ip":"10.1.1.1",\n      "end-ip":"255.255.255.255",\n      "fqdn":"",\n      "country":"",\n      "url":"",\n      "cache-ttl":0,\n      "wildcard":"10.1.1.1 255.255.255.255",\n      "comment":"",\n      "visibility":"enable",\n      "associated-interface":"",\n      "color":0,\n      "tags":[\n      ]\n    }\n  ],\n  "vdom":"dc2",\n  "path":"firewall",\n  "name":"address",\n  "mkey":"srv-A",\n  "status":"success",\n  "http_status":200,\n  "serial":"FWF90D3Z13003141",\n  "version":"v5.2.9",\n  "build":736\n}'

fg.SetFwAddress('srv-A','10.2.2.2/32')
200

fg.DelFwAddress('srv-A')
200
```

A toolbox of everything you need to manage the fw, used for daily production at Sigma Informatique.
Clean and simple (at least i tried to)
