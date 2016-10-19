# FortigateApi.py
# access to fortigate rest api
# David Chayla - nov 2016

import requests, json


# class
class Fortigate:
    def __init__(self, ip, vdom, user, passwd):
        ipaddr = 'http://' + ip
        
        # URL definition
        self.login_url = ipaddr + '/logincheck'
        self.logout_url = ipaddr + '/logout'
        self.api_url = ipaddr + '/api/v2/'

        self.vdom = vdom

        # Start session to keep cookies
        self.s = requests.Session()

        # Login
        # REMEMBER TO CHANGE THIS TO YOUR USER
        payload = {'username': user, 'secretkey': passwd}
        self.r = self.s.post(self.login_url, data=payload)

        #print 'login status:', self.r.status_code
        #print 'cookie:', self.s.cookies['ccsrftoken']

        for cookie in self.s.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1]
                self.s.headers.update({'X-CSRFTOKEN': csrftoken})
    
    def Logout(self):
        req = self.s.get(self.logout_url)
        #print 'logout status:', req.status_code

    def ApiRequest(self, method):
        'requests methods to api_url and prints the result in json decoded format'
        req = self.s.get(self.api_url + method, params={'vdom':self.vdom})
        #print '----json', r.json()
        #print '----text', r.text
        #print 'request status:', r.status_code
        return req

    def ApiPost(self, method, data=None):
        'post to api_url in json encoded format'
        req = self.s.post(self.api_url + method, params={'vdom':self.vdom}, data=repr(data))
        #print 'ApiPost text:', req.text
        return req.status_code

    def ApiDelete(self, method, data=None):
        'delete to api_url in json encoded format'
        req = self.s.delete(self.api_url + method, params={'vdom':self.vdom}, data=repr(data))
        #print 'status:', r.status_code
        #print r.text
        return req.status_code

    def Exists(self, method, objects):
        req = self.ApiRequest(method)
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            identical = True 
            #print '--------'
            for x in range(0,len(objects)):
                req_res = data['results'][y][objects[x][0]]
                if (type(req_res) is list):
                    if ((req_res != []) and (objects[x][1] != req_res[0]['name'])):
                        #print 'object list is different:',objects[x][0], objects[x][1] ,'to',req_res[0]['name']
                        identical = False
                        break
                elif (objects[x][1] != req_res):
                    #print 'object is different:', objects[x][0], ':', objects[x][1] ,'to', req_res
                    identical = False
                    break	
            if identical: 
                return True 
        return False 
	#
    def GetVdom(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/system/vdom/' + name)
        return req.text

    def AddVdom(self, name):
        payload = {'json':
                    {
                    'name':  name 
                    }     
                }
        return self.ApiPost('cmdb/system/vdom/', payload)
    
    def AddVdomIdempotent(self, name):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/system/vdom/', objects)):
            #object does not exist, create it
            return self.AddVdom(name)
        else: 
            #object already Exists
            return 200

    def DelVdom(self, name):
        payload = { }
        return self.ApiDelete('cmdb/system/vdom/' + name, data=payload)

    #
    def GetSystemAdmin(self, name=''):
        #without id: prints all
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/system/admin/' + name)
        return req.text

    def AddSystemAdmin(self, name, password, profile='prof_admin', remote_auth='disable'):
        #profile: prof_admin/super_admin
        payload = {'json':
                    {
                    'name':  name,
                    'password': password,
                    'accprofile': profile,
                    'remote-auth':remote_auth,
                     "vdom":[
                            {
                        "name":self.vdom,
                            }
                         ]
                    }     
                }
        return self.ApiPost('cmdb/system/admin/', payload)
   
    def AddSystemAdminIdempotent(self, name, password, profile='prof_admin', remote_auth='disable'):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/system/admin/', objects)):
            #object does not exist, create it
            return self.AddSystemAdmin(name, password, profile, remote_auth)
        else: 
            #object already Exists
            return 200

    def DelSystemAdmin(self, name):
        payload = { }
        return self.ApiDelete('cmdb/system/admin/' + name, data=payload)

    #
    def GetInterface(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/system/interface/' + name)
        result = []
        data = json.loads(req.text)
        #search for current vdom only
        for y in range(0,len(data['results'])):
               if self.vdom == data['results'][y]['vdom']:
                   result.append(data['results'][y])
        return json.dumps(result, indent=4)
    
    def AddLoopbackInterface(self, name, ip_mask, vdom, allowaccess):
        #type:vlan/loopback
        #allowaccess: ping/http/https/ssh/snmp
        payload = { 'json':
                    {
                    'name': name,
                    'type': 'loopback', 
                    'ip': ip_mask,
                    'vdom': vdom, 
                    'mode': 'static', 
                    'status': 'up',
                    'secondary-IP': 'disable',
                    'alias':'',
                    "ipv6": {
                        "ip6-extra-addr": []
                     },
                    'allowaccess': allowaccess
                    }   
                }
        return self.ApiPost('cmdb/system/interface/', payload)

    def AddLoopbackInterfaceIdempotent(self, name, ip_mask, vdom, allowaccess):
        objects =  [['name',name],['ip',ip_mask]] 
        if not (self.Exists('cmdb/system/interface/', objects)):
            #object does not exist, create it
            return self.AddLoopbackInterface(name, ip_mask, vdom, allowaccess)
        else: 
            #object already Exists
            return 200

    def AddVlanInterface(self, name, interface, vlanid, ip_mask, vdom, mode, allowaccess):
        #type:vlan/loopback
        #allowaccess: ping/http/https/ssh/snmp
        payload = { 'json':
                    {
                    'name': name,
                    'vlanid': vlanid,
                    'vdom': vdom,     
                    'interface': interface,
                    'type': 'vlan', 
                    'ip': ip_mask, 
                    'mode': mode, 
                    'status': 'up',
                    "dhcp-relay-service":"disable",
                    "dhcp-relay-ip":"",
                    "dhcp-relay-type":"regular",
                    'secondary-IP': 'disable',
                    'alias':'',
                    "ipv6": {
                        "ip6-extra-addr": []
                     },
                    'allowaccess': allowaccess
                    }   
                }
        #return self.ApiPost('cmdb/system/interface/', payload)
        method = 'cmdb/system/interface/'
        req = self.s.post(self.api_url + method, params={'vdom':'root'}, data=repr(payload))
        #print 'ApiPost text:', req.text
        return req.status_code

    def AddVlanInterfaceIdempotent(self, name, interface, vlanid, ip_mask, vdom, mode, allowaccess):
        objects =  [['name',name],['interface',interface],['vlanid', int(vlanid)],['ip',ip_mask]] 
        if not (self.Exists('cmdb/system/interface/', objects)):
            #object does not exist, create it
            return self.AddVlanInterface(name, interface, vlanid, ip_mask, vdom, mode, allowaccess)
        else: 
            #object already Exists
            return 200

    def SetVlanInterface(self, name, vlanid, ip_mask, vdom, mode, allowaccess):
        payload = { 'json':
                {
                'vlanid': vlanid, 
                'ip': ip_mask,
                'vdom': vdom, 
                'mode': mode, 
                'allowaccess': allowaccess
                }     
            }
        return self.ApiPost('cmdb/system/interface/' + name, payload)

    def DelInterface(self, name):
        payload = { }
        return self.ApiDelete('cmdb/system/interface/' + name, data=payload)

    def DelAllInterface(self):
        req = self.ApiRequest('cmdb/system/interface/')
        data = json.loads(req.text)
        final_return_code = 200
        for y in range(0,len(data['results'])):
            if self.vdom == data['results'][y]['vdom']:
                int_name = data['results'][y]['name']
                return_code = self.DelInterface(int_name)
                print 'del interface:', int_name, '(', return_code,')'
                if return_code != 200: final_return_code = return_code
        return final_return_code
    #
    def GetFwAddress(self, name=''):
        #without id: prints all
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/firewall/address/' + name)
        return req.text

    def AddFwAddress(self, name, subnet, associated_interface='', comment=''):
        payload = {'json':
                    {
                    'name':  name ,
                    'associated-interface': associated_interface,
                    'comment': comment,
                    'subnet':  subnet 
                    }     
                }
        return self.ApiPost('cmdb/firewall/address/', payload)

    def AddFwAddressIdempotent(self, name, subnet, associated_interface='', comment=''):
        objects =  [['name',name],['subnet',subnet]] 
        if not (self.Exists('cmdb/firewall/address/', objects)):
            #object does not exist, create it
            return self.AddFwAddress(name, subnet, associated_interface, comment)
        else: 
            #object already Exists
            return 200
    

    def DelFwAddress(self, name):
        payload = {'json':
                    {
                    'name':name
                    }
                }
        return self.ApiDelete('cmdb/firewall/address', data=payload)

    def DelAllFwAddress(self):
        req = self.ApiRequest('cmdb/firewall/address/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            address_name = data['results'][y]['name']
            return_code = self.DelFwAddress(address_name)
            print 'del fw address :', address_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwAddressGroup(self, name=''):
        req = self.ApiRequest('cmdb/firewall/addrgrp/' + name)
        return req.text

    def AddFwAddressGroup(self, name, member_list):
        member = []
        for member_elem in member_list:
            member.append({'name': member_elem})
        payload = {'json':
                    {
                    'name':  name,
                    'member': member
                    }     
                }
        return self.ApiPost('cmdb/firewall/addrgrp/', payload)

    def AddFwAddressGroupIdempotent(self, name, member_list):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/firewall/addrgrp/', objects)):
            #object does not exist, create it
            return self.AddFwAddressGroup(name, member_list)
        else: 
            #object already Exists
            return 200

    def DelFwAddressGroup(self, name):
        payload = {'json':
                    {
                    'name': name
                    }     
                }
        return self.ApiDelete('cmdb/firewall/addrgrp/', payload)
    
    def DelAllFwAddressGroup(self):
        req = self.ApiRequest('cmdb/firewall/addrgrp/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            group_name = data['results'][y]['name']
            return_code = self.DelFwAddressGroup(group_name)
            print 'del fw address group:', group_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetRouterStaticID(self, id=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/router/static/' + id)
        return req.text

    def AddRouterStatic(self, dst, device, gateway, comment=''):
        # dst example '1.1.1.1 255.255.255.0'
        payload = {'json':
                    {
                    'dst':  dst,
                    'device': device,
                    'gateway': gateway,
                    'comment': comment
                    }     
                }
        return self.ApiPost('cmdb/router/static/', payload)

    def AddRouterStaticIdempotent(self, dst, device, gateway, comment=''):
        objects =  [['dst',dst],['device',device],['gateway',gateway]] 
        if not (self.Exists('cmdb/router/static/', objects)):
            #object does not exist, create it
            return self.AddRouterStatic(dst, device, gateway, comment)
        else: 
            #object already Exists
            return 200

    def DelRouterStaticID(self, id):
        payload = {'json': 
                    {
                    }
                }
        return self.ApiDelete('cmdb/router/static/' + str(id), data=payload)

    def DelRouterStatic(self, dst):
        # dst example '1.1.1.1 255.255.255.0'
        # get all the static routes
        req = self.ApiRequest('cmdb/router/static/')
        data = json.loads(req.text)
        # search for router static ID with specific dst
        for x in range(0,len(data['results'])):
            if (dst == data['results'][x]['dst']):
                # ID is found : delete it
                return self.DelRouterStaticID(data['results'][x]['seq-num'])	
        return 404

    def DelAllRouterStatic(self):
        req = self.ApiRequest('cmdb/router/static/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            route_id = data['results'][y]['seq-num']
            return_code = self.DelRouterStaticID(route_id)
            print 'del route id:', route_id , '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwPolicyID(self, id=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/firewall/policy/' + id)
        return req.text

    def AddFwPolicy(self, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL', action='accept', schedule='always', nat='disable', poolname='[]', ippool='disable', status='enable', comments=''):
        payload = {'json':
                    {
                    'srcintf': [
                            {
                             'name': srcintf
                            } 
                    ],
                    'dstintf': [
                            {
                             'name': dstintf
                            } 
                    ],       
                    'srcaddr': [
                            {
                             'name': srcaddr
                            } 
                    ],
                    'dstaddr': [
                            {
                             'name': dstaddr
                            } 
                    ],
                    'action': action,
                    'schedule': schedule,
                    'nat': nat,
                    'status': status,
                    'nat': nat,
                    'ippool': ippool,
                    'poolname': [
                            {
                             'name': poolname
                            } 
                    ],
                    'service': [
                            {
                             'name': service
                            } 
                    ],
                    'comments': comments
                    }     
                }
        return self.ApiPost('cmdb/firewall/policy/', payload)

    def AddFwPolicyIdempotent(self, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL', action='accept', schedule='always', nat='disable', poolname='[]', ippool='disable', status='enable', comments=''):
        objects =  [['srcintf',srcintf],['dstintf',dstintf],['srcaddr',srcaddr],['dstaddr',dstaddr],['service',service],['action',action],['schedule',schedule],['nat',nat],['poolname',poolname],['ippool',ippool],['status',status]] 
        if not (self.Exists('cmdb/firewall/policy/', objects)):
            #object does not exist, create it
            #print 'AddFwPolicyIdempotent: object does not exists'
            return self.AddFwPolicy(srcintf, dstintf, srcaddr, dstaddr, service, action, schedule, nat, poolname, ippool, status, comments)
        else: 
            #object already Exists
            #print 'AddFwPolicyIdempotent: object already exists'
            return 200



    def GetFwPolicyID(self, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL'):
        objects =  [['srcintf',srcintf],['dstintf',dstintf],['srcaddr',srcaddr],['dstaddr',dstaddr],['service',service]] 
        req = self.ApiRequest('cmdb/firewall/policy/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            identical = True 
            for x in range(0,len(objects)):
                req_res = data['results'][y][objects[x][0]]
                if (type(req_res) is list):
                    if ((req_res != []) and (objects[x][1] != req_res[0]['name'])):
                        #print 'object list is different:',objects[x][0], objects[x][1] ,'to',req_res[0]['name']
                        identical = False
                elif (objects[x][1] != req_res):
                    #print 'object is different:', objects[x][0], ':', objects[x][1] ,'to', req_res
                    identical = False	
            if identical: 
                #print 'policyid:', data['results'][y]['policyid']
                return data['results'][y]['policyid']
        return None

    def DelFwPolicy(self, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL'):
        fw_id = self.GetFwPolicyID(srcintf, dstintf, srcaddr, dstaddr, service)
        if fw_id != None:
            return self.DelFwPolicyID(fw_id)
        else:    
            return 404
       
    def DelFwPolicyID(self, id):
        payload = {'json': 
                    {
                    }
                }
        return self.ApiDelete('cmdb/firewall/policy/' + str(id), data=payload) 
    
    def DelAllFwPolicy(self):
        req = self.ApiRequest('cmdb/firewall/policy/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            policy_id = data['results'][y]['policyid']
            return_code = self.DelFwPolicyID(policy_id)
            print 'del fw policy id:', policy_id ,  '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwService(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/firewall.service/custom/' + name)
        return req.text

    def AddFwService(self,name, tcp_portrange='', udp_portrange='', protocol='TCP/UDP/SCTP', fqdn='', iprange='0.0.0.0',  comment=''):
        if tcp_portrange : protocol_number = 6
        elif udp_portrange : protocol_number = 17

        payload = {'json':
            {
            'name': name,
            'tcp-portrange': tcp_portrange,
            'udp-portrange': udp_portrange,
            'protocol':  protocol,
            'protocol-number': protocol_number,
            'fqdn': fqdn, 
            'iprange': iprange,
            'comment': comment
            }     
        }
        return self.ApiPost('cmdb/firewall.service/custom/', payload)
    
    def AddFwServiceIdempotent(self,name, tcp_portrange='', udp_portrange='', protocol='TCP/UDP/SCTP', fqdn='', iprange='0.0.0.0',  comment=''):
        objects = [['name',name],['tcp-portrange',tcp_portrange],['udp-portrange',udp_portrange],['protocol',protocol],['fqdn',fqdn],['iprange',iprange]]
        if not (self.Exists('cmdb/firewall.service/custom/', objects)):
            #object does not exist, create it
            #print 'AddFwServiceIdempotent: object does not exist, create it'
            return self.AddFwService(name, tcp_portrange, udp_portrange, protocol, fqdn, iprange, comment)
        else: 
            #object already Exists
            return 200

    def DelFwService(self, name):
        payload = {'json':
                {
                'name': 'custom'
                }     
            }
        return self.ApiDelete('cmdb/firewall.service/custom/' + name, payload)
    
    def DelAllFwService(self):
        req = self.ApiRequest('cmdb/firewall.service/custom/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            service_name = data['results'][y]['name']
            return_code = self.DelFwService(service_name)
            print 'del fw service :', service_name, '(', return_code,')'
            #if return_code != 200: return return_code
        return 200
    #
    def GetFwServiceGroup(self, name=''):
        #without id: prints all the statics routes
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/firewall.service/group/' + name)
        return req.text
    
    def AddFwServiceGroup(self, name, member_list):
        member = []
        for member_elem in member_list:
            member.append({'name': member_elem})
        payload = {'json':
                    {
                    'name':  name,
                    'member': member
                    }     
                }
        #print 'AddFwServiceGroup:', payload
        return self.ApiPost('cmdb/firewall.service/group/', payload)

    def AddFwServiceGroupIdempotent(self, name, member_list):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/firewall.service/group/', objects)):
            #object does not exist, create it
            return self.AddFwServiceGroup(name, member_list)
        else: 
            #object already Exists
            return 200

    def DelFwServiceGroup(self, name):
        payload = {'json':
                    {
                    'name': name
                    }     
                }
        return self.ApiDelete('cmdb/firewall.service/group/', payload)    
    
    def DelAllFwServiceGroup(self):
        req = self.ApiRequest('cmdb/firewall.service/group/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            service_group_name = data['results'][y]['name']
            return_code = self.DelFwServiceGroup(service_group_name)
            print 'del fw service group:', service_group_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetTrafficShaper(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/firewall.shaper/traffic-shaper/' + name)
        return req.text
    
    def AddTrafficShaper(self, name, per_policy, priority, guaranteed_bandwidth, maximum_bandwidth, diffserv='disable', diffservcode='000000'):
        # priority: high/medium/low
        # per_policy : enable/disable
        payload = {'json':
            {
            'name': name,
            'per-policy': per_policy,
            'priority': priority,
            'guaranteed-bandwidth':  int(guaranteed_bandwidth),
            'maximum-bandwidth': int(maximum_bandwidth),
            'diffserv': diffserv, 
            'diffservcode': diffservcode
            }     
        }
        return self.ApiPost('cmdb/firewall.shaper/traffic-shaper/', payload)
    
    def AddTrafficShaperIdempotent(self, name, per_policy, priority, guaranteed_bandwidth, maximum_bandwidth, diffserv='disable', diffservcode='000000'):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/firewall.shaper/traffic-shaper/', objects)):
            #object does not exist, create it
            return self.AddTrafficShaper(name, per_policy, priority, guaranteed_bandwidth, maximum_bandwidth, diffserv, diffservcode)
        else: 
            #object already Exists
            return 200

    def DelTrafficShaper(self, name=''):
        payload = {'json':
                    {
                    
                    }     
                }
        return self.ApiDelete('cmdb/firewall.shaper/traffic-shaper/' + name, payload)     
    
    def DelAllTrafficShaper(self):
        req = self.ApiRequest('cmdb/firewall.shaper/traffic-shaper/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            traffic_shaper_name = data['results'][y]['name']
            return_code = self.DelTrafficShaper(traffic_shaper_name)
            print 'del traffic shaper:', traffic_shaper_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwVIP(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/firewall/vip/' + name)
        return req.text

    def AddFwVIP(self, name, extip, extintf, mappedip, portforward='disable', extport='0-65535', mappedport='0-65535', comment=''):
        mappedip = [{'range': mappedip}]
        payload = {'json':
            {
            'name': name,
            'extip': extip,
            'extintf': extintf,
            'mappedip':  mappedip,
            'portforward': portforward,
            'extport': extport,
            'mappedport': mappedport,
            'comment': comment
            }     
        }
        return self.ApiPost('cmdb/firewall/vip/', payload)
    
    def AddFwVIPidempotent(self, name, extip, extintf, mappedip, portforward='disable', extport='0-65535', mappedport='0-65535', comment=''):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/firewall/vip/', objects)):
            #object does not exist, create it
            return self.AddFwVIP(name, extip, extintf, mappedip, portforward, extport, mappedport, comment)
        else: 
            #object already Exists
            return 200
    
    def DelFwVIP(self, name):
        payload = {'json':
                    {
                    'name': 'vip'
                    }     
                }
        return self.ApiDelete('cmdb/firewall/vip/' + name, payload)  
    
    def DelAllFwVIP(self):
        req = self.ApiRequest('cmdb/firewall/vip/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            vip_name = data['results'][y]['name']
            return_code = self.DelFwVIP(vip_name)
            print 'del vip:', vip_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwIPpool(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req = self.ApiRequest('cmdb/firewall/ippool/' + name)
        return req.text  
    
    def AddFwIPpool(self, name, startip, endip, type_pool='overload', internal_startip='0.0.0.0', external_startip='0.0.0.0', comment=''):
        #type_pool : overload/one-to-one/fixed-port-range         
        payload = {'json':
            {
            'name': name,
            'startip': startip,
            'endip': endip,
            'type':  type_pool,
            'source-startip': internal_startip,
            'source-endip': external_startip,
            'comments': comment
            }     
        }
        return self.ApiPost('cmdb/firewall/ippool/', payload)

    def AddFwIPpoolIdempotent(self, name, startip, endip, type_pool='overload', internal_startip='0.0.0.0', external_startip='0.0.0.0', comment=''):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/firewall/ippool/', objects)):
            #object does not exist, create it
            return self.AddFwIPpool(name, startip, endip, type_pool, internal_startip, external_startip, comment)
        else: 
            #object already Exists
            return 200
        
    def DelFwIPpool(self, name):
        payload = {'json':
                    {
                    'name': 'ippool'
                    }     
                }
        return self.ApiDelete('cmdb/firewall/ippool/' + name, payload)  

    def DelAllFwIPpool(self):
        req = self.ApiRequest('cmdb/firewall/ippool/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            ippool_name = data['results'][y]['name']
            return_code = self.DelFwIPpool(ippool_name)
            print 'del ip pool:', ippool_name , 'res:', return_code
            if return_code != 200: return return_code
        return 200 
    #
    def GetVPNipsecPhase1(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req_phase1 = self.ApiRequest('cmdb/vpn.ipsec/phase1-interface/' + name)
        return req_phase1.text

    def GetVPNipsecPhase2(self, name=''):
        #without id: prints all 
        #with id: print only the selected one
        req_phase2 = self.ApiRequest('cmdb/vpn.ipsec/phase2-interface/' + name)
        return req_phase2.text 

    def AddVPNipsecPhase1(self, name, interface, remote_gw, nattraversal, dpd, psk, ike_version, mode, proposal, dhgrp, keylife=28800, localid=''):
        #nattraversal: enable/disable
        #dpd: enabel/disable
        #ike-version: 1/2
        #mode: main/..
        #proposal: aes256-sha1/
        #dhgrp: 1/2/5/14/15...
        #keylife: default 28800
        #psk: <minimum 6 car>
        payload = {'json':
                {
            'name': name,
            'type': 'static',
            'interface': interface,
            'ip-version': 4,
            'ike-version': int(ike_version), 
            'local-gw': '0.0.0.0', 
            'nattraversal': nattraversal,
            'keylife': int(keylife),
            'authmethod': 'psk',
            'mode': mode, 
            'proposal': proposal,
            'localid': localid,
            'dpd': dpd, 
            'dhgrp': dhgrp, 
            'remote-gw': remote_gw,
            'psksecret': psk
                }     
            }
        return self.ApiPost('cmdb/vpn.ipsec/phase1-interface/', payload)

    def AddVPNipsecPhase1Idempotent(self, name, interface, remote_gw, nattraversal, dpd, psk, ike_version, mode, proposal, dhgrp, keylife=28800, localid=''):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/vpn.ipsec/phase1-interface/', objects)):
            #object does not exist, create it
            return self.AddVPNipsecPhase1(name, interface, remote_gw, nattraversal, dpd, psk, ike_version, mode, proposal, dhgrp, keylife, localid)
        else: 
            #object already Exists
            return 200

    def AddVPNipsecPhase2(self, name, phase1name, src_addr_type, src_subnet, dst_addr_type, dst_subnet, proposal, pfs, dhgrp, replay, keepalive, keylife_type, keylifeseconds):
        #src_addr_type: subnet/
        #proposal: aes128-sha1/aes256-sha1/
        #pfs: enable/disable
        #replay: enable/disable
        #keepalive: enable/disable
        #keylife-type: seconds
        payload = {'json':
                {
            'name': name,
            'phase1name': phase1name,
            'src-addr-type': src_addr_type,
            'src-subnet': src_subnet,
            'dst-addr-type': dst_addr_type, 
            'dst-subnet': dst_subnet, 
            'proposal': proposal, 
            'pfs': pfs, 
            'dhgrp': dhgrp,
            'replay': replay,
            'keepalive': keepalive,
            'keylife-type': keylife_type,
            'keylifeseconds': int(keylifeseconds)
                }     
            }
        return self.ApiPost('cmdb/vpn.ipsec/phase2-interface/', payload)

    def AddVPNipsecPhase2Idempotent(self, name, phase1name, src_addr_type, src_subnet, dst_addr_type, dst_subnet, proposal, pfs, dhgrp, replay, keepalive, keylife_type, keylifeseconds):
        objects =  [['name',name]]
        if not (self.Exists('cmdb/vpn.ipsec/phase2-interface/', objects)):
            #object does not exist, create it
            return self.AddVPNipsecPhase2(name, phase1name, src_addr_type, src_subnet, dst_addr_type, dst_subnet, proposal, pfs, dhgrp, replay, keepalive, keylife_type, keylifeseconds)
        else: 
            #object already Exists
            return 200
    
    def DelVPNipsec(self, name):
        #delete phase1 and phase2 configuration
        req = self.GetVPNipsecPhase2()
        data = json.loads(req)
        for y in range(0,len(data['results'])):
            cur_phase1 = data['results'][y]['phase1name']
            if  cur_phase1 == name:
                cur_phase2 = data['results'][y]['name']
                #print 'del phase2:', cur_phase2
                self.DelVPNipsecPhase2(cur_phase2)
        #print 'del phase1:', cur_phase1
        return self.DelVPNipsecPhase1(cur_phase1)      


    def DelVPNipsecPhase1(self, name):
        payload = {'json':
                    {
                    'name': name
                    }     
                }
        return self.ApiDelete('cmdb/vpn.ipsec/phase1-interface/', payload)  

    def DelVPNipsecPhase2(self, name):
