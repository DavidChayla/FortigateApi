# FortigateApi.py
# access to fortigate rest api
# David Chayla - nov 2016
# v1
# v1.2 django edition
# v1.3 https enabled
# v1.4 add http put method
# v1.5 traffic shaper on  fw policy
# v1.6 add access to user local 
# v1.7 correction DelAllUserLocal
# v1.8 creation method DelAllVPNipsec() + correction DelSystemAdmin()
# v1.9 add AddFwAddressRange
# v1.10 Suppression des msg de warnings lors de la cnx ssl
# v1.11 modify idempotence to make it 7x faster

#openstack reference
#https://github.com/openstack/networking-fortinet/blob/5ca7b1b4c17240c8eb1b60f7cfa9a46b5b943718/networking_fortinet/api_client/templates.py

import requests, json

#suppression du warning lors de la cnx https avec certi autosigne
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# class
class Fortigate:
    def __init__(self, ip, vdom, user, passwd):
        ipaddr = 'https://' + ip
        
        # URL definition
        self.login_url = ipaddr + '/logincheck'
        self.logout_url = ipaddr + '/logout'
        self.api_url = ipaddr + '/api/v2/'

        self.vdom = vdom

        # Start session to keep cookies
        self.s = requests.Session()

        # Login
        payload = {'username': user, 'secretkey': passwd}
        #verify=False to permit login even with no valid ssl cert
        self.r = self.s.post(self.login_url, data=payload, verify=False)

        print 'login status:', self.r.status_code
        #print 'cookie:', self.s.cookies['ccsrftoken']

        for cookie in self.s.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1]
                self.s.headers.update({'X-CSRFTOKEN': csrftoken})
        

    def Logout(self):
        req = self.s.get(self.logout_url)
        #print 'logout status:', req.status_code
        return req.status_code

    # About api request message naming regulations:
    # Prefix         HTTP method
    # ADD_XXX    -->    POST
    # SET_XXX    -->    PUT
    # DELETE_XXX -->    DELETE
    # GET_XXX    -->    GET

    def ApiGet(self, url):
        req = self.s.get(self.api_url + url, params={'vdom':self.vdom})
        #print '----json', req.json()
        #print '----text', req.text
        #print 'request status:', r.status_code
        return req

    def ApiAdd(self, url, data=None):
        req = self.s.post(self.api_url + url, params={'vdom':self.vdom}, data=repr(data))
        return req.status_code

    def ApiDelete(self, url, data=None):
        req = self.s.delete(self.api_url + url, params={'vdom':self.vdom}, data=repr(data))
        return req.status_code

    def ApiSet(self, url, data=None):
        req = self.s.put(self.api_url + url, params={'vdom':self.vdom}, data=repr(data))
        return req.status_code

    #-----------------------------------------------------------------------------------------        

    def Exists(self, url, objects):
        """
        Test if the objects exist in the url.

        Parameters
        ----------        
        url: the api url to test the objects (type string)
        objects: the list of objects you want to test (type [[]])
            ex:
                objects =  [['name','srv-A'],['subnet','10.1.1.1/32']] 
                self.Exists('cmdb/firewall/address/', objects)

        Returns
        -------
        Return True if all the objects exist, otherwise False.
        """
        req = self.ApiGet(url)
        data = json.loads(req.text)
        #print "exists data:", data
        #print '--------------------------------------'
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
        '''
        Return the json vdom object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------        
        name: the vdom object name (type string)
        
        Returns
        -------
        Return the json object
        '''
        req = self.ApiGet('cmdb/system/vdom/' + name)
        return req.text

    def AddVdom(self, name):
        """
        Create a new vdom.

        Parameters
        ----------        
        name: name of the vdom (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                    {
                    'name':  name 
                    }     
                }
        return self.ApiAdd('cmdb/system/vdom/', payload)
    
    def AddVdomIdempotent(self, name):
        """
        Create a new vdom, return ok if it already exist.

        Parameters
        ----------        
        name: name of the vdom (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        objects =  [['name',name]]
        if not (self.Exists('cmdb/system/vdom/', objects)):
            #object does not exist, create it
            return self.AddVdom(name)
        else: 
            #object already Exists
            return 200

    def DelVdom(self, name):
        payload = {'json':
                {
                'name': 'vdom'
                }     
            }
        return self.ApiDelete('cmdb/system/vdom/' + name + '/', data=payload)

    #
    def GetSystemAdmin(self, name=''):
        '''
        Return the json system admin object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------        
        name: the system admin object name (type string)
        
        Returns
        -------
        Return the json object
        '''
        req = self.ApiGet('cmdb/system/admin/' + name)
        return req.text

    def AddSystemAdmin(self, name, password, profile='prof_admin', remote_auth='disable'):
        """
        Create a system admin on the vdom.

        Parameters
        ----------  
        name: the system admin name (type string)
        password: the system admin password (type string)
        profile: the profile, choice: prof_admin/super_admin (type string)(default prof_admin)
        remote_auth: choice: enable/disable (type string)(default disable)
            
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        password = str(password)
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
        return self.ApiAdd('cmdb/system/admin/', payload)
   
    def AddSystemAdminIdempotent(self, name, password, profile='prof_admin', remote_auth='disable'):
        """
        Create a system admin on the vdom, return ok if it already exist.

        Parameters
        ----------  
        name: the system admin name (type string)
        password: the system admin password (type string)
        profile: the profile, choice: prof_admin/super_admin (type string)(default prof_admin)
        remote_auth: choice: enable/disable (type string)(default disable)
            
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        password = str(password)
        objects =  [['name',name]]
        if not (self.Exists('cmdb/system/admin/', objects)):
            #object does not exist, create it
            return self.AddSystemAdmin(name, password, profile, remote_auth)
        else: 
            #object already Exists
            return 200

    def SetSystemAdmin(self, name, password, profile='prof_admin', remote_auth='disable'):
        """
        Modify a system admin on the vdom.

        Parameters
        ----------  
        name: the system admin name (type string)
        password: the system admin password (type string)
        profile: the profile, choice: prof_admin/super_admin (type string)(default prof_admin)
        remote_auth: choice: enable/disable (type string)(default disable)
            
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        password = str(password)
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
        return self.ApiSet('cmdb/system/admin/'+ name + '/', payload)
   
    def DelSystemAdmin(self, name):
        """
        Delete system admin object referenced by name.

        Parameters
        ----------        
        name: object to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                {
                'name': 'admin'
                }     
            }
        return self.ApiDelete('cmdb/system/admin/'+ name + '/', data=payload)
    #
    def GetUserLocal(self, name=''):
        '''
        Return the json user local object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------        
        name: the system admin object name (type string)
        
        Returns
        -------
        Return the json object
        '''
        req = self.ApiGet('cmdb/user/local/' + name)
        return req.text

    def AddUserLocal(self, name, passwd, type_user='password', status='enable', email_to='', ldap_server='', radius_server=''):
        """
        Create a user local on the vdom.

        Parameters
        ----------  
        name: the system admin name (type string)
        passwd: the system admin password (type string)
        type_user: set to 'password' for Local (type string)
        status: (type string)(default enable)
        email_to: (type string)(default'')
        ldap_server: (type string)(default'')
        radius_server: (type string)(default'')

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        passwd = str(passwd)

        payload = {'json':
                    {
                    'name':  name,
                    'passwd': passwd,
                    'type': type_user,
                    'status': status,
                    'email-to': email_to,
                    'ldap-server': ldap_server,
                    'radius-server': radius_server,
                    }     
                }
        return self.ApiAdd('cmdb/user/local/', payload)
    
    def AddUserLocalIdempotent(self, name, passwd, type_user='password', status='enable', email_to='', ldap_server='', radius_server=''):
        """
        Create a user local on the vdom, return ok if it already exist.

        Parameters
        ----------  
        name: the system admin name (type string)
        passwd: the system admin password (type string)
        type_user: set to 'password' for Local (type string)
        status: (type string)(default enable)
        email_to: (type string)(default'')
        ldap_server: (type string)(default'')
        radius_server: (type string)(default'')

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        passwd = str(passwd)
        objects =  [['name',name],['type',type_user]]
        if not (self.Exists('cmdb/user/local/', objects)):
            #object does not exist, create it
            return self.AddUserLocal(name, passwd, type_user, status, email_to, ldap_server, radius_server) 
        else: 
            #object already Exists
            return 200

    def SetUserLocal(self, name, passwd, type_user='password', status='enable', email_to='', ldap_server='', radius_server=''):
        """
        Modify a user local on the vdom.

        Parameters
        ----------  
        name: the system admin name (type string)
        passwd: the system admin password (type string)
        type_user: set to 'password' for Local (type string)
        status: (type string)(default enable)
        email_to: (type string)(default'')
        ldap_server: (type string)(default'')
        radius_server: (type string)(default'')
            
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        passwd = str(passwd)

        payload = {'json':
                    {
                    'name':  name,
                    'passwd': passwd,
                    'type': type_user,
                    'status': status,
                    'email-to': email_to,
                    'ldap-server': ldap_server,
                    'radius-server': radius_server,
                    }     
                }
        return self.ApiSet('cmdb/user/local/'+ name + '/', payload)

    def DelUserLocal(self, name):
        """
        Delete user local object referenced by name.

        Parameters
        ----------        
        name: object to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                {
                'name': 'local'
                }     
            }
        return self.ApiDelete('cmdb/user/local/' + name + '/', data=payload)
    
    def DelAllUserLocal(self):
        """
        Delete all user local object of the vdom.

        Parameters
        ----------        

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        req = self.ApiGet('cmdb/user/local/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            user_name = data['results'][y]['name']
            return_code = self.DelUserLocal(user_name)
            print 'del user :', user_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetInterface(self, name=''):
        """
        Return the json interface object, when the param id is defined it returns the selected object, without id: return all the objects
                
        Parameters
        ----------
        name: the object name or nothing (type string)
 
        Returns
        -------
        Return the json fw interface object
        """
        req = self.ApiGet('cmdb/system/interface/' + name)
        result = []
        data = json.loads(req.text)
        #search for current vdom only
        for y in range(0,len(data['results'])):
               if self.vdom == data['results'][y]['vdom']:
                   result.append(data['results'][y])
        return json.dumps(result, indent=4)
    
    def AddLoopbackInterface(self, name, ip_mask, vdom, allowaccess=''):
        """
        Create a loopback interface on the vdom.

        Parameters
        ----------       
        name: the name of the loopback int (type string)
        ip_mask: the ip and mask (for ex: 1.1.1.1 255.255.255.255 or 1.1.1.1/32)(type string)
        vdom: the existing vdom of the loopback (type string)
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)(default none)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        ip_mask = str(ip_mask)
        vdom = str(vdom)
        allowaccess = str(allowaccess)
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
        return self.ApiAdd('cmdb/system/interface/', payload)

    def AddLoopbackInterfaceIdempotent(self, name, ip_mask, vdom, allowaccess):
        """
        Create a loopback interface on the vdom, return ok if it already exists.

        Parameters
        ----------       
        name: the name of the loopback int (type string)
        ip_mask: the ip and mask (for ex: 1.1.1.1 255.255.255.255 or 1.1.1.1/32)(type string)
        vdom: the existing vdom of the loopback (type string)
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        ip_mask = str(ip_mask)
        vdom = str(vdom)
        allowaccess = str(allowaccess)
        objects =  [['name',name],['ip',ip_mask]] 
        if not (self.Exists('cmdb/system/interface/', objects)):
            #object does not exist, create it
            return self.AddLoopbackInterface(name, ip_mask, vdom, allowaccess)
        else: 
            #object already Exists
            return 200
            
    def SetLoopbackInterface(self, name, ip_mask, vdom, allowaccess=''):
        """
        Modify a loopback interface on the vdom.

        Parameters
        ----------       
        name: the name of the loopback int (type string)
        ip_mask: the ip and mask (for ex: 1.1.1.1 255.255.255.255 or 1.1.1.1/32)(type string)
        vdom: the existing vdom of the loopback (type string)
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        ip_mask = str(ip_mask)
        vdom = str(vdom)
        allowaccess = str(allowaccess)
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
        return self.ApiSet('cmdb/system/interface/' + name + '/', payload)

    def AddVlanInterface(self, name, interface, vlanid, ip_mask, vdom, mode='none', allowaccess=''):
        """
        Create an interface on the vdom.
        You must have access on the root vdom to use this method.

        Parameters
        ----------       
        name: the name of the interface vlan (type string)
        interface: the physical interface which you going to attach the vlan to (type string)
        vlanid: the vlan vlan id (type string)
        ip_mask: the ip and mask (for ex: 1.1.1.1 255.255.255.255 or 1.1.1.1/32)(type string)
        vdom: the existing vdom of the loopback (type string)
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)
        mode: security mode: choice none or 
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)(default none)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        interface = str(interface)
        vlanid = str(vlanid)
        ip_mask = str(ip_mask)
        vdom = str(vdom)
        mode = str(mode)
        allowaccess = str(allowaccess)
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
        #return self.ApiAdd('cmdb/system/interface/', payload)
        url = 'cmdb/system/interface/'
        #adding an interface can only be made from the root vdom
        req = self.s.post(self.api_url + url, params={'vdom':'root'}, data=repr(payload))
        #print 'ApiAdd text:', req.text
        return req.status_code

    def AddVlanInterfaceIdempotent(self, name, interface, vlanid, ip_mask, vdom, mode, allowaccess):
        """
        Create an interface on the vdom, return ok if the vdom already exist.
        You must have access on the root vdom to use this method.

        Parameters
        ----------       
        name: the name of the interface vlan (type string)
        interface: the physical interface which you going to attach the vlan to (type string)
        vlanid: the vlan vlan id (type string)
        ip_mask: the ip and mask (for ex: 1.1.1.1 255.255.255.255 or 1.1.1.1/32)(type string)
        vdom: the existing vdom of the loopback (type string)
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)
        mode: security mode: choice none or 
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)(default none)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        interface = str(interface)
        vlanid = str(vlanid)
        ip_mask = str(ip_mask)
        vdom = str(vdom)
        mode = str(mode)
        allowaccess = str(allowaccess)
        objects =  [['name',name],['interface',interface],['vlanid', int(vlanid)],['ip',ip_mask]] 
        if not (self.Exists('cmdb/system/interface/', objects)):
            #object does not exist, create it
            return self.AddVlanInterface(name, interface, vlanid, ip_mask, vdom, mode, allowaccess)
        else: 
            #object already Exist
            return 200

    def SetVlanInterface(self, name, interface, vlanid, ip_mask, vdom, mode='none', allowaccess=''):
        """
        Modify an interface on the vdom.

        Parameters
        ----------       
        name: the name of the interface vlan (type string)
        interface: the physical interface which you going to attach the vlan to (type string)
        vlanid: the vlan vlan id (type string)
        ip_mask: the ip and mask (for ex: 1.1.1.1 255.255.255.255 or 1.1.1.1/32)(type string)
        vdom: the existing vdom of the loopback (type string)
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)
        mode: security mode: choice none or 
        allowaccess: choice in: ping/http/https/ssh/snmp separated with space (for ex: 'ping ssh http')(type string)(default none)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        interface = str(interface)
        vlanid = str(vlanid)
        ip_mask = str(ip_mask)
        vdom = str(vdom)
        mode = str(mode)
        allowaccess = str(allowaccess)
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
        return self.ApiSet('cmdb/system/interface/' + name + '/', data=payload)


    
    def DelInterface(self, name):
        """
        Delete fw interface object referenced by name.

        Parameters
        ----------        
        name: object to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                {
                'name': 'interface'
                }     
            }
        return self.ApiDelete('cmdb/system/interface/' + name + '/', data=payload)

    def DelAllInterface(self):
        """
        Delete all fw interface object of the vdom.

        Parameters
        ----------        

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        req = self.ApiGet('cmdb/system/interface/')
        data = json.loads(req.text)
        final_return_code = 200
        for y in range(0,len(data['results'])):
            if self.vdom == data['results'][y]['vdom']:
                int_name = data['results'][y]['name']
                return_code = self.DelInterface(int_name)
                print 'del interface:', int_name, '(', return_code,')'
                if return_code != 200 and int_name.find('ssl.') == -1:
                        final_return_code = return_code
        return final_return_code
    #
    def GetFwAddress(self, name=''):
        '''
        Return the json fw address object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------        
        name: the fw address object name (type string)
        
        Returns
        -------
        Return the json object
        '''
        req = self.ApiGet('cmdb/firewall/address/' + name)
        return req.text

    def AddFwAddress(self, name, subnet, associated_interface='', comment=''):
        """
        Create address  on the firewall.

        Parameters
        ----------  
        name: the fw address object name (type string)
        subnet: the ip address and masq, (for ex: '1.1.1.1 255.255.255.255' or '1.1.1.1/32') (type string)
        associated_interface: interface of the object, leave blank for 'Any' (default: Any) (type string)
        comment: (default none) (type string)
            
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        subnet = str(subnet)
        associated_interface = str(associated_interface)
        payload = {'json':
                    {
                    'name': name,
                    'type': 'ipmask',
                    'subnet': subnet, 
                    'associated-interface': associated_interface,
                    'comment': comment
                    }     
                }
        return self.ApiAdd('cmdb/firewall/address/', payload)

    def AddFwAddressRange(self, name, start_ip, end_ip, associated_interface='', comment=''):
        """
        Create address range on the firewall.

        Parameters
        ----------  
        name: the fw address object name (type string)
        start_ip: the first ip address of the range (type string)
        end_ip: the last ip address of the range (type string)
        associated_interface: interface of the object, leave blank for 'Any' (default: Any) (type string)
        comment: (default none) (type string)
            
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        start_ip = str(start_ip)
        end_ip = str(end_ip)
        associated_interface = str(associated_interface)
        payload = {'json':
                    {
                    'name':  name ,
                    'type': 'iprange',
                    'start-ip': start_ip, 
                    'end-ip': end_ip, 
                    'associated-interface': associated_interface,
                    'comment': comment
                    }     
                }
        return self.ApiAdd('cmdb/firewall/address/', payload)


    def AddFwAddressIdempotent(self, name, subnet, associated_interface='', comment=''):
        """
        Create address object on the firewall, if the object already exist return ok.

        Parameters
        ----------  
        name: the fw address object name (type string)
        subnet: the ip address and masq, (for ex: '1.1.1.1 255.255.255.255' or '1.1.1.1/32') (type string)
        associated_interface: interface of the object, leave blank for 'Any' (default: Any) (type string)
        comment: (default none) (type string)
                
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        subnet = str(subnet)
        associated_interface = str(associated_interface)
        
        return_code = self.AddFwAddress(name, subnet, associated_interface, comment)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects =  [['name',name],['subnet',subnet]]
            if self.Exists('cmdb/firewall/address/', objects):
                return_code = 200
        return return_code
        
    

    def SetFwAddress(self, name, subnet, associated_interface='', comment=''):
        """
        Modify address object on the firewall.

        Parameters
        ---------- 
        name: the fw address object name (type string)
        subnet: the ip address and masq, (for ex: '1.1.1.1 255.255.255.255' or '1.1.1.1/32') (type string)
        associated_interface: interface of the object, leave blank for 'Any' (default: Any) (type string)
        comment: (default none) (type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        subnet = str(subnet)
        associated_interface = str(associated_interface)
        payload = {'json':
                    {
                    'name':  name ,
                    'associated-interface': associated_interface,
                    'comment': comment,
                    'subnet':  subnet 
                    }     
                }
        return self.ApiSet('cmdb/firewall/address/' + name + '/', payload)    
    
    def DelFwAddress(self, name):
        """
        Delete fw address  object referenced by name.

        Parameters
        ----------        
        name : the fw address name (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """  
        payload = {'json':
                    {
                    'name': name
                    }
                }
        return self.ApiDelete('cmdb/firewall/address/', data=payload)

    def DelAllFwAddress(self):
        """
        Delete all the fw address on the vdom.

        Parameters
        ----------        

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        req = self.ApiGet('cmdb/firewall/address/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            address_name = data['results'][y]['name']
            return_code = self.DelFwAddress(address_name)
            print 'del fw address :', address_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwAddressGroup(self, name=''):
        '''
        Return the json address group object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------        
        name: the address group object name (type string)
        
        Returns
        -------
        Return the json object
        '''
        req = self.ApiGet('cmdb/firewall/addrgrp/' + name)
        return req.text

    def AddFwAddressGroup(self, name, member_list):
        """
        Create address group on the firewall.

        Parameters
        ----------   
        name : the group name (type string)
        member_list : the list of existing objects to add to the group (type [])
                
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """   
        name = str(name)
        member = []
        for member_elem in member_list:
            member.append({'name': member_elem})
        payload = {'json':
                    {
                    'name':  name,
                    'member': member
                    }     
                }
        return self.ApiAdd('cmdb/firewall/addrgrp/', payload)

    def AddFwAddressGroupIdempotent(self, name, member_list):
        """
        Create address group on the firewall, if the object already exist return ok.

        Parameters
        ----------  
        name : the group name (type string)
        member_list : the list of existing objects to add to the group (type [])
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
   
        return_code = self.AddFwAddressGroup(name, member_list)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects =  [['name',name]]
            if self.Exists('cmdb/firewall/addrgrp/', objects):
                return_code = 200
        return return_code


    def SetFwAddressGroup(self, name, member_list):
        """
        Modify the members of the address group on the firewall.

        Parameters
        ----------   
        name : the group name (type string)
        member_list : the modified list of objects for the group (type [])
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        member = []
        for member_elem in member_list:
            member.append({'name': member_elem})
        payload = {'json':
                    {
                    'member': member
                    }     
                }
        return self.ApiSet('cmdb/firewall/addrgrp/' + name + '/', payload)

    def DelFwAddressGroup(self, name):
        """
        Delete address group object referenced by name.

        Parameters
        ----------        
        name : the group name (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """  
        payload = {'json':
                    {
                    'name': name
                    }     
                }
        return self.ApiDelete('cmdb/firewall/addrgrp/', payload)
    
    def DelAllFwAddressGroup(self):
        """
        Delete all the address group on the vdom.

        Parameters
        ----------        

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """  
        req = self.ApiGet('cmdb/firewall/addrgrp/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            group_name = data['results'][y]['name']
            return_code = self.DelFwAddressGroup(group_name)
            print 'del fw address group:', group_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetRouterStaticID(self, id=''):
        """
        Return the json route static object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------
        id: the static route id (type string)
        
        Returns
        -------
        Return the json object
        """
        id = str(id)
        req = self.ApiGet('cmdb/router/static/' + id)
        return req.text

    def AddRouterStatic(self, dst, device, gateway, comment=''):
        """
        Create a static route on the firewall.

        Parameters
        ----------   
        dst: the destination, example '1.1.1.1 255.255.255.0' (type string)
        device: (type string)
        gateway: (type string)
        comment: (type string)(default none)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """   
        dst = str(dst)
        device = str(device)
        gateway = str(gateway)
        payload = {'json':
                    {
                    'dst':  dst,
                    'device': device,
                    'gateway': gateway,
                    'comment': comment
                    }     
                }
        return self.ApiAdd('cmdb/router/static/', payload)

    def AddRouterStaticIdempotent(self, dst, device, gateway, comment=''):
        """
        Create a static route on the firewall, return ok if it already exists.

        Parameters
        ----------   
        dst: the destination, example '1.1.1.1 255.255.255.0' (type string)
        device: (type string)
        gateway: (type string)
        comment: (type string)(default none)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        dst = str(dst)
        device = str(device)
        gateway = str(gateway)

        return_code = self.AddRouterStatic(dst, device, gateway, comment)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects =  [['dst',dst],['device',device],['gateway',gateway]]
            if self.Exists('cmdb/router/static/', objects):
                return_code = 200
        return return_code
    
    def SetRouterStatic(self, id, dst, device, gateway, comment=''):
        """
        Modify a static route (referenced by his id) on the firewall.

        Parameters
        ----------   
        id: the reference of the static route (type string)
        dst: the destination, example '1.1.1.1 255.255.255.0' (type string)
        device: (type string)
        gateway: (type string)
        comment: (type string)(default none)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        dst = str(dst)
        device = str(device)
        gateway = str(gateway)
        payload = {'json':
                    {
                    'dst':  dst,
                    'device': device,
                    'gateway': gateway,
                    'comment': comment
                    }     
                }
        return self.ApiSet('cmdb/router/static/' + str(id) + '/', payload)

    def DelRouterStaticID(self, id):
        """
        Delete the route selected with his id.

        Parameters
        ----------       
        id: the route id to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """  
        payload = {'json':
                {
                'name': 'static'
                }     
            }
        return self.ApiDelete('cmdb/router/static/' + str(id) + '/', data=payload)
    


    def DelRouterStatic(self, dst):
        """
        Delete the route selected with his destination parameter.

        Parameters
        ----------       
        dst: the destination route to delete ( example '1.1.1.1 255.255.255.0')(type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        req = self.ApiGet('cmdb/router/static/')
        data = json.loads(req.text)
        # search for router static ID with specific dst
        for x in range(0,len(data['results'])):
            if (dst == data['results'][x]['dst']):
                # ID is found : delete it
                return self.DelRouterStaticID(data['results'][x]['seq-num'])	
        return 404

    def DelAllRouterStatic(self):
        """
        Delete all the route of the vdom.

        Parameters
        ----------       

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        req = self.ApiGet('cmdb/router/static/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            route_id = data['results'][y]['seq-num']
            return_code = self.DelRouterStaticID(route_id)
            print 'del route id:', route_id , '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwPolicyID(self, id=''):
        """
        Return the json fw policy object, when the param id is defined it returns the selected object, without id: return all the objects
                
        Parameters
        ----------
        id: the object id or nothing (type string)
 
        Returns
        -------
        Return the json fw policy object
        """
        req = self.ApiGet('cmdb/firewall/policy/' + id)
        return req.text

    def GetFwPolicyStats(self):
        """
	Return json object with traffic statistics for all policies. 
	
	Returns
	-------
	Return the json fw policy statistics
	"""
	req = self.ApiGet('monitor/firewall/policy')
	return req.text

    def AddFwPolicy(self, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL', action='accept', schedule='always', nat='disable', poolname='[]', ippool='disable', status='enable', comments='', traffic_shaper='', traffic_shaper_reverse=''):
        """
        Create a fw policy.

        Parameters
        ----------
        #srcintf: source interface (type string)(default any)
        #dstintf: destination interface (type string)(default any)
        #srcaddr: source address (type string)(default any)
        #dstaddr: destination address (type string)(default any)
        #service: service (type string)(default ALL)
        #action: action, type choice string: accept or deny or drop (type string)(default accept)
        #schedule: schedule (type string)(default always)
        #nat: nat, type choice string: enable or disable (type string)(default disable)
        #poolname: if you enabled nat, the poolname (type string)(default [])
        #ippool: if you enabled nat, the ippool (type string)(default disable)
        #status: the status of the policy, type choice string: enable or disable (default enable)
        #comment: (type string)
        #traffic_shaper: traffic shaper object name (type string)
        #traffic_shaper_reverse: traffic shaper object name (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        srcintf= str(srcintf)
        dstintf= str(dstintf)
        srcaddr= str(srcaddr)
        dstaddr= str(dstaddr)
        service= str(service)
        action= str(action)

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
                    'traffic-shaper': traffic_shaper,
                    'traffic-shaper-reverse': traffic_shaper_reverse,
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
        return self.ApiAdd('cmdb/firewall/policy/', payload)

    def AddFwPolicyIdempotent(self, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL', action='accept', schedule='always', nat='disable', poolname='[]', ippool='disable', status='enable', comments='', traffic_shaper='', traffic_shaper_reverse=''):
        """
        Create a fw policy, return 200 if the policy already exists.

        Parameters
        ----------
        #srcintf: source interface (type string)(default any)
        #dstintf: destination interface (type string)(default any)
        #srcaddr: source address (type string)(default any)
        #dstaddr: destination address (type string)(default any)
        #service: service (type string)(default ALL)
        #action: action, type choice string: accept or deny or drop (type string)(default accept)
        #schedule: schedule (type string)(default always)
        #nat: nat, type choice string: enable or disable (type string)(default disable)
        #poolname: if you enabled nat, the poolname (type string)(default [])
        #ippool: if you enabled nat, the ippool (type string)(default disable)
        #status: the status of the policy, type choice string: enable or disable (default enable)
        #comment: (type string)
        #traffic_shaper: traffic shaper object name (type string)
        #traffic_shaper_reverse: traffic shaper object name (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        srcintf= str(srcintf)
        dstintf= str(dstintf)
        srcaddr= str(srcaddr)
        dstaddr= str(dstaddr)
        service= str(service)
        action= str(action)
        objects =  [['srcintf',srcintf],['dstintf',dstintf],['srcaddr',srcaddr],['dstaddr',dstaddr],['service',service],['action',action],['schedule',schedule],['nat',nat],['poolname',poolname],['ippool',ippool],['status',status],['traffic-shaper',traffic_shaper],['traffic-shaper-reverse',traffic_shaper_reverse]] 
        if not (self.Exists('cmdb/firewall/policy/', objects)):
            #object does not exist, create it
            #print 'AddFwPolicyIdempotent: object does not exists'
            return self.AddFwPolicy(srcintf, dstintf, srcaddr, dstaddr, service, action, schedule, nat, poolname, ippool, status, comments, traffic_shaper, traffic_shaper_reverse)
        else: 
            #object already Exists
            #print 'AddFwPolicyIdempotent: object already exists'
            return 200

    def SetFwPolicy(self, id, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL', action='accept', schedule='always', nat='disable', poolname='[]', ippool='disable', status='enable', comments='', traffic_shaper='', traffic_shaper_reverse=''):
        """
        Modify a fw policy.

        Parameters
        ----------
        #id: the policy id to modify (type string)
        #srcintf: source interface (type string)(default any)
        #dstintf: destination interface (type string)(default any)
        #srcaddr: source address (type string)(default any)
        #dstaddr: destination address (type string)(default any)
        #service: service (type string)(default ALL)
        #action: action, type choice string: accept or deny or drop (type string)(default accept)
        #schedule: schedule (type string)(default always)
        #nat: nat, type choice string: enable or disable (type string)(default disable)
        #poolname: if you enabled nat, the poolname (type string)(default [])
        #ippool: if you enabled nat, the ippool (type string)(default disable)
        #status: the status of the policy, type choice string: enable or disable (default enable)
        #comment: (type string)
        #traffic_shaper: traffic shaper object name (type string)
        #traffic_shaper_reverse: traffic shaper object name (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        id = str(id)
        srcintf= str(srcintf)
        dstintf= str(dstintf)
        srcaddr= str(srcaddr)
        dstaddr= str(dstaddr)
        service= str(service)
        action= str(action)

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
                    'traffic-shaper': traffic_shaper,
                    'traffic-shaper-reverse': traffic_shaper_reverse,
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
        return self.ApiSet('cmdb/firewall/policy/'+ id +'/', payload)



    


    def DelFwPolicy(self, srcintf='any', dstintf='any', srcaddr='all', dstaddr='all', service='ALL'):
        """
        Delete the policy which is defined by the params.

        Parameters
        ----------
        srcintf: source interface (type string)(default any)
        dstintf: destination interface (type string)(default any)
        srcaddr: source address (type string)(default any)
        dstaddr: destination address (type string)(default any)
        service: service (type string)(default ALL)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        fw_id = self.SearchFwPolicyID(srcintf, dstintf, srcaddr, dstaddr, service)
        if fw_id != 0:
            return self.DelFwPolicyID(fw_id)
        else:    
            return 404
       
    def DelFwPolicyID(self, id):
        """
        Delete the policy which is referenced by his ID.

        Parameters
        ----------
        id: the id of the policy to delete (type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                {
                'name': 'policy'
                }     
            }
        return self.ApiDelete('cmdb/firewall/policy/' + str(id) + '/', data=payload) 
    
    def DelAllFwPolicy(self):
        """
        Delete all the policy of the vdom.

        Parameters
        ----------
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        req = self.ApiGet('cmdb/firewall/policy/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            policy_id = data['results'][y]['policyid']
            return_code = self.DelFwPolicyID(policy_id)
            print 'del fw policy id:', policy_id ,  '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    
    def SearchFwPolicyID(self, srcintf='', dstintf='', srcaddr='', dstaddr='', service='', action='', schedule='', nat='', poolname='[]', ippool='', status='', comments='', traffic_shaper='', traffic_shaper_reverse=''):
        """
        Search a policy id from his parameters and return his ID.
        
        Parameters
        ----------
        srcintf: source interface (type string)(default any)
        dstintf: destination interface (type string)(default any)
        srcaddr: source address (type string)(default any)
        dstaddr: destination address (type string)(default any)
        service: service (type string)(default ALL)
        #action: action, type choice string: accept or deny or drop (type string)(default accept)
        #schedule: schedule (type string)(default always)
        #nat: nat, type choice string: enable or disable (type string)(default disable)
        #poolname: if you enabled nat, the poolname (type string)(default [])
        #ippool: if you enabled nat, the ippool (type string)(default disable)
        #status: the status of the policy, type choice string: enable or disable (default enable)
        #comment: (type string)
        #traffic_shaper: traffic shaper object name (type string)
        #traffic_shaper_reverse: traffic shaper object name (type string)

        Returns
        -------
        the id of the policy or 0 if the policy was not found
        """
        objects = []
        if srcintf != '': 
            objects.append(['srcintf',srcintf])
        if dstintf != '':
            objects.append(['dstintf',dstintf])
        if srcaddr != '': 
            objects.append(['srcaddr',srcaddr])
        if dstaddr != '':
            objects.append(['dstaddr',dstaddr])
        if service != '': 
            objects.append(['service',service])
        if action != '':
            objects.append(['action',action])
        if schedule != '':
            objects.append(['schedule',schedule])   
        if nat != '':
            objects.append(['nat',nat]) 
        if poolname != '[]':
            objects.append(['poolname',poolname])
        if ippool != '':
            objects.append(['ippool',ippool])
        if status != '':
            objects.append(['status',status])
        if comments != '':
            objects.append(['comments',comments])
        if traffic_shaper != '':
            objects.append(['traffic-shaper',traffic_shaper])
        if traffic_shaper_reverse != '':
            objects.append(['traffic-shaper-reverse',traffic_shaper_reverse])
        
        print objects

        #get all fw policy
        req = self.ApiGet('cmdb/firewall/policy/')
        data = json.loads(req.text)
        #parse policy one by one
        for y in range(0,len(data['results'])):
            identical = True 
            #compare every parameters objects which is not null
            for x in range(0,len(objects)):
                req_res = data['results'][y][objects[x][0]]
                if (type(req_res) is list):
                    if ((req_res != []) and (objects[x][1] != req_res[0]['name'])):
                        #print 'object list is different:',objects[x][0], objects[x][1] ,'to',req_res[0]['name']
                        identical = False
                        break
                elif (objects[x][1] != req_res):
                    print 'object is different:', objects[x][0], ':', objects[x][1] ,'to', req_res
                    identical = False
                    break
            if identical: 
                #print 'policyid:', data['results'][y]['policyid']
                return data['results'][y]['policyid']
        return 0
    #
    def GetFwService(self, name=''):
        '''
        Return the json fw service object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------        
        name: the fw service object name (type string)
        
        Returns
        -------
        Return the json object
        '''
        req = self.ApiGet('cmdb/firewall.service/custom/' + name)
        return req.text

    def AddFwService(self,name, tcp_portrange='', udp_portrange='', protocol='TCP/UDP/SCTP', fqdn='', iprange='0.0.0.0',  comment=''):
        '''
        Add a fw service object.

        Parameters
        ----------
        tcp_portrange: (type string)
        udp_portrange: (type string)
        protocol: (type string)
        fqdn: (type string)
        iprange: (type string)
        comment: (type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        '''
        name = str(name)
        tcp_portrange = str(tcp_portrange)
        udp_portrange = str(udp_portrange)
        protocol = str(protocol)
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
        return self.ApiAdd('cmdb/firewall.service/custom/', payload)
    
    def AddFwServiceIdempotent(self,name, tcp_portrange='', udp_portrange='', protocol='TCP/UDP/SCTP', fqdn='', iprange='0.0.0.0',  comment=''):
        '''
        Add a fw service object, return ok if the object already exists.

        Parameters
        ----------
        tcp_portrange: (type string)
        udp_portrange: (type string)
        protocol: (type string)
        fqdn: (type string)
        iprange: (type string)
        comment: (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        '''
        name = str(name)
        tcp_portrange = str(tcp_portrange)
        udp_portrange = str(udp_portrange)
        protocol = str(protocol)
    
        return_code = self.AddFwService(name, tcp_portrange, udp_portrange, protocol, fqdn, iprange, comment)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects = [['name',name],['tcp-portrange',tcp_portrange],['udp-portrange',udp_portrange],['protocol',protocol],['fqdn',fqdn],['iprange',iprange]]
            if self.Exists('cmdb/firewall.service/custom/', objects):
                return_code = 200
        return return_code


    def SetFwService(self,name, tcp_portrange='', udp_portrange='', protocol='TCP/UDP/SCTP', fqdn='', iprange='0.0.0.0',  comment=''):
        '''
        Modify a fw service object referenced by hist name.

        Parameters
        ----------
        tcp_portrange: (type string)
        udp_portrange: (type string)
        protocol: (type string)
        fqdn: (type string)
        iprange: (type string)
        comment: (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        '''
        name = str(name)
        tcp_portrange = str(tcp_portrange)
        udp_portrange = str(udp_portrange)
        protocol = str(protocol)
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
        return self.ApiSet('cmdb/firewall.service/custom/' + name + '/', payload)

    def DelFwService(self, name):
        """
        Delete fw service object referenced by name.

        Parameters
        ----------        
        name: object to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """        
        payload = {'json':
                {
                'name': name
                }     
            }
        return self.ApiDelete('cmdb/firewall.service/custom/', payload)
    
    def DelAllFwService(self):
        """
        Delete all the fw service of the vdom.
        
        Parameters
        ----------
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """        
        req = self.ApiGet('cmdb/firewall.service/custom/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            service_name = data['results'][y]['name']
            return_code = self.DelFwService(service_name)
            print 'del fw service :', service_name, '(', return_code,')'
            #if return_code != 200: return return_code
        return 200
    #
    def GetFwServiceGroup(self, name=''):
        """
        Return the json fw service group object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------
        name: the group name (type string)
        
        Returns
        -------
        Return the json object
        """
        req = self.ApiGet('cmdb/firewall.service/group/' + name)
        return req.text
    
    def AddFwServiceGroup(self, name, member_list):
        """
        Create fw service group on the firewall.
        
        Parameters
        ----------
        name : the group name (type string)
        member_list : the list of existing objects to add to the group (type [])
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """       
        name = str(name)
        member = []
        for member_elem in member_list:
            member.append({'name': member_elem})
        payload = {'json':
                    {
                    'name':  name,
                    'member': member
                    }     
                }
        return self.ApiAdd('cmdb/firewall.service/group/', payload)

    def AddFwServiceGroupIdempotent(self, name, member_list):
        """
        Create fw service group on the firewall, return ok if the group already exists.

        Parameters
        ----------        
        name : the group name (type string)
        member_list : the list of existing objects to add to the group (type [])      
        
        Returns
        -------        
        Http status code: 200 if ok, 4xx if an error occurs
        """
        name = str(name)
        
        return_code = self.AddFwServiceGroup(name, member_list)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects =  [['name',name]]
            if self.Exists('cmdb/firewall.service/group/', objects):
                return_code = 200
        return return_code

    
    def SetFwServiceGroup(self, name, member_list):
        """
        Modify fw service group on the firewall.

        Parameters
        ----------        
        name : the group name (type string)
        member_list : the list of existing objects to add to the group (type [])
        
        Returns
        -------    
        Http status code: 200 if ok, 4xx if an error occurs    
        """
        name = str(name)
        member = []
        for member_elem in member_list:
            member.append({'name': member_elem})
        payload = {'json':
                    {
                    'member': member
                    }     
                }
        return self.ApiSet('cmdb/firewall.service/group/'+ name + '/', payload)

    def DelFwServiceGroup(self, name):
        """
        Delete fw service group referenced by name.

        Parameters
        ----------
        name: the group name (type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                    {
                    'name': name
                    }     
                }
        return self.ApiDelete('cmdb/firewall.service/group/', payload)    
    
    def DelAllFwServiceGroup(self):
        """
        Delete all fw service group of the vdom.
        
        Parameters
        ----------
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        req = self.ApiGet('cmdb/firewall.service/group/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            service_group_name = data['results'][y]['name']
            return_code = self.DelFwServiceGroup(service_group_name)
            print 'del fw service group:', service_group_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetTrafficShaper(self, name=''):
        """
        Return the json shared traffic shaper object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------
        name: the traffic shaper name (type string)
        
        Returns
        -------
        Return the json object
        """
        req = self.ApiGet('cmdb/firewall.shaper/traffic-shaper/' + name)
        return req.text
    
    def AddTrafficShaper(self, name, per_policy, priority, guaranteed_bandwidth, maximum_bandwidth, diffserv='disable', diffservcode='000000'):
        """
        Add a shared traffic shaper on the vdom.

        Parameters
        ----------
        name: the name of the shaper (type string)
        per_policy : shaper applied per policy or 'all policy using this shaper', choice: enable/disable
        priority: choice: high/medium/low
        guaranteed_bandwidth: in Kb/s (type int)
        maximum_bandwidth: in Kb/s (type int)
        diffserv: choice: enable/disable (default disable)
        diffservcode: (type string) (default '000000')

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
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
        return self.ApiAdd('cmdb/firewall.shaper/traffic-shaper/', payload)
    
    def AddTrafficShaperIdempotent(self, name, per_policy, priority, guaranteed_bandwidth, maximum_bandwidth, diffserv='disable', diffservcode='000000'):
        """
        Add a shared traffic shaper on the vdom, return ok if it already exists.

        Parameters
        ----------
        name: the name of the shaper (type string)
        per_policy : shaper applied per policy, choice: enable/disable
        priority: choice: high/medium/low
        guaranteed_bandwidth: in Kb (type int)
        maximum_bandwidth: in Kb (type int)
        diffserv: choice: enable/disable (default disable)
        diffservcode: (type string) (default '000000')

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        return_code = self.AddTrafficShaper(name, per_policy, priority, guaranteed_bandwidth, maximum_bandwidth, diffserv, diffservcode)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects =  [['name',name]]
            if self.Exists('cmdb/firewall.shaper/traffic-shaper/', objects):
                return_code = 200
        return return_code

    def SetTrafficShaper(self, name, per_policy, priority, guaranteed_bandwidth, maximum_bandwidth, diffserv='disable', diffservcode='000000'):
        """
        Modify a shared traffic shaper on the vdom.

        Parameters
        ----------
        name: the name of the shaper (type string)
        per_policy : shaper applied per policy or 'all policy using this shaper', choice: enable/disable
        priority: choice: high/medium/low
        guaranteed_bandwidth: in Kb/s (type string)
        maximum_bandwidth: in Kb/s (type string)
        diffserv: choice: enable/disable (default disable)
        diffservcode: (type string) (default '000000')

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
            {
            'name': name,
            'per-policy': per_policy,
            'priority': priority,
            'guaranteed-bandwidth':  int(guaranteed_bandwidth),
            'maximum_bandwidth': int(maximum_bandwidth),
            'diffserv': diffserv, 
            'diffservcode': diffservcode
            }     
        }
        return self.ApiSet('cmdb/firewall.shaper/traffic-shaper/'+ name +'/', payload)

    def DelTrafficShaper(self, name=''):
        """
        Delete the shared traffic shaper defined by his name.

        Parameters
        ----------
        name: the shaper to delete (type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                    {
                    'name': name
                    }     
                }
        return self.ApiDelete('cmdb/firewall.shaper/traffic-shaper/', payload)     
    
    def DelAllTrafficShaper(self):
        """
        Delete all the shared traffic shaper of the vdom.

        Parameters
        ----------
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        req = self.ApiGet('cmdb/firewall.shaper/traffic-shaper/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            traffic_shaper_name = data['results'][y]['name']
            return_code = self.DelTrafficShaper(traffic_shaper_name)
            print 'del traffic shaper:', traffic_shaper_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwVIP(self, name=''):
        """
        Return the json vip object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------
        name: the vip name (type string)
        
        Returns
        -------
        Return the json object
        """
        req = self.ApiGet('cmdb/firewall/vip/' + name)
        return req.text

    def AddFwVIP(self, name, extip, extintf, mappedip, portforward='disable', protocol='', extport='0-65535', mappedport='0-65535', comment=''):
        """
        Create vip address.

        Parameters
        ----------
        name: the vip name (type string)
        extip: the external ip (type string)
        extintf: the external interface (type string)
        mappedip: the internal ip (type string)
        portforward: enable portforwarding ? (type choice string: enable or disable)
        protocol: if you enable portforwarding, set the protocol (type string choice in tcp or udp or stcp or icmp)
        extport: if you enable portforwarding, set the external ports (type string numerical range, ex: 20-21)
        mappedport: if you enable portforwarding, set the mapped ports (type string numerical range, ex: 20-21)
        comment: (type string)
        
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """   
        name = str(name)
        extip = str(extip)
        extinff = str(extintf)
        mappedip = str(mappedip)
        mappedip = [{'range': mappedip}]
        payload = {'json':
            {
            'name': name,
            'extip': extip,
            'extintf': extintf,
            'mappedip':  mappedip,
            'portforward': portforward,
            'protocol': protocol,
            'extport': extport,
            'mappedport': mappedport,
            'comment': comment
            }     
        }
        return self.ApiAdd('cmdb/firewall/vip/', payload)
    
    def AddFwVIPidempotent(self, name, extip, extintf, mappedip, portforward='disable', extport='0-65535', mappedport='0-65535', comment=''):
        """
        Create vip address, return ok if it already exists.

        Parameters
        ----------
        name: the vip name (type string)
        extip: the external ip (type string)
        extintf: the external interface (type string)
        mappedip: the internal ip (type string)
        portforward: enable portforwarding ? (type choice string: enable or disable)
        protocol: if you enable portforwarding, set the protocol (type string choice in tcp or udp or stcp or icmp)
        extport: if you enable portforwarding, set the external ports (type string numerical range, ex: 20-21)
        mappedport: if you enable portforwarding, set the mapped ports (type string numerical range, ex: 20-21)
        comment: (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        extip = str(extip)
        extinff = str(extintf)
        mappedip = str(mappedip)
    
        return_code = self.AddFwVIP(name, extip, extintf, mappedip, portforward, extport, mappedport, comment)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects =  [['name',name]]
            if self.Exists('cmdb/firewall/vip/', objects):
                return_code = 200
        return return_code

    def SetFwVIP(self, name, extip, extintf, mappedip, portforward='disable', protocol='', extport='0-65535', mappedport='0-65535', comment=''):
        """
        Modify vip address.
        
        Parameters
        ----------        
        name: the vip name (type string)
        extip: the external ip (type string)
        extintf: the external interface (type string)
        mappedip: the internal ip (type string)
        portforward: enable portforwarding ? (type choice string: enable or disable)
        protocol: if you enable portforwarding, set the protocol (type string choice in tcp or udp or stcp or icmp)
        extport: if you enable portforwarding, set the external ports (type string numerical range, ex: 20-21)
        mappedport: if you enable portforwarding, set the mapped ports (type string numerical range, ex: 20-21)
        comment: (type string)
                
        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        extip = str(extip)
        extinff = str(extintf)
        mappedip = str(mappedip)
        mappedip = [{'range': mappedip}]
        payload = {'json':
            {
            'name': name,
            'extip': extip,
            'extintf': extintf,
            'mappedip':  mappedip,
            'portforward': portforward,
            'protocol': protocol,
            'extport': extport,
            'mappedport': mappedport,
            'comment': comment
            }     
        }
        return self.ApiSet('cmdb/firewall/vip/'+ name + '/', payload)
    
    def DelFwVIP(self, name):
        """
        Delete the vip object on the firewall vdom.

        Parameters
        ----------
        name : the fw vip object name (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """          
        payload = {'json':
                    {
                    'name': 'vip'
                    }     
                }
        return self.ApiDelete('cmdb/firewall/vip/' + name + '/', payload)  
    
    def DelAllFwVIP(self):
        """
        Delete all the vip object on the vdom.

        Parameters
        ----------

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """  
        req = self.ApiGet('cmdb/firewall/vip/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            vip_name = data['results'][y]['name']
            return_code = self.DelFwVIP(vip_name)
            print 'del vip:', vip_name, '(', return_code,')'
            if return_code != 200: return return_code
        return 200
    #
    def GetFwIPpool(self, name=''):
        """
        Return the json ip pool object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------
        name: the ip pool name (type string)
        
        Returns
        -------
        Return the json object
        """
        req = self.ApiGet('cmdb/firewall/ippool/' + name)
        return req.text  
    
    def AddFwIPpool(self, name, startip, endip, type_pool='overload', internal_startip='0.0.0.0', internal_endip='0.0.0.0', arp_reply='enable',block_size='128', num_blocks_per_user='8', comment=''):
        """
        Create the ip pool on the firewall.
        
        Parameters
        ----------      
        name: the fw ip pool object name (type string)
        startip: the first ip of the external range (type string)
        endtip: the last ip of the external range (type string)
        type_pool : type choice string: overload or one-to-one or fixed-port-range, default overload     
        internal_startip: if the type is 'fixed-port-range', the first ip of the internal range (type string)
        internal_endip: if the type is 'fixed-port-range', the last ip of the internal range (type string)
        arp_enable: type choice string: enable or disable, default enable
        block_size: if the type is X, set the block size, default is 128 (type string)
        num_blocks_per_user: : if the type is X, set the number of block per user, default is 8 (type string)
        comment: (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """   
        name = str(name)
        startip = str(startip)
        endip = str(endip)
        payload = {'json':
            {
            'name': name,
            'startip': startip,
            'endip': endip,
            'type':  type_pool,
            'source-startip': internal_startip,
            'source-endip': internal_endip,
            'arp-reply': arp_reply,
            'block-size': block_size,
            'num-blocks-per-user': num_blocks_per_user,
            'comments': comment
            }     
        }
        return self.ApiAdd('cmdb/firewall/ippool/', payload)

    def AddFwIPpoolIdempotent(self, name, startip, endip, type_pool='overload', internal_startip='0.0.0.0', internal_endip='0.0.0.0', arp_reply='enable',block_size='128', num_blocks_per_user='8', comment=''):
        """
        Create the ip pool on the firewall, return ok if it already exists.
        
        Parameters
        ----------      
        name: the fw ip pool object name (type string)
        startip: the first ip of the external range (type string)
        endtip: the last ip of the external range (type string)
        type_pool : type choice string: overload or one-to-one or fixed-port-range, default overload     
        internal_startip: if the type is 'fixed-port-range', the first ip of the internal range (type string)
        internal_endip: if the type is 'fixed-port-range', the last ip of the internal range (type string)
        arp_enable: type choice string: enable or disable, default enable
        block_size: if the type is X, set the block size, default is 128 (type string)
        num_blocks_per_user: : if the type is X, set the number of block per user, default is 8 (type string)
        comment: (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        name = str(name)
        startip = str(startip)
        endip = str(endip)
        
        return_code = self.AddFwIPpool(name, startip, endip, type_pool, internal_startip, internal_endip, arp_reply,block_size, num_blocks_per_user, comment)
        if  return_code != 200:
            #creation failed, check to see if the object already exists
            objects =  [['name',name]]
            if self.Exists('cmdb/firewall/ippool/', objects):
                return_code = 200
        return return_code

    def DelFwIPpool(self, name):
        """
        Delete the ip pool referenced by his name.

        Parameters
        ----------        
        name: the name of the object (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """         
        payload = {'json':
                    {
                    'name': 'ippool'
                    }     
                }
        return self.ApiDelete('cmdb/firewall/ippool/' + name + '/', payload)  

    def DelAllFwIPpool(self):
        """
        Delete all the ip pool referenced in the vdom.

        Parameters
        ----------        

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        req = self.ApiGet('cmdb/firewall/ippool/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            ippool_name = data['results'][y]['name']
            return_code = self.DelFwIPpool(ippool_name)
            print 'del ip pool:', ippool_name , 'res:', return_code
            if return_code != 200: return return_code
        return 200 
    #
    
    def GetVPNipsecPhase1(self, name=''):
        """
        Return the json vpn phase1 object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------
        name: the group name (type string)
        
        Returns
        -------
        Return the json object
        """
        req_phase1 = self.ApiGet('cmdb/vpn.ipsec/phase1-interface/' + name)
        return req_phase1.text

    def GetVPNipsecPhase2(self, name=''):
        """
        Return the json vpn phase2 object, when the param name is defined it returns the selected object, without name: return all the objects.

        Parameters
        ----------
        name: the group name (type string)
        
        Returns
        -------
        Return the json object
        """
        req_phase2 = self.ApiGet('cmdb/vpn.ipsec/phase2-interface/' + name)
        return req_phase2.text 

    def AddVPNipsecPhase1(self, name, interface, remote_gw, nattraversal, dpd, psk, ike_version, mode, proposal, dhgrp, keylife=28800, localid=''):
        """
        Create vpn ipsec tunnel phase1.

        Parameters
        ----------        
        name: name of the phase1 (type string)
        interface: (type string)
        remote_gw: (ype string)
        nattraversal: choice: enable/disable (type string)
        dpd: dead peer detection, choice: enable/disable (type string)
        psk: pre shared key (type string)
            be careful: the psk must be at least 6 caracters long
        ike_version: choice: 1/2 (type int)
        mode: choice: main/aggressive
        proposal: choice: aes256-sha1... (type string)
        dhgrp: choice: 1/2/5/14/15... (type string)
        keylife: in sec, (type int)(default 28800)
        localid: (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
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
            'authurl': 'psk',
            'mode': mode, 
            'proposal': proposal,
            'localid': localid,
            'dpd': dpd, 
            'dhgrp': dhgrp, 
            'remote-gw': remote_gw,
            'psksecret': psk
                }     
            }
        return self.ApiAdd('cmdb/vpn.ipsec/phase1-interface/', payload)

    def AddVPNipsecPhase1Idempotent(self, name, interface, remote_gw, nattraversal, dpd, psk, ike_version, mode, proposal, dhgrp, keylife=28800, localid=''):
        """
        Create vpn ipsec tunnel phase1, return ok if it already exist.

        Parameters
        ----------        
        name:  name of the phase1 (type string)
        interface: (type string)
        remote_gw: (ype string)
        nattraversal: choice: enable/disable (type string)
        dpd: dead peer detection, choice: enable/disable (type string)
        psk: pre shared key (type string)
            be careful: the psk must be at least 6 caracters long
        ike_version: choice: 1/2 (type int)
        mode: choice: main/aggressive
        proposal: choice: aes256-sha1... (type string)
        dhgrp: choice: 1/2/5/14/15... (type string)
        keylife: in sec, (type int)(default 28800)
        localid: (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        objects =  [['name',name]]
        if not (self.Exists('cmdb/vpn.ipsec/phase1-interface/', objects)):
            #object does not exist, create it
            return self.AddVPNipsecPhase1(name, interface, remote_gw, nattraversal, dpd, psk, ike_version, mode, proposal, dhgrp, keylife, localid)
        else: 
            #object already Exists
            return 200

    def AddVPNipsecPhase2(self, name, phase1name, local_addr_type, local_subnet, remote_addr_type, remote_subnet, proposal, pfs, dhgrp, replay, keepalive, keylife_type, keylifeseconds):
        """
        Create vpn ipsec tunnel phase2.

        Parameters
        ----------        
        name:  name of the phase2 (type string)
        phase1name: the name of the phase1 that already exist (type string)
        local_addr_type: local address type, choice subnet/IP range/IP address (type string)
        local_subnet: local address (type string)
        remote_addr_type: local address type, choice subnet/IP range/IP address (type string)
        remote_subnet: (type string)
        proposal: choice: aes256-sha1... (type string)
        pfs: choice: enable/disable (type string)
        dhgrp: choice: 1/2/5/14/15... (type string)
        replay: enable/disable (type string)
        keepalive: enable/disable (type string)
        keylife_type: key lifetime, choice: seconds/kilobytes/both (type string)
        keylifeseconds: (type int)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                {
            'name': name,
            'phase1name': phase1name,
            'src-addr-type': local_addr_type,
            'src-subnet': local_subnet,
            'dst-addr-type': remote_addr_type, 
            'dst-subnet': remote_subnet, 
            'proposal': proposal, 
            'pfs': pfs, 
            'dhgrp': dhgrp,
            'replay': replay,
            'keepalive': keepalive,
            'keylife-type': keylife_type,
            'keylifeseconds': int(keylifeseconds)
                }     
            }
        return self.ApiAdd('cmdb/vpn.ipsec/phase2-interface/', payload)

    def AddVPNipsecPhase2Idempotent(self, name, phase1name, local_addr_type, local_subnet, remote_addr_type, remote_subnet, proposal, pfs, dhgrp, replay, keepalive, keylife_type, keylifeseconds):
        """
        Create vpn ipsec tunnel phase2.

        Parameters
        ----------        
        name:  name of the phase2 (type string)
        phase1name: the name of the phase1 that already exist (type string)
        local_addr_type: local address type, choice subnet/IP range/IP address (type string)
        local_subnet: local address (type string)
        remote_addr_type: local address type, choice subnet/IP range/IP address (type string)
        remote_subnet: (type string)
        proposal: choice: aes256-sha1... (type string)
        pfs: choice: enable/disable (type string)
        dhgrp: choice: 1/2/5/14/15... (type string)
        replay: enable/disable (type string)
        keepalive: enable/disable (type string)
        keylife_type: key lifetime, choice: seconds/kilobytes/both (type string)
        keylifeseconds: (type int)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        objects =  [['name',name]]
        if not (self.Exists('cmdb/vpn.ipsec/phase2-interface/', objects)):
            #object does not exist, create it
            return self.AddVPNipsecPhase2(name, phase1name, local_addr_type, local_subnet, remote_addr_type, remote_subnet, proposal, pfs, dhgrp, replay, keepalive, keylife_type, keylifeseconds)
        else: 
            #object already Exists
            return 200
    
    def DelVPNipsec(self, name):
        """
        Delete the phase1 and phase2 configuration of an ipsec vpn
        
        Parameters
        ----------        
        name: object to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
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
        """
        Delete the phase1 configuration of an ipsec vpn
        Must delete the phase2 first.

        Parameters
        ----------        
        name: object to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                    {
                    'name': 'phase1-interface'
                    }     
                }
        return self.ApiDelete('cmdb/vpn.ipsec/phase1-interface/'+ name + '/', payload)  

    def DelVPNipsecPhase2(self, name):
        """
        Delete the phase2 configuration of an ipsec vpn

        Parameters
        ----------        
        name: object to delete (type string)

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """
        payload = {'json':
                    {
                    'name': 'phase2-interface'
                    }     
                }
        return self.ApiDelete('cmdb/vpn.ipsec/phase2-interface/'+ name + '/', payload) 
    
    def DelAllVPNipsec(self):
        """
        Delete all vpn of the vdom.

        Parameters
        ----------        

        Returns
        -------
        Http status code: 200 if ok, 4xx if an error occurs
        """ 
        req = self.ApiGet('cmdb/vpn.ipsec/phase1-interface/')
        data = json.loads(req.text)
        for y in range(0,len(data['results'])):
            vpn_name = data['results'][y]['name']
            return_code = self.DelVPNipsec(vpn_name)
            print 'del vpn:', vpn_name , 'res:', return_code
            if return_code != 200: return return_code
        return 200 
