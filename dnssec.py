import dns.query
import dns.message
import dns.name
import dns.flags
import dns.dnssec
import sys
import time

anchor_key1 = dns.rrset.from_text('.', 1, 'IN', 'DNSKEY', '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=')
anchor_key2 = dns.rrset.from_text('.', 1, 'IN', 'DNSKEY', '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=')
#get speicfic information from response by datatype
def get_info_from_reponse(response,type):
   if (type=='1'): #A
     for rrset in response.answer:
        if rrset.rdtype == 1:
          return rrset
   elif (type=='48'): #DNSkey
     for rrset in response.answer:
         if rrset.rdtype == 48:
             name=rrset.name
             return rrset,name
   elif (type=='2'): #NS
     for rrset in response.answer:
       if rrset.rdtype == 2:
         return rrset
   elif (type=='15'): #mx
     for rrset in response.answer:
      if rrset.rdtype == 15:
         return rrset
   elif (type=='43'): #DS
     for rrset in response.authority:
        if rrset.rdtype == 43:
          return rrset
   elif (type=='46'): #RRsig
     for rrset in response.authority:
         if rrset.rdtype == 46:
           return rrset
           
def make_query_helper (hostname,reqtype):
   if (reqtype != 'A' and  reqtype != 'NS' and reqtype != 'MX'):
     print("Invalid DNS type.")
     exit()
   domain = dns.name.from_text(hostname)
   request = dns.message.make_query(domain, reqtype, want_dnssec=True, payload=2048)
   return request
   
#using key.flag to identify public key for decryption
def get_publicKSK(dnskey):
  for key in dnskey:
    if key.flags == 257:
        return key
        
def quey_helper(request, sever_ip):
    response = dns.query.tcp(request,str(sever_ip),timeout=3)
    return response
    
#verify the DNSKEY part for the current resolve level
def verify_zsk(response, name,dnskey):
    #dnskey,name=get_info_from_reponse(response,'48'):
    try:
        dns.dnssec.validate(dnskey,response.answer[1],{name:dnskey})
    except Exception as e:
         raise e
    else:
        print(name, 'DNSKEYs verify succeed')
        #return
        
#verify the DS part for the next resolve level
def verify_ds(response, name_key, dnskey):
  try:
    rrsig_ds=get_info_from_reponse(response,'46')
    ds=get_info_from_reponse(response,'43')
    name=ds.name
    dns.dnssec.validate(ds, rrsig_ds, {name_key:dnskey})
  except Exception as e:
    raise e
  else:
    print(name, 'DS is verified successfully')

#for dns query of root server
def iniresolve_sec(hostname,reqtype):
    serverlist =["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4","198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]
    
    request = make_query_helper (hostname,reqtype)
    sec_request=dns.message.make_query('.', dns.rdatatype.DNSKEY, want_dnssec=True, payload=2048) #for check dnssec at root
    
    for server in serverlist:
        
          try:
            response = quey_helper(request, server) #hostname DNS query
          except dns.exception.Timeout:
              continue
          except OSError:
              continue
          try:
           #1.check root KSK stored local first
            sec_response = quey_helper(sec_request, server) #root key DNS query
          except dns.exception.Timeout:
              continue
          except OSError:
              continue
          dnskey,name= get_info_from_reponse(sec_response,'48')
          if type(dnskey) == None:
              print("No DNSKEY received.")
              continue
          pubKSK=get_publicKSK(dnskey)
          if (pubKSK.to_text() == anchor_key1[0].to_text() ):
                print("Root KSK verification succeed.")
          elif (pubKSK.to_text() == anchor_key2[0].to_text()):
                print("Root KSK verification succeed.")
          else:
                print("Root KSK verification failed.")
                continue
                
          #2. check root's ZSK:
    
          verify_zsk(sec_response, name, dnskey)
          #3. check root's ZSK:
   
          if(verify_ds(response, name, dnskey)==1):
             continue
          #4. get the info for next round of query
          
          cur_ds=response.authority[1]
          cur_rrsg=response.authority[2]
          for elem in response.authority:
                rrset_type = dns.rdatatype.to_text(elem.rdtype)
                next_domain = elem.name
          next_sever_ip=response.additional[0][0]
          return foresolve_sec(hostname, reqtype, next_sever_ip, next_domain, cur_ds)
          
    
#for dnssec qury of non-root server
def foresolve_sec(hostname,reqtype,sever_ip,next_domain, previous_ds):
       #send the dnssec query to the server
       sec_request=dns.message.make_query(str(next_domain), dns.rdatatype.DNSKEY, want_dnssec=True, payload=2048)
       sec_response=quey_helper(sec_request, str(sever_ip))
        
       dnskey,name = get_info_from_reponse(sec_response,'48')
       ds_hash_algo = previous_ds[0].digest_type
       publicKSK=get_publicKSK(dnskey)
       tempDS = dns.dnssec.make_ds(next_domain, publicKSK, 'SHA1' if ds_hash_algo==1 else 'SHA256')
       
       if(tempDS == previous_ds[0]):
             print('Zone validation succeed.')
       else:
             print('Zone validation failed.')
             return
       
       verify_zsk(sec_response, name, dnskey)
       
       request = make_query_helper (hostname,reqtype)
    #try:
       response = quey_helper(request, sever_ip)
       
       if len(response.answer) == 0 and len(response.additional) == 0:
          print('DNSSec verification failed.')
          exit()
          
       if (len(response.answer)!=0):
          for elem in response.answer:
            if (elem.rdtype ==5): # CNAME is returned not reuired IP address
              answer = str(response.answer[0])
              data = answer.split(' ')
              return iniresolve(data[-1],'A')
            else: #ip returned
              return response
                  
       if (len(response.additional)!=0):
            for elem in response.additional:
                if (elem.rdtype ==1):
                  new_server= elem[0]
                  break;
            #get the ds and rrsig and validate
            for elem in response.authority:
                rrset_type = dns.rdatatype.to_text(elem.rdtype)
                next_domain = elem.name
                break
            cur_ds=get_info_from_reponse(response,'43')
            if cur_ds is None:
              print('DNSSEC not supported')
              exit()
            verify_ds(response, name, dnskey)
            new_server=response.additional[0][0]
            
            return foresolve_sec(hostname,reqtype,new_server,next_domain, cur_ds)
               
       else:
             ans = str(response.authority[0])
             data = ans.split(' ')
             autho_res=iniresolve_sec(str(data[-1]), 'A')
             autho_an=get_info_from_reponse(autho_res, '1')
             autho_ip=autho_an[0].to_text()
             
             for elem in response.authority:
                 rrset_type = dns.rdatatype.to_text(elem.rdtype)
                 next_domain = elem.name
                 break
             cur_ds=get_info_from_reponse(response,'43')
             if cur_ds is None:
               print('DNSSEC not supported')
               exit()
             verify_ds(response, name,dnskey)
             
             return foresolve_sec(hostname,reqtype,autho_ip,next_domain, cur_ds)
         
def main():
  #parse system paratermers: prepare dns query data and use the return to print
   try:
      reqtype = sys.argv[2]
      query_domain = str(sys.argv[1])
   except BaseException:
      print("the system argument is invalid, please identify domain and query type")
      exit()
   starttime = time.time()
   response=iniresolve_sec(query_domain,reqtype)
   endtime= time.time()
   print('QUESTION SECTION:')
   print(str(query_domain) + " " + "IN" + " " + str(reqtype))
   print('ANSWER SECTION:')
   print(response.answer[0])
   #for item in response.answer:
   #   print(item)
   print('Query time: %s ms' % ((endtime - starttime) * 1000))
   print('WHEN: ' + str(time.ctime()))
   print('MSG SIZE rcvd: ' + str(len(str(response))))

if __name__ == '__main__':
    main()
