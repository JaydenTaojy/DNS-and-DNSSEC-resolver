import dns.query
import dns.message
import dns.name
import dns.flags
import sys
import time

#help to get IP from response.answer section, used for authroty re-resolve
def get_IP_from_answer(response):
   for rrset in response.answer:
      if rrset.rdtype == 1:
        return rrset[0].to_text()
        
def make_query_helper (hostname,reqtype):
   if (reqtype != 'A' and  reqtype != 'NS' and reqtype != 'MX'):
        print("Invalid DNS type.")
        exit()
   domain = dns.name.from_text(hostname)
   request = dns.message.make_query(domain, reqtype)
   return request
   
def quey_helper(request, sever_ip):
    response = dns.query.udp(request,str(sever_ip),timeout=0.5)
    return response

#it is for root resolve
def iniresolve(hostname,reqtype):
    serverlist =["198.41.0.4","199.9.14.201","192.33.4.12","199.7.91.13","192.203.230","192.5.5.241","192.112.36.4","198.97.190.53","192.36.148.17","192.58.128.30","193.0.14.129","199.7.83.42","202.12.27.33"]
    
    request = make_query_helper (hostname,reqtype)
        # use severlist to send query
    for server in serverlist:
        
        #try:
          response = quey_helper(request, server)
          #the root resolve contain no result, check additional set for next level resolve directly
          if (len(response.additional)!=0):
              for elem in response.additional:
                  if (elem.rdtype ==1):
                      new_server= elem[0]
                      break;
              return foresolve(hostname, reqtype, new_server)
           
          #If additional sections are empty, get the name from authority section and send it for resolution
          else:
              ans = str(response.authority[0])
              data = ans.split(' ')
              
              autho_res=iniresolve(str(data[-1]), 'A')
              autho_ip=get_IP_from_answer(autho_res)
              #autho_ip=iniresolve(authoDomain[0].to_text(), 'A')
              print(autho_ip)
              return foresolve(hostname,reqtype,autho_ip)
            
          break
          
#it is for non-root resolve
def foresolve(hostname,reqtype,sever_ip):
       request = make_query_helper (hostname,reqtype)
    #try:
       response = quey_helper(request, sever_ip)
       
       #check the answer set to get final result
       if (len(response.answer)!=0):
         for elem in response.answer:
            if (elem.rdtype ==5): # CNAME is returned not reuired IP address
              answer = str(response.answer[0])
              data = answer.split(' ')
              return iniresolve(data[-1],'A')
            else: #ip returned
               return response
        #no final result, check additional set for next level resolve
       elif (len(response.additional)!=0):
            for elem in response.additional:
                if (elem.rdtype==1):
                    new_server= elem[0]
                    break;
                          
            return foresolve(hostname, reqtype, new_server)
            #quey_helper(request, new_server)
               
       #If answer and additional sections are empty, get the name from authority section and send it for resolution
       elif(len(response.authority)!=0):
             ans = str(response.authority[0])
             data = ans.split(' ')
             
             autho_res=iniresolve(str(data[-1]), 'A')
             autho_ip=get_IP_from_answer(autho_res)
             #autho_ip=iniresolve(authoDomain[0].to_text(), 'A')
             return foresolve(hostname,reqtype,autho_ip)
                  
       else:
          print("resolve failed!")

   
         
def main():
  #parse system paratermers: prepare dns query data and use the return to print
   try:
      reqtype = sys.argv[2]
      query_domain = str(sys.argv[1])
   except BaseException:
      print("the system argument is invalid")
      exit()

   print('QUESTION SECTION:')
   print(str(query_domain) + " " + "IN" + " " + str(reqtype))
   starttime = time.time()
   response=iniresolve(query_domain,reqtype)
   endtime= time.time()
   
   print('ANSWER SECTION:')
   for item in response.answer:
      print(item)
   print('Query time: %s ms' % ((endtime - starttime) * 1000))
   print('WHEN: ' + str(time.ctime()))
   print('MSG SIZE rcvd: ' + str(len(str(response))))

if __name__ == '__main__':
    main()
