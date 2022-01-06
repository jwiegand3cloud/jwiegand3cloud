#!/usr/bin/python3
import requests
import sys
import socket
import whois
from ipwhois import IPWhois
from bs4 import BeautifulSoup
import json
from pysafebrowsing import SafeBrowsing
 
gsb_apikey = ""
registrant_email_table = []
content_type = {'Content-Type': 'application/json'}
user_agent = {'User-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_4) AppleWebKit/537.36 Chrome/36.0.1985.125 Safari/537.36'}
 
tlds = "tld.txt"
 
try:
    domain = sys.argv[1]
except:
    print ("!!  ERROR   !!")
    sys.exit()
 
print ("\nAll Your TLDs Are Belong To Us!")
print ("Now running lookups for " + domain + "...\n") 
 
def whois_lookup(domainname):
    try:
        nameservers = []
        nameserver1 = ""
        nameserver2 = ""
        nameserver3 = ""
        nameserver4 = ""
        registrant_emails = []
        registrant_email1 = ""
        registrant_email2 = ""
        registrant_email3 = ""
        registrant_email4 = ""
        registrant_name1 = ""
        registrant_address = ""
        registrant_country = ""
        state = ""
        orgname1 = ""
        emailindex = 1
        nsindex = 1
        try:
            w = whois.whois(domainname)
        except:
            pass
        try:
            created_date = w.creation_date
            try:
                if len(created_date) == 2:
                    created_date = created_date[0]
            except:
                pass
        except:
            created_date = "1969-12-31 00:00:00"
            pass
        try:
            expired_date = w.expiration_date
            try:
                if len(expired_date) == 2:
                    expired_date = expired_date[0]
            except:
                pass
        except:
            expired_date = "1969-12-23 00:00:00"
            pass
        try:
            registrant_name1 = w.name
            if not registrant_name1:
                registrant_name1 = ""
        except:
            registrant_name1 = ""
            pass
        try:
            registrant_address = w.address
            if not registrant_address:
                registrant_address = ""
        except:
            pass
            registrant_address = ""
        try:
            registrant_country = w.country
            registrant_country = str(registrant_country)
            if not registrant_country:
                registrant_country = ""
        except:
            registrant_country = ""
            pass
        try:
            state = w.state
            if not state:
                state = ""
        except:
            state = ""
            pass
        try:
            orgname1 = w.org
            if not orgname1:
                orgname1 = ""
        except:
            orgname1 = ""
            pass
        try:
            whois_city = w.city
            if not whois_city:
                whois_city = ""
        except:
            whois_city = ""
            pass
        try:
            whois_zipcode = w.zipcode
            if not whois_zipcode:
                whois_zipcode = ""
        except:
            whois_zipcode = ""
            pass
        try:
            whois_registrar = w.registrar
            if len(whois_registrar) < 4:
                whois_registrar = whois_registrar[0]
            whois_ref_url = w.referral_url
        except:
            whois_registrar = ""
            whois_ref_url = ""
            pass
        try:
            nameservers = w.name_servers
            if not nameservers:
                nameservers = ""
        except:
            nameservers = ""
            pass
        try:
            nameserver1 = w.name_servers[0]
            if not nameserver1:
                nameserver1 = ""
        except:
            nameserver1 = ""
            pass
        try:
            nameserver2 = w.name_servers[1]
            if not nameserver2:
                nameserver2 = ""
        except:
            nameserver2 = ""
            pass
        try:
            nameserver3 = w.name_servers[2]
            if not nameserver3:
                nameserver3 = ""
        except:
            nameserver3 = ""
            pass
        try:
            nameserver4 = w.name_servers[3]
            if not nameserver4:
                nameserver4 = ""
        except:
            nameserver4 = ""
            pass
        try:
            registrant_emails = w.emails
            if len(registrant_emails) > 5:
                registrant_email1 = w.emails
                registrant_email_table.append(registrant_email1)
            else:
                for registrant_email in registrant_emails:
                    registrant_email_table.append(registrant_email)
                    if emailindex == 1:
                        registrant_email1 = registrant_email
                    if emailindex == 2:
                        registrant_email2 = registrant_email
                    if emailindex == 3:
                        registrant_email3 = registrant_email
                    if emailindex == 4:
                        registrant_email4 = registrant_email
                    emailindex = emailindex + 1
        except:
            pass
    except:
        pass
    try:
        try:
            domain_ipaddr = socket.gethostbyname(domainname)
        except:
            domain_ipaddr = "- -"
            pass
        if domain_ipaddr != "- -":
            obj = IPWhois(domain_ipaddr)
            results = obj.lookup_whois()
            domain_asnid = "AS" + results['asn']
            if domain_asnid == "":
                domain_asnid = "- -"
            try:
                domain_country = results['asn_country_code']
                if domain_country == "":
                    domain_country = "- -"    
            except:
                domain_country = "- -"
                pass
            try:
                domain_asn_name = results['nets'][0]['name']
                if domain_asn_name == "" or 'None':
                    domain_asn_name = "- -"
            except:
                domain_asn_name = "- -"
                pass
        else:
            domain_asnid = "- -"
            domain_country = "- -"
            domain_asn_name = "- -"
    except:
        domain_asnid = "- -"
        domain_asnid = "- -"
        domain_country = "- -"
        domain_asn_name = "- -"
        pass
    #################### BLOCKLIST FUNCTION BELOW ##################
    try:
        url = "https://www.urlvoid.com/scan/" + domainname + "/"
        results = requests.get(url, headers=user_agent).content
        soup = BeautifulSoup(results, 'html.parser')
        t = soup.find('span',{'class':'label-danger'})
        urlvoid_bl = "URLVOID: " + t.text
        print(urlvoid_bl)
        #return urlvoid_bl
    except:
        urlvoid_bl = ""
        pass
    try:
        url2 = "https://fortiguard.com/webfilter?q=" + domainname + "&version=8"
        results2 = requests.get(url2, headers=user_agent).content
        soup2 = BeautifulSoup(results2, 'html.parser')
        t2 = soup2.find("meta", property="description")
        fortiguard = "FORTIGUARD " + str(t2["content"]) 
        print(fortiguard)
        #return fortiguard
    except:
        fortiguard = ""
        pass
    try:
        url3 = "http://www.siteadvisor.com/sitereport.html?url=" + domainname
        results3 = requests.get(url3, headers=user_agent).content
        soup3 = BeautifulSoup(results3, 'html.parser')
        t3 = soup3.find('a').contents[0]
        siteadvisor_bl = "SITEADVISOR: " + str(t3)
        print(siteadvisor_bl)
        #return fortiguard
    except:
        siteadvisor_bl = ""
        pass
    try:
        gsb_lookup = SafeBrowsing(gsb_apikey)
        results4 = gsb_lookup.lookup_urls([domainname])
        gsb_status = str(results4[domainname]['malicious'])
        gsb_platforms = results4[domainname]['platforms'][0]
        gsb_threats = results4[domainname]['threats'][0]
        print("GOOGLE SAFE BROWSING API4: " + gsb_status + " || " + gsb_platforms + " || " + gsb_threats)
    except:
        gsb_status = ""
        gsb_platforms = ""
        gsb_threats = ""
        pass
    try:
        url5 = "https://www.abuseipdb.com/check/" + domainname
        results5 = requests.get(url5, headers=user_agent).content
        soup5 = BeautifulSoup(results5, 'html.parser')
        abusedb_status = soup5.find_all('h3')[0].contents[2].strip().strip(" <tr>")
        if abusedb_status == "was found in our database!":
            abusedb_reported = soup5.find('div',{'class':'well'}).contents[3].contents[1].contents[0]
            abusedb_reported = str(abusedb_reported)
            abusedb_confidence = soup5.find('div',{'class':'well'}).contents[3].contents[3].contents[0]
            abusedb_confidence = str(abusedb_confidence)
            print("ABUSEDB : " + abusedb_status + " || " + abusedb_reported + " || " + abusedb_confidence)
        else:
            abusedb_status = ""
            abusedb_reported = ""
            abusedb_confidence = ""
    except:
        abusedb_status = ""
        abusedb_reported = ""
        abusedb_confidence = ""
        pass
    try:
        output = domainname + ";" + orgname1 + ";"  + registrant_name1 + ";" + registrant_email1 + ";" + registrant_email2 + ";" + registrant_email3 + ";" + registrant_email4 + ";" + registrant_country + ";" + whois_city + ";" + whois_zipcode+ ";" +  nameserver1 + ";" + nameserver2 + ";" +  domain_ipaddr + ";" + domain_asnid + ";" + domain_asn_name + ";" + domain_country + ";" + gsb_status + ";" + gsb_platforms + ";" + gsb_threats + ";" + fortiguard + ";" + urlvoid_bl + ";" + siteadvisor_bl + ";" + abusedb_status + ";" + abusedb_reported + ";" + abusedb_confidence + "\n"
        filename1 =  domain + "-ALLTLDS.csv"
        with open (filename1, "a") as outputfile:
            outputfile.write(output)
        output = ""
    except:
        print("!!!!     ERROR     !!!!")
        pass
 
 
 
inputfile = open(tlds, "r")
all_doms = inputfile.readlines()
all_tlds = set(all_doms)
inputfile.close()
 
 
 
for domainname in all_tlds:
    domainname = domainname.strip("\n")
    domainname = domain + "." + domainname
    print ("\n" + domainname + ":")
    whois_lookup(domainname)
 
 
print ("\n\n-=-=-=-=-   All Your TLDs has completed.  -=-=-=-=-\n\n")
 
sys.exit()