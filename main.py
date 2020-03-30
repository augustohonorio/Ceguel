# -*- coding: utf-8 -*-
#!/usr/bin/env python

import os
import sys
import fileinput
import optparse
import subprocess
import string
def main():
    try: 
        def logo():
            os.system('clear')
            print ("""
##################################################################   
# Created and edited by Augusto Honorio  | BRA | 11 OUT 2017     #  
# Version : 2.1  UPDATED AT 01 ABR 2018  OPEN                    #
# Contact : Augusto@tenditech.com  GitHub:github.com/Alobus      #
# Telegram: @augustohonorio                                      #
##################################################################""")

        def home():
            print ("""
1 - Install nmap and their componets
2 - Install soft of your choise
3 - Search soft of your choise
4 - Enter katoolin
5 - Enter modules attack nmap
6 - Create connection SSH
7 - List directory
8 - Simple Crawling and E-mail(s) Finder
99 - help
0 - Exit.
""")
            option = raw_input("\033[1;36m[HOME]Option valid> \033[1;m")
            
            if option == "0":
                print ("BYE!!")
                os.system('exit')
            elif option == "1":
                install_nmap()
            elif option == "2":
                install_soft()
            elif option == "3":
                checking_install_soft()
            elif option == "4":
                enter_kat()
            elif option == "5":
                opt1()
            elif option == "6":
                newssh()
            elif option == "7":
                list_directory()
            elif option == "8":
                email_finder()
            elif option == "99":
                help()
            else:
                os.system('clear && cls')
                logo()
                print "Select a valid option!"
                home()

        ####### Features ######
        def checkrequisite():
            os.system("python /ceguel/checkdependences.py")
        def install_nmap():
            os.system('sudo apt-get install nmap')
            os.system('clear')
            logo()
            home()

        def install_soft():
            soft = raw_input(str('soft for install[Press 0 to come back]: '))
            if soft == "0":
                print ("CANCELED!")
                home()

            else:
                os.system('sudo apt-get install ' + soft)

            
        def enter_kat():
            logo()
            os.system('sudo python /ceguel/kat.py')

        def checking_install_soft():
            soft = raw_input(str('search soft: '))
            if soft == "back":
                logo()
                home()
            elif soft == "home":
                logo()
                home()      
            else:
                os.system('sudo dpkg -l | grep ' + soft)
                prox = raw_input ('Press Enter key to continue')
                logo()
                home()

        def newssh():
            host = raw_input(str('Enter host: '))
            if host == "0":
                logo()
                home()
            else:
                user = raw_input(str('Enter user: '))
                os.system('ssh -l ' + user + ' ' + host)

        def help():
            print ('''
****************** +prerequisite+ ******************
Ubuntu 16.04 LTS or other distribution based on debian
Python 2.7.14 
Nmap 7.60 or above

****************** +Commands+ ******************
1 - back = back to previous page
2 - home = back to home page
when it is not possible to use "back" or "home" it will be described as returning to the proper function

****************** +OBS+ ******************
in cases of errors or bugs, please report with images or anything else that proves the same
        ''')
            nex = raw_input(str('Press enter to continue . . .'))
            os.system('clear')
            logo()
            home()

        def opt1():
            print ('''
1 - HTTP NSE Attackmod.
2 - RECON  NSE Attackmod.
3 - CUSTOM  NSE Attackmod.
4 - SSH NSE Attackmod.
5 - FTP NSE Attackmod.
6 - MySql NSE Attackmod.
7 - Http-vuln-cve NSE Attackmod
8 - SMB-vuln-cve NSE Attackmod
''')
            atack = raw_input("\033[1;36mEnter Attackmod > \033[1;m")
            if atack == "1":
                httpmain()
            elif atack == "2":
                reconmain()
            elif atack == "3":
                custommain()
            elif atack == "4":
                sshnse()
            elif atack == "5":
                ftpnse()
                home()
            elif atack == "6":
                MySqlnse()
                home()
            elif atack == "7":
                http_vuln_cve()
                home()
            elif atack == "8":
                smbvulncve()
                home()
            elif atack == "back":
                logo()
                home()
            elif atack == "home":
                logo()
                home()
            else:
                os.system('clear')
                print ("Select a valid option!")
                logo()
                opt1()

        def MySqlnse():
            os.system('clear')
            logo()
            print ("""
MySql SCRIPT
WARNING: this attack module may take a while due to the brute force script
To back Press 0 and Enter
""")

            rhost = raw_input(str("Enter the server url ex:8.8.8.8: "))
            if rhost == "0":
                logo()
                opt1()
            else:
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script mysql* " + "-p3306 " + rhost + " " + addop)
                home()

        def http_vuln_cve():
            os.system('clear')
            logo()
            print ('''
List vuln CVE
1 - vuln-cve2006-3392   2 - vuln-cve2009-3960
3 - vuln-cve2010-0738   4 - vuln-cve2010-2861
5 - vuln-cve2011-3192   6 - vuln-cve2011-3368
7 - vuln-cve2012-1823   8 - vuln-cve2013-0156
9 - vuln-cve2013-6786   10 - vuln-cve2013-7091
11 - vuln-cve2014-2126   12 - vuln-cve2014-2127
13 - vuln-cve2014-2128   14 - vuln-cve2014-2129
15 - vuln-cve2014-3704   16 - vuln-cve2014-8877
17 - vuln-cve2015-1427   18 - vuln-cve2015-1635
19 - vuln-cve2017-1001000 20 - vuln-cve2017-5638
21 - vuln-cve2017-5689   22 - vuln-cve2017-8917
        ''')
            vuln = raw_input(str("\033[1;36mEnter num vuln-cve> \033[1;m"))
            if vuln == '1':
                vuln2 = 'http-vuln-cve2006-3392.nse'
            elif vuln == '2':
                vuln2 = 'http-vuln-cve2009-3960.nse'
            elif vuln == '3':
                vuln2 = 'http-vuln-cve2010-0738.nse'
            elif vuln == '4':
                vuln2 = 'http-vuln-cve2010-2861.nse'
            elif vuln == '5':
                vuln2 = 'http-vuln-cve2011-3192.nse'
            elif vuln == '6':
                vuln2 = 'http-vuln-cve2011-3368.nse'
            elif vuln == '7':
                vuln2 = 'http-vuln-cve2012-1823.nse'
            elif vuln == '8':
                vuln2 = 'http-vuln-cve2013-0156.nse'
            elif vuln == '9':
                vuln2 = 'http-vuln-cve2013-6786.nse'
            elif vuln == '10':
                vuln2 = 'http-vuln-cve2013-7091.nse'
            elif vuln == '11':
                vuln2 = 'http-vuln-cve2014-2126.nse'
            elif vuln == '12':
                vuln2 = 'http-vuln-cve2014-2127.nse'
            elif vuln == '13':
                vuln2 = 'http-vuln-cve2014-2128.nse'
            elif vuln == '14':
                vuln2 = 'http-vuln-cve2014-2129.nse'
            elif vuln == '15':
                vuln2 = 'http-vuln-cve2014-3704.nse'
            elif vuln == '16':
                vuln2 = 'http-vuln-cve2014-8877.nse'
            elif vuln == '17':
                vuln2 = 'http-vuln-cve2015-1427.nse'
            elif vuln == '18':
                vuln2 = 'http-vuln-cve2015-1635.nse'
            elif vuln == '19':
                vuln2 = 'http-vuln-cve2017-1001000.nse'
            elif vuln == '20':
                vuln2 = 'http-vuln-cve2017-5638.nse'
            elif vuln == '21':
                vuln2 = 'http-vuln-cve2017-5689.nse'
            elif vuln == '22':
                vuln2 = 'http-vuln-cve2017-8917.nse'
            elif vuln == 'back':
                logo()
                opt1()
            elif vuln == 'home':
                logo()
                home()
            else:
                print ('''
        Select a option valid!
                    ''')
                http_vuln_cve()
            rhost = raw_input(str("Enter the server ex:8.8.8.8"))
            if rhost == "0":
                logo()
                opt1()
            else:
                addop = raw_input(str("Add option to nmap? ex -Pn -sV othr: "))
                os.system("nmap --script " + vuln2 + " " + rhost + " " + addop)

        def smbvulncve():
            os.system('clear')
            logo()
            print('''
SMB SCRIPT
1 - smb brute                2 - smb double pulsar backdoor
3 - smb enum domains         4 - smb enum groups
5 - smb enum processes       6 - smb enum sessions
7 - smb enum shares          8 - smb enum users
9 - smb flood                10 - smb ls
11 - smb mbenum              12 - smb os discovery
13 - smb print text          14 - smb protocols
15 - smb psexec              16 - smb security mode
17 - smb server stats        18 - smb system info
19 - smb vuln conficker      20 - smb vuln cve2009-3103
21 - smb vuln cve-2017-7494  22 - smb vuln ms06-025
23 - smb vuln ms07-029       24 - smb vuln ms08-067
25 - smb vuln ms10-054       26 - smb vuln ms10-061
27 - smb vuln ms17-010       28 - smb vuln regsvc dos
        ''')
            vuln = raw_input(str("\033[1;36mEnter num vuln-cve> \033[1;m"))
            if vuln == '1':
                vuln2 = 'smb-brute.nse'
            elif vuln == '2':
                vuln2 = 'smb-double-pulsar-backdoor.nse'
            elif vuln == '3':
                vuln2 = 'smb-enum-domains.nse'
            elif vuln == '4':
                vuln2 = 'smb-enum-groups.nse'
            elif vuln == '5':
                vuln2 = 'smb-enum-processes.nse'
            elif vuln == '6':
                vuln2 = 'smb-enum-sessions.nse'
            elif vuln == '7':
                vuln2 = 'smb-enum-shares.nse'
            elif vuln == '8':
                vuln2 = 'smb-enum-users.nse'
            elif vuln == '9':
                vuln2 = 'smb-flood.nse'
            elif vuln == '10':
                vuln2 = 'smb-ls.nse'
            elif vuln == '11':
                vuln2 = 'smb-mbenum.nse'
            elif vuln == '12':
                vuln2 = 'smb-os-discovery.nse'
            elif vuln == '13':
                vuln2 = 'smb-print-text.nse'
            elif vuln == '14':
                vuln2 = 'smb-protocols.nse'
            elif vuln == '15':
                vuln2 = 'smb-psexec.nse'
            elif vuln == '16':
                vuln2 = 'smb-security-mode.nse'
            elif vuln == '17':
                vuln2 = 'smb-server-stats.nse'
            elif vuln == '18':
                vuln2 = 'smb-system-info.nse'
            elif vuln == '19':
                vuln2 = 'smb-vuln-conficker.nse'
            elif vuln == '20':
                vuln2 = 'smb-vuln-cve2009-3103.nse'
            elif vuln == '21':
                vuln2 = 'smb-vuln-cve-2017-7494.nse'
            elif vuln == '22':
                vuln2 = 'smb-vuln-ms06-025.nse'
            elif vuln == '23':
                vuln2 = 'smb-vuln-ms07-029.nse'
            elif vuln == '24':
                vuln2 = 'smb-vuln-ms08-067.nse'
            elif vuln == '25':
                vuln2 = 'smb-vuln-ms10-054.nse'
            elif vuln == '26':
                vuln2 = 'smb-vuln-ms10-061.nse'
            elif vuln == '27':
                vuln2 = 'smb-vuln-ms17-010.nse'
            elif vuln == '28':
                vuln2 = 'smb-vuln-regsvc-dos.nse'
            elif vuln == 'back':
                logo()
                opt1()
            elif vuln == 'home':
                logo()
                home()
            else:
                print ('''
        Select a option valid!
                    ''')
                smbvulncve()
            rhost = raw_input(str("Enter the victim: "))
            if rhost == "0":
                logo()
                opt1()
            else:
                addop = raw_input(str("Add option to nmap? ex -Pn -sV othr:"))
                os.system("nmap --script " +  vuln2 + " " + rhost + " " + addop)

        def ftpnse():
                os.system('clear')
                logo()
                print ("""
FTP SCRIPT
WARNING: this attack module may take a while due to the brute force script
To back Press 0 and Enter
""")

                rhost = raw_input(str("Enter the web url ex:8.8.8.8: "))
                if rhost == "0":
                    logo()
                    opt1()
                else:
                    addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                    os.system("nmap --script ftp* " + rhost + " " + addop)
                    home()

        def sshnse():
            os.system('clear')
            logo()
            print ("""
SSH SCRIPT
locate default file /usr/share/nmap/nselib/data/passwords.lst
WARNING: this attack module may take a while due to the brute force script
To back Press 0 and Enter
""")

            rhost = raw_input(str("Enter the server IP ex:8.8.8.8: "))
            if rhost == "0":
                logo()
                opt1()
            else:
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script ssh* " + rhost + " " + addop)
                home()

        def httpmain():
            print "httpmain ok"
            os.system('clear')
            logo()
            print ("""
1 - HTTP-ENUM
2 - HTTP-TITLE
3 - HTTP-SITEMAP-GENERATOR 
4 - HTTP-BRUTE
5 - Print Help
""")

            menuselect = raw_input("\033[1;36moption > \033[1;m")
            if menuselect == "0":
                os.system('clear')
                logo()
                opt1()
            elif menuselect == "1":
                os.system('clear')
                logo()
                print ("""
HTTP-ENUM > Enumerate directories on one host ex: www.site.com
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script http-enum " + rhost + " " + addop)
                home()

            elif menuselect == "2":
                os.system('clear')
                logo()
                print ("""
HTTP-TITLE > Find the Title of the web page from a web server
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script http-title " + rhost + " " + addop)
                home()


            elif menuselect == "3":
                os.system('clear')
                logo()
                print ("""
HTTP-SITEMAP-GENERATOR > Generate a simple sitemap from a webserver
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script http-sitemap-generator " + rhost + " " + addop)
                home()
            elif menuselect == "4":
                os.system('clear')
                logo()
                print ("""
HTTP-BRUTE > Brute http scan from a webserver
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script http-brute " + rhost + " " + addop)
                home()
            elif menuselect == "5":
                print ("""
1 - HTTP-ENUM > Enumerate directories on one host ex: www.site.com
2 - HTTP-TITLE > Find the Title of the web page from a web server
3 - HTTP-SITEMAP-GENERATOR > Generate a simple sitemap from a webserver 
4 - HTTP-BRUTE > Brute http scan from a webserver
""")
                back = raw_input("Press enter key to continue")
                httpmain()
            elif menuselect == "back":
                logo()
                opt1()
            elif menuselect == "home":
                logo()
                home()
            else:
                os.system('clear')
                logo()
                print "Select a valid option!"
                httpmain()

        def reconmain():
            print "httpmain ok"
            logo()
            print ("""
1 - DNS-BRUTE
2 - HOSTMAP-BFK
3 - TRACE-GEOLOC
4 - SMB-DISCOVER
5 - SMB-BRUTE
6 - Help Services in page
""")

            menuselect = raw_input(str("\033[1;36mOption > \033[1;m"))

            if menuselect == "1":
                os.system('clear')
                logo()
                print ("""
DNS-BRUTE > Detecting sub-domains associated with an organizations domain.
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script dns-brute " + rhost + " " + addop)
                home()

            elif menuselect == "2":
                os.system('clear')
                logo()
                print ("""
HOSTMAP-BFK > Another tactic for expanding and find virtual hosts on an IP.
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script hostmap-bfk " + rhost + " " + addop)
                home()

            elif menuselect == "3":
                os.system('clear')
                logo()
                print ("""
TRACE-GEOLOC > Perform a traceroute to your target IP address and have geolocation.
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script traceroute-geolocation " + rhost + " " + addop)
                home()

            elif menuselect == "4":
                os.system('clear')
                logo()
                print ("""
SMB-DISCOVER > Determine operating system, computer name, netbios name and domain.
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap -O --script smb-os-discovery " + rhost + " " + addop)
                home()

            elif menuselect == "5":
                os.system('clear')
                logo()
                print ("""
SMB-BRUTE > Attempt to brute force local accounts against the samba service.
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script smb-brute " + rhost + " " + addop)
                home()
            elif menuselect == "6":
                os.system('clear')
                logo()
                print ('''
1 - DNS-BRUTE > Detecting sub-domains associated with an organizations domain.
2 - HOSTMAP-BFK > Another tactic for expanding and find virtual hosts on an IP.
3 - TRACE-GEOLOC > Perform a traceroute to your target IP address and have geolocation.
4 - SMB-DISCOVER > Determine operating system, computer name, netbios name and domain.
5 - SMB-BRUTE > Attempt to brute force local accounts against the samba service.
        ''')
                enter = raw_input("press enter key to continue ")
                os.system('clear')
                reconmain()
            elif menuselect == "back":
                logo()
                opt1()
            elif menuselect == "gohome":
                logo()
                home()

            else:
                os.system('clear')
                logo()
                print "Select a valid option!"
                reconmain()


        def custommain():
            print "httpmain ok"
            os.system('clear')
            logo()
            print ("""
1 - CUSTOM SCRIPT > Scripts cotained at /usr/share/nmap/scripts/
""")

            menuselect = raw_input(str("\033[1;36mOption > \033[1;m"))

            if menuselect == "1":
                os.system('clear')
                logo()
                print ("""
CUSTOM SCRIPT > Scripts cotained at /usr/share/nmap/scripts/
""")
                rhost = raw_input(str("Enter the web url ex: www.site.com: "))
                nsesc = raw_input(str("Enter the nse script name: "))
                addop = raw_input(str("Add option to nmap?ex -Pn -sV othr: "))
                os.system("nmap --script " + nsesc + " " + rhost + " " + addop)
                home()
            elif menuselect == "back":
                logo()
                opt1()
            elif menuselect == "gohome":
                logo()
                home()
            else:
                os.system('clear')
                logo()
                print "Select a valid option!"
                home()
        def list_directory():
            os.system('clear')
            logo()
            helps = raw_input("Need help? y/N ")

            if helps == "y":
                kata = raw_input ('''
Prerequisites: Dirb and wordlist's both can be installed using our katollin function
Would you like to go to her? y/N
''')
                if kata == "y":
                    os.system('clear')
                    katoolin()
                else:
                    list_directory_true()
            else:
                list_directory_true()

        def list_directory_true():
            server = raw_input("Enter url (ex:http://www.google.com): ")
            wordlist_dirb = raw_input('''
Enter wordlist
ex: /usr/share/dirb/wordlists/vulns/apache.txt
if nothing is set, we will use the one used in the example
locate wordlist: ''')
            if wordlist_dirb == "":
                wordlist_dirb = "/usr/share/dirb/wordlists/vulns/apache.txt"
            else:
                wordlist_dirb = wordlist_dirb
            os.system('dirb ' + server + " " + wordlist_dirb )

        def email_finder():
            import requests
            import re

            print (''' 
Emails finder and crawling site
Scan may take according to site size
Example: https://google.com
''')

            site = raw_input('site: ')

            intensity = raw_input('''
1- Simple
2- Medium
3- Intense
intensity of scan: ''')
            if intensity == "1":
                intensity = 25
            elif intensity == "2":
                intensity = 50
            else:
                intensity = 100

            to_crawl = [site]
            crawled = set()

            emails_found = set()

            header = {'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                                    'Chrome/51.0.2704.103 Safari/537.36'}

            for i in range(intensity):
                url = to_crawl[0]
                try:
                    req = requests.get(url, headers=header)
                except:
                    to_crawl.remove(url)
                    crawled.add(url)
                    continue

                html = req.text
                links = re.findall(r'<a href="?\'?(https?:\/\/[^"\'>]*)', html)
                print 'Crawling:', url

                emails = re.findall(r'[\w\._-]+@[\w_-]+\.[\w\._-]+\w', html)

                to_crawl.remove(url)
                crawled.add(url)

                for link in links:
                    if link not in crawled and link not in to_crawl:
                        to_crawl.append(link)

                for email in emails:
                    emails_found.add(email)

            print emails_found
            contiue = raw_input("Press enter to continue. . .")
            #os.system('ceguel')
            home()

        #order by priority
        checkrequisite()
        logo()
        home()

    except KeyboardInterrupt:
        print ("Shutdown requested...Goodbye...")
    except Exception:
        traceback.print_exc(file=sys.stdout)
    sys.exit(0)
if __name__ == "__main__":
    main()
