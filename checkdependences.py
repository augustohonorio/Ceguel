# -*- coding: utf-8 -*-
#!/usr/bin/env python
import os

def check_prerequisite():
    print ('''
######## CHECK PRE REQUIREMENTS ########
    ''')
    os.system(''' 
    echo  "Checking DIRB =>"
        if ! hash dirb 2>/dev/null; then
        echo -e '\033[1;31m DIRB Not Installed \033[m'   
        exit=1
    else
        echo 'OK!'   
    fi
    sleep 0.5

    echo "Checking python =>"
    if ! hash python 2>/dev/null; then
        echo -e '\033[31;40;1m Python Not Installed \033[m'
        exit=1
    else
        echo "OK!"
    fi
    sleep 0.5

    echo "Checking NMAP =>"
    if ! hash nmap 2>/dev/null; then
        echo "NMAP Not Installed"
        exit=1
    else
        echo "OK!"
    fi
    sleep 0.5

    if [ "$exit" = "1" ]; then
    exit 1
    fi
    sleep 0.5''')
    contiue = raw_input("Press enter to continue. . .")
    os.system('clear')

check_prerequisite()