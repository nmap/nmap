# Author: b0yd @rwincey
# Website: securifera.com
#
# Setup:
# -------------------------------------------------
# Install Selenium
# - pip install selenium
# 
# Download latest google chrome & install
# - wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
# - dpkg -i ./google-chrome-stable_current_amd64.deb
#
# Identify google version
# - ./google-chrome-stable --version 
#
# Vist http://chromedriver.chromium.org/downloads to identity the right version of driver
#
# Use wget to download the right version
# - wget https://chromedriver.storage.googleapis.com/<version>/chromedriver_linux64.zip
#
# Move the chromedriver to a directory in the PATH env var
# - mv ./chromedriver /usr/bin/
#
# Usage:
# -------------------------------------------------
# python screenshot.py -u 172.217.12.78 -p 443
#
#
# Troubleshooting
# -------------------------------------------------
# Error: TypeError: urlopen() got multiple values for keyword argument 'body'
#
# Solution: pip install --upgrade --ignore-installed urllib3
#


import argparse
import httplib, sys
import socket
import json
import os
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException

def get_ssl_subject_name(origin, log):

    #Parse through performance logs and attempt to dig out the subject name from the SSL info
    try:
        for entry in log:

            #Get the message
            msg = entry['message']
            inner_msg = json.loads(msg)

            #Get the inner message
            msg = inner_msg['message']
            method = msg['method']
            #Only parse network response msgs
            if method == 'Network.responseReceived':
                data = msg['params']
                #Get response
                response = data['response']
                #Get URL
                url = response['url']
                if origin == url:
                    ssl_info = response['securityDetails']
                    return ssl_info['subjectName']
    except:
        pass

def navigate_to_url( driver, url, host ):

    ret_host = None
    print url
    try:
        driver.get(url)
    except Exception, e:
        print e
        pass

    origin = driver.current_url
    ssl_subj_name = get_ssl_subject_name(origin, driver.get_log('performance'))
    if ssl_subj_name and host != ssl_subj_name:
        print "Certificate Host Mismatch: %s %s" % ( host, ssl_subj_name )
        ret_host = ssl_subj_name

    return ret_host

def take_screenshot( ip, port_arg, query_arg="" ):

    try:
        host = socket.gethostbyaddr(ip)[0]
    except:
        host = ip
        pass

    empty_page = '<html><head></head><body></body></html>'
    caps = DesiredCapabilities.CHROME
    caps['loggingPrefs'] = {'performance': 'ALL'}      # Works prior to chrome 75
    caps['goog:loggingPrefs'] = {'performance': 'ALL'} # Updated in chrome 75
    options = webdriver.ChromeOptions()
    if os.name == 'nt':
        options.binary_location = 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
    else:
        options.binary_location = '/usr/bin/google-chrome-stable'
        
    options.add_argument('headless')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--no-sandbox')
    options.add_argument('--user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36"')

    driver = webdriver.Chrome('chromedriver', chrome_options=options, desired_capabilities=caps)
    driver.set_window_size(1024, 768) # set the window size that you need
    driver.set_page_load_timeout(30)
    source = None

    port = ""
    if port_arg:
        port = ":" + port_arg

    #Add query if it exists
    path = host + port
    if query_arg:
        path += "/" + query_arg

    #Get the right URL
    url = "http://" + path

    #Retrieve the page
    ret_err = False

    #Enable network tracking
    driver.execute_cdp_cmd('Network.enable', {'maxTotalBufferSize': 1000000, 'maxResourceBufferSize': 1000000, 'maxPostDataSize': 1000000})

    #Goto page
    ret_host = navigate_to_url(driver, url, host)
    try: 

        if driver.page_source == empty_page or 'use the HTTPS scheme' in driver.page_source or 'was sent to HTTPS port' in driver.page_source:
            
            url = "https://" + path
            #print url
            ret_host = navigate_to_url(driver, url, host)
            if driver.page_source == empty_page:
                ret_err = True

        if ret_err == False:
            #Cleanup filename and save
            filename = url.replace('https://', '').replace('http://','').replace(':',"_")
            if host != ip:
                filename += "_" + ip
            driver.save_screenshot(filename + ".png")

        #If the SSL certificate references a different hostname
        if ret_host:

            #Replace any wildcards in the certificate
            ret_host = ret_host.replace("*.", "")
            url = "https://" + ret_host + port

            navigate_to_url(driver, url, ret_host)
            if driver.page_source != empty_page:
                filename = url.replace('https://', '').replace('http://','').replace(':',"_")
                if host != ip:
                    filename += "_" + ip
                driver.save_screenshot(filename + ".png")
        
    except:
        pass
    finally:
        source = driver.page_source
        driver.close()
        driver.quit()

    if ret_err == True:
        sys.exit(1)

    return source
        

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Screenshot a website.')
    parser.add_argument('-u', dest='host', help='Website URL', required=True)
    parser.add_argument('-q', dest='query', help='URL Query', required=False)
    parser.add_argument('-p', dest='port', help='Port', required=False)
    args = parser.parse_args()

    take_screenshot(args.host, args.port, args.query)

