# Author: b0yd @rwincey
# Website: securifera.com
#
# Setup:
# -------------------------------------------------
# pip install selenium
# wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
# google-chrome-stable --version 
# Vist http://chromedriver.chromium.org/downloads to identity the right version
# wget https://chromedriver.storage.googleapis.com/72.0.3626.69/chromedriver_linux64.zip
#
# Usage:
# -------------------------------------------------
# python screenshot.py -u 172.217.12.78 -p 443


import argparse
import httplib, sys
import socket
from selenium import webdriver
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
from selenium.common.exceptions import TimeoutException


def take_screenshot( host_arg, port_arg, query_arg="" ):

    try:
        host = socket.gethostbyaddr(host_arg)[0]
    except:
        host = host_arg
        pass

    options = webdriver.ChromeOptions()
    options.binary_location = '/usr/bin/google-chrome-stable'
    options.add_argument('headless')
    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--no-sandbox')
    options.add_argument('--user-agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.50 Safari/537.36"')

    driver = webdriver.Chrome('chromedriver', chrome_options=options)
    driver.set_window_size(1024, 768) # set the window size that you need
    driver.set_page_load_timeout(10)

    port = ""
    if port_arg:
        port = ":" + port_arg

    #Add query if it exists
    path = host_arg + port
    if query_arg:
        path += "/" + query_arg

    #Get the right URL
    url = "http://" + path

    #Retrieve the page
    print url
    try:
        driver.get(url)
        if driver.page_source == '<html><head></head><body></body></html>':
            url = "https://" + path
            driver.get(url)
            if driver.page_source == '<html><head></head><body></body></html>':
                driver.close()
                driver.quit()
                sys.exit(1)

        #Cleanup filename and save
        filename = url.replace('https://', '').replace('http://','').replace(':',"_")
        driver.save_screenshot(filename + "_" + host_arg + ".png")
        driver.close()
        driver.quit()
        
    except:
        pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Screenshot a website.')
    parser.add_argument('-u', dest='host', help='Website URL', required=True)
    parser.add_argument('-q', dest='query', help='URL Query', required=False)
    parser.add_argument('-p', dest='port', help='Port', required=False)
    args = parser.parse_args()

    take_screenshot(args.host, args.port, args.query)



