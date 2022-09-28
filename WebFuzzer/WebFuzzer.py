import sys
from urllib.parse import parse_qs, urlparse
from xml import dom
import requests
import argparse, sys
import pycurl
from bs4 import BeautifulSoup
from utils.WebParser import HTMLParser
from utils.GrammerMiner import GenerateGrammar
import gramfuzz
import re
import io


webparser=argparse.ArgumentParser()

webparser.add_argument('--url', help='Website URL', required= True, type=str)
webparser.add_argument('--noofrequests', help='Number of requests, default value 20', type=int, default=20)
webparser.add_argument('--filtercode', help='Filter the status code', type = int)
webparser.add_argument('--attack', help='Type of attack: SQLI/XSS', required=True, type=str)
webparser.add_argument('--method', help='Type of request: GET/POST', required=True, type=str)
arguments=webparser.parse_args()

 
class WebFuzzer():
    def __init__(self, reqType, baseUrl):
        self.reqType = reqType
        self.baseUrl = baseUrl
        self.htmlParser = HTMLParser()
        self.parseWebPage()
        self.grammaer = GenerateGrammar(self.htmlParser, arguments.attack)
        self.gramUrl = self.getGramUrl()
        webdomain = urlparse(self.baseUrl).netloc
        self.updatedUrl = webdomain + "/" + self.htmlParser.action
    
    def getGramUrl(self):
        gramFuzzer = gramfuzz.GramFuzzer()
        gramFuzzer.load_grammar("GeneratedGrammar.py")
        urls = gramFuzzer.gen(cat="url", num=arguments.noofrequests)
        return [url.decode() for url in urls]

    def parseWebPage(self):
        htmlText = requests.get(self.baseUrl).text
        bsoup = BeautifulSoup(htmlText, "lxml")
        form = bsoup.body.find("form")
        self.htmlParser.parseForm(form)

    def output(self):
        print("**********************************************************")
        print("\tWebFuzzer Result Summary\t")
        print("**********************************************************")
        print("Target URL: " + self.updatedUrl)
        print("Type of attack " + arguments.attack )
        print("Request Type: " + self.reqType)
        print("Total Requests: "+ str(len(self.gramUrl)))
        print("**********************************************************")
        if arguments.attack == "XSS":
            print("XSS Result\t\tRequest Parameters")
        elif arguments.attack == "SQLI":
            print("Response\t\tRequest Parameters")

    def sqlInjectionAttack(self):
        for url in self.gramUrl:
            curl = pycurl.Curl()
            reqParams = url.split("?")[1]
            if self.reqType == "GET":
                fullUrl = self.updatedUrl +"?"+ reqParams
                curl.setopt(curl.URL, fullUrl)
                curl.setopt(pycurl.HTTPGET, 1)
            elif self.reqType == "POST":
                curl.setopt(curl.URL, self.updatedUrl)
                curl.setopt(pycurl.POST, 1)
                curl.setopt(pycurl.POSTFIELDS, reqParams)
            curl.setopt(pycurl.WRITEFUNCTION, lambda x: None)
            curl.perform()
            output = str(parse_qs(reqParams))
            responseCode = curl.getinfo(pycurl.HTTP_CODE)
            if arguments.filtercode != responseCode:
                print(str(curl.getinfo(pycurl.HTTP_CODE)) +"\t\t"+ output)
    
    def xssAttack(self):
        for url in self.gramUrl:
            storage = io.BytesIO()
            curl = pycurl.Curl()
            reqParams = url.split("?")[2]
            if self.reqType == "GET":
                fullurl = self.updatedUrl +"&"+ reqParams
                curl.setopt(curl.URL, fullurl)
                curl.setopt(pycurl.HTTPGET, 1)
            elif self.reqType == "POST":
                curl.setopt(curl.URL, self.updatedUrl)
                curl.setopt(pycurl.POST, 1)
                curl.setopt(pycurl.POSTFIELDS, reqParams)
            curl.setopt(pycurl.WRITEFUNCTION, storage.write)
            curl.perform()
            content = storage.getvalue().decode('UTF-8')
            reqex = self.grammaer.xss_field_name + "=(.+?)&" + self.grammaer.submit_field_name
            query = re.search(reqex, reqParams)
            if query:
                val = query.group(1).strip()
                responseCode = curl.getinfo(pycurl.HTTP_CODE)
                result = "FAIL"
                if responseCode != arguments.filtercode: 
                    if val in content:
                        result = "SUCCESS"
                    print(result + "\t\t" + val)

    def run(self):
        self.output()
        if arguments.attack == "XSS":
            self.xssAttack()
        elif arguments.attack == "SQLI":
            self.sqlInjectionAttack()
        
        


webFuzz = WebFuzzer(arguments.method, arguments.url)
webFuzz.run()


#References:-
# http://localhost/mutillidae/index.php?page=login.php
# http://www.webscantest.com/login.php
# https://brokencrystals.com/api/auth/login
# http://juice-shop.herokuapp.com/rest/user/login
