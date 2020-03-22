#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Created on 2019-10-29 15:23:08
# Project: VulDB_Spider
# Author: KEYONE @ https://github.com/hi-KK
# 
# 此版本未完全解决反爬虫机制，可供参考

# 参考https://github.com/RyQcan/cnvd_requests_spider/blob/master/cnvd2.py
# 
# sudo python3 -m pip install --upgrade pip
# sudo python3 -m pip install --upgrade setuptools
# sudo python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ requests
# sudo python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ selenium
# sudo python3 -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple/ sqlalchemy

# chromedriver
# 下载：https://npm.taobao.org/mirrors/chromedriver/70.0.3538.16/
# 移动：sudo mv chromedriver  /usr/local/bin/chromedriver
# 执行权限：sudo chmod u+x,o+x   /usr/local/bin/chromedriver
# 检验：chromedriver --version   


from pyspider.libs.base_handler import *
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from lxml import etree
import ast
import time
import random
import requests
import sys
reload(sys)
sys.setdefaultencoding('utf8')
#Header = [
#    ('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.16 Safari/537.36')
#]


class Handler(BaseHandler):
    crawl_config = {

    }
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.16 Safari/537.36"}
        # 如果从某处断线了，可以更改起始的url地址
        self.start_url = "http://www.cnvd.org.cn/flaw/list.htm"
        self.count = 0
        self.cookies = self.get_cookies()
        
    def get_cookies(self):
        chrome_options = Options()
        # 加上下面两行，解决报错
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        
        driver = webdriver.Chrome(chrome_options=chrome_options)
        driver.get("https://www.cnvd.org.cn/flaw/list.htm")
        cj = driver.get_cookies()
        cookie = ''
        for c in cj:
            cookie += "'"+c['name'] + "':'" + c['value'] + "',"
        cookie = ast.literal_eval('{'+cookie+'}')
        time.sleep(2)
        driver.quit()
        
        return cookie
    
    def parse(self, url):
        time.sleep(random.randint(1, 2))
        self.count += 1
        print(self.count)
        if(self.count == 5):
            self.cookies = self.get_cookies()
            self.count = 0
        html = requests.get(url, headers=self.headers,cookies=self.cookies).content.decode()
        html = etree.HTML(html)
        return html
    
    @every(minutes=24 * 60)
    def on_start(self):
        
        #Header['cookie']=self.get_cookies()
        self.cookies = self.get_cookies()
        
        for i in range(0,128800,100): #每次 i 递增100位
            
            url='https://www.cnvd.org.cn/flaw/list.htm?%s' % str(i) #这样是为了能进行循环获取链接，因为CNVD要post数据才能获取下一页

            #使用POST方法，测试过cnvd前端是用post方法才能显示下一页
            self.crawl(url, method='POST', data={'max': 100, 'offset': str(i)}, callback=self.index_page,headers=self.headers, cookies=self.cookies)
                    
        
        
#1、response.json用于解析json数据
#2、response.doc返回的是PyQuery对象
#3、response.etree返回的是lxml对象
#4、response.text返回的是unicode文本
#5、response.content返回的是字节码        

    @config(age=10 * 24 * 60 * 60)
    def index_page(self, response):
        
        
        #使用pyspider的response.etree來引入xpath选择器，获取所有链接        

        list_url = response.etree.xpath("//div[@id='flawList']/tbody/tr/td[1]/a/@href")
        if list_url is None:
            list_url = response.etree.xpath("//div[@class='blkContainerPblk']//table[@class='tlist']/tbody/tr/td[1]/a/@href")
        for url in list_url:
            url = "http://www.cnvd.org.cn"+url
            self.detail_page(url)
            #self.crawl(url, callback=self.detail_page, headers=Header)
            

    @config(priority=2)
    def detail_page(self, url):
        #time.sleep(random.randint(1, 2))
        html = self.parse(url)
        item = {}
        #使用pyspider的response.etree來引入xpath选择器
        # 获取漏洞标题
        item["cn_title"] = html.xpath(
            "//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")
        if item["cn_title"]:
            item["cn_title"] = html.xpath("//div[@class='blkContainerPblk']/div[@class='blkContainerSblk']/h1/text()")[
                0].strip()
        else:
            item["cn_title"] = 'Null'

        # 获取漏洞公开日期，加 u 解决 xpath 中的中文编码问题
        item["date"] = ''.join(html.xpath(u"//td[text()='公开日期']/following-sibling::td[1]/text()")).strip()

        # 获取漏洞危害级别
        item["hazard_level"] = html.xpath(
            u"//td[text()='危害级别']/following-sibling::td[1]/text()")
        if item["hazard_level"]:
            item["hazard_level"] = "".join(
                [i.replace("(", "").replace(")", "").strip() for i in item["hazard_level"]])
        else:
            item["hazard_level"] = 'Null'

        # 获取漏洞影响的产品
        item["cn_impact"] = html.xpath(
            u"//td[text()='影响产品']/following-sibling::td[1]/text()")
        if item["cn_impact"]:
            item["cn_impact"] = "   ;   ".join(
                [i.strip() for i in item["cn_impact"]])
        else:
            item["cn_impact"] = 'Null'

        # 获取cnvd id
        item["cnvd_id"] = html.xpath(
            "//td[text()='CNVD-ID']/following-sibling::td[1]/text()")
        if item["cnvd_id"]:
            item["cnvd_id"] = "".join(
                [i.strip() for i in item["cnvd_id"]])
        else:
            item["cnvd_id"] = 'Null'

        # 获取cve id
        item["cve_id"] = html.xpath(
            "//td[text()='CVE ID']/following-sibling::td[1]//text()")
        if item["cve_id"]:
            item["cve_id"] = "".join(
                [i.strip() for i in item["cve_id"]])
        else:
            item["cve_id"] = 'Null'

        # 获取漏洞类型
        item["cn_types"] = html.xpath(
            u"//td[text()='漏洞类型']/following-sibling::td[1]//text()")
        if item["cn_types"]:
            item["cn_types"] = "".join(
                [i.strip() for i in item["cn_types"]])
        else:
            item["cn_types"] = 'Null'

        # 获取漏洞描述
        item["cn_describe"] = html.xpath(
            u"//td[text()='漏洞描述']/following-sibling::td[1]//text()")
        if item["cn_describe"]:
            item["cn_describe"] = "".join(
                [i.strip() for i in item["cn_describe"]]).replace("\u200b", "")
        else:
            item["cn_describe"] = 'Null'

        # 获取漏洞的参考链接
        item["cn_reference"] = html.xpath(
            u"//td[text()='参考链接']/following-sibling::td[1]/a/@href")
        if item["cn_reference"]:
            item["cn_reference"] = item["cn_reference"][0].replace('\r', '')
        else:
            item["cn_reference"] = 'Null'

        # 获取漏洞的解决方案
        item["cn_solution"] = html.xpath(
            u"//td[text()='漏洞解决方案']/following-sibling::td[1]//text()")
        if item["cn_solution"]:
            item["cn_solution"] = "".join(
                [i.strip() for i in item["cn_solution"]])
        else:
            item["cn_solution"] = 'Null'

        # 获取漏洞厂商补丁
        item["cn_patch"] = html.xpath(
            u"//td[text()='厂商补丁']/following-sibling::td[1]/a")
        if item["cn_patch"]:
            for i in item["cn_patch"]:
                list = []
                list.append(i.xpath("./text()")[0])
                list.append("http://www.cnvd.org.cn" + i.xpath("./@href")[0])
                item["cn_patch"] = list[0] + ':' + list[1]
        else:
            item["cn_patch"] = 'Null'
        
               
        return {
            #"url": response.url,
            #"cnvd_title":response.doc('h1').text(),
            
            "cnvd_id":item["cnvd_id"],
            "cnvd_date":item["date"],
            "cnvd_level":item["hazard_level"],
            "cnvd_product":item["cn_impact"],
            "cnvd_cve_id":item["cve_id"],
            "cnvd_type": item["cn_types"],
            "cnvd_description":item["cn_describe"],
            "cnvd_reference":item["cn_reference"],
            "cnvd_solution":item["cn_solution"],
            "cnvd_patch":item["cn_patch"],
        }