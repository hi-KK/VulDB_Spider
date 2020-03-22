#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Created on 2019-10-22 15:17:03
# Project: VulDB_Spider
# Author: KEYONE @ https://github.com/hi-KK

from pyspider.libs.base_handler import *

Headers2 = [
    ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'),
    ('Accept-Encoding', 'gzip, deflate'),
    ('Accept-Language', 'zh-CN,zh;q=0.9'),
    ('Connection', 'keep-alive'),
    ('Cookie', '自填'),
    ('Host', 'www.cnnvd.org.cn'),
    ('Upgrade-Insecure-Requests', '1'),
    ('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.87 Safari/537.36')
]

class Handler(BaseHandler):
    crawl_config = {
        "headers": {
            "User-Agent": "BaiDuSpider", #配置用户代理，模拟百度蜘蛛
        }
    }

    @every(minutes=24 * 60)
    def on_start(self):
        #此处输入总页数，懒得搞下一页了
        for i in range(1,13447):
            url='http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=%s' %str(i)
            
            self.crawl(url, callback=self.index_page, headers=Headers2)

    @config(age=10 * 24 * 60 * 60)
    def index_page(self, response):
        
        for each in response.doc('div.fl > a[href^="http"]').items():
            self.crawl(each.attr.href, callback=self.detail_page, headers=Headers2)

            
            
    @config(priority=2)
    def detail_page(self, response):
        
        cnnvd_title = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > h2').text()
        
        #cnnvd_id = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(1)').text()
        
        cnnvd_level = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(2) > a').text()
        
        cve_id = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(3) > a').text()        
        vulnerable_type = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(4) > a').text()
        upload_time = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(5) > a').text()
        threat_type = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(6) > a').text()

        update = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div.detail_xq.w770 > ul > li:nth-child(7) > a').text()
        vulnerable_detail = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div:nth-child(3)').text()
        
        vulnerable_notice = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div:nth-child(4)').text()
        
        reference_url = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div:nth-child(5)').text()
        
        patch = response.doc('body > div.container.m_t_10 > div > div.fl.w770 > div:nth-child(9)').text()
        
        return {
            "url": response.url,
            "cnnvd_title": cnnvd_title,
            #"cnnvd_id": cnnvd_title,
            "cnnvd_level": cnnvd_level,
            "cve_id": cve_id,
            "vulnerable_type": vulnerable_type,
            "upload_time": upload_time,
            "threat_type": threat_type,
            "update": update,
            "vulnerable_detail": vulnerable_detail,
            "vulnerable_notice": vulnerable_notice,
            "reference_url": reference_url,
            "patch": patch
        
            
        }
