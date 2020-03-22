#!/usr/bin/env python3
# -*- encoding: utf-8 -*-
# Created on 2020-03-17 15:33:47
# Project: VulDB_Spider
# Author: KEYONE @ https://github.com/hi-KK

from pyspider.libs.base_handler import *


class Handler(BaseHandler):
    crawl_config = {
    }

    @every(minutes=24 * 60)
    def on_start(self):
        self.crawl('https://nvd.nist.gov/vuln/full-listing/', callback=self.index_page)

    @config(age=10 * 24 * 60 * 60)
    def index_page(self, response): #获取nvd按年月进行分类的链接
        for each in response.doc('#page-content a[href^="http"]').items():
            self.crawl(each.attr.href, callback=self.index2_page)
            
    def index2_page(self, response):#获取所属分类的具体CVE链接,修改了css选择器排除了最后一个不是cve的链接
        for each in response.doc('#page-content div.row a[href^="http"]').items():
            self.crawl(each.attr.href, callback=self.detail_page)
        
    @config(priority=2)
    def detail_page(self, response):#解析CVE链接页面的字段
        items = response.etree.xpath('//div[@class="col-lg-9 col-md-7 col-sm-12"]')
        for item in items:#只取NVD的数据，CNA暂时不要
            
            vuln_description = ''.join(item.xpath('//p[@data-testid="vuln-description"]/text()')).strip()
            
            
            cvss3_nvd_base_score = ''.join(item.xpath('//*[@data-testid="vuln-cvss3-panel-score"]/text()')).strip()#显式数据提取
            #cvssv3_base_score = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-base-score"]/text()')).strip()#隐式数据提取
            #cvssv3_base_score_severity = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-base-score-severity"]/text()')).strip()#隐式数据提取
            
            cvss3_nvd_vector = ''.join(item.xpath('//*[@data-testid="vuln-cvss3-nist-vector"]/text()')).strip()#显式数据提取
            #cvssv3_vector = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-vector"]/text()')).strip()#隐式数据提取
            
            #cvssv3_impact_score = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-impact-score"]/text()')).strip()#隐式数据提取
            #cvssv3_exploitability_score = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-exploitability-score"]/text()')).strip()#隐式数据提取
            #cvssv3_attack_vector = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-av"]/text()')).strip()#隐式数据提取
            #cvssv3_attack_complexity = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-ac"]/text()')).strip()#隐式数据提取
            #cvssv3_privileges_required = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-pr"]/text()')).strip()#隐式数据提取
            #cvssv3_user_interaction = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-ui"]/text()')).strip()#隐式数据提取
            #cvssv3_scope = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-s"]/text()')).strip()#隐式数据提取
            #cvssv3_confidentiality = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-c"]/text()')).strip()#隐式数据提取
            #cvssv3_integrity = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-i"]/text()')).strip()#隐式数据提取
            #cvssv3_availability = ''.join(item.xpath('//span[@data-testid="vuln-cvssv3-a"]/text()')).strip()#隐式数据提取
            
     
            cvss2_nvd_base_score = ''.join(item.xpath('//*[@id="p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilityDetail_VulnFormView_Cvss2CalculatorAnchor"]/text()')).strip()#显式数据提取
            #cvssv2_base_score = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-base-score"]/text()')).strip()#隐式数据提取
            #cvssv2_base_score_severity = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-base-score-severity"]/text()')).strip()#隐式数据提取
            
            cvss2_nvd_vector = ''.join(item.xpath('//*[@data-testid="vuln-cvss2-panel-vector"]/text()')).strip()#显式数据提取
            #cvssv2_vector = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-vector"]/text()')).strip()#隐式数据提取
            
            #cvssv2_impact_score = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-impact-score"]/text()')).strip()#隐式数据提取
            #cvssv2_exploitability_score = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-exploitability-score"]/text()')).strip()#隐式数据提取
            #cvssv2_attack_vector = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-av"]/text()')).strip()#隐式数据提取
            #cvssv2_attack_complexity = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-ac"]/text()')).strip()#隐式数据提取
            #cvssv2_privileges_required = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-pr"]/text()')).strip()#隐式数据提取
            #cvssv2_user_interaction = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-ui"]/text()')).strip()#隐式数据提取
            #cvssv2_scope = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-s"]/text()')).strip()#隐式数据提取
            #cvssv2_confidentiality = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-c"]/text()')).strip()#隐式数据提取
            #cvssv2_integrity = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-i"]/text()')).strip()#隐式数据提取
            #cvssv2_availability = ''.join(item.xpath('//span[@data-testid="vuln-cvssv2-a"]/text()')).strip()#隐式数据提取            
            
                          
            references ='\n'.join(item.xpath('//*[@data-testid="vuln-hyperlinks-table"]//a/text()')).strip()
            cwe_id = '\n'.join(item.xpath('//*[@data-testid="vuln-CWEs-link-0"]/a/text()')).strip()
            cwe_name = '\n'.join(item.xpath('//*[@data-testid="vuln-CWEs-link-0"]/text()')).strip()
            cpe = '\n'.join(item.xpath('//*[@data-testid="vuln-configurations-container"]//b[@data-testid]/text()')).strip() #本页xpath灵魂表达式
            
                                                
            
             
        return {
            
            
            "vuln_description": vuln_description,
            "cvss3_nvd_base_score": cvss3_nvd_base_score,
            #"cvssv3_base_score": cvssv3_base_score,
            #"cvssv3_base_score_severity": cvssv3_base_score_severity,
            "cvss3_nvd_vector": cvss3_nvd_vector,
            #"cvssv3_vector": cvssv3_vector,
            # "cvssv3_impact_score": cvssv3_impact_score,
            # "cvssv3_exploitability_score": cvssv3_exploitability_score,
            # "cvssv3_attack_vector": cvssv3_attack_vector,
            # "cvssv3_attack_complexity": cvssv3_attack_complexity,
            # "cvssv3_privileges_required": cvssv3_privileges_required,
            # "cvssv3_user_interaction": cvssv3_user_interaction,
            # "cvssv3_scope": cvssv3_scope,
            # "cvssv3_confidentiality": cvssv3_confidentiality,
            # "cvssv3_integrity": cvssv3_integrity,
            # "cvssv3_availability": cvssv3_availability,

            "cvss2_nvd_base_score": cvss2_nvd_base_score,
            # "cvssv2_base_score": cvssv2_base_score,
            # "cvssv2_base_score_severity": cvssv2_base_score_severity,
            "cvss2_nvd_vector": cvss2_nvd_vector,
            # "cvssv2_vector": cvssv2_vector,
            # "cvssv2_impact_score": cvssv2_impact_score,
            # "cvssv2_exploitability_score": cvssv2_exploitability_score,
            # "cvssv2_attack_vector": cvssv2_attack_vector,
            # "cvssv2_attack_complexity": cvssv2_attack_complexity,
            # "cvssv2_privileges_required": cvssv2_privileges_required,
            # "cvssv2_user_interaction": cvssv2_user_interaction,
            # "cvssv2_scope": cvssv2_scope,
            # "cvssv2_confidentiality": cvssv2_confidentiality,
            # "cvssv2_integrity": cvssv2_integrity,
            # "cvssv2_availability": cvssv2_availability,            
            
            "references": references,
            "cwe_id": cwe_id,
            "cwe_name": cwe_name,
            "cpe": cpe,
            #"title": response.doc('title').text(),
        }