import p.config as CONF
from elasticsearch import Elasticsearch
import redis
import json
import datetime
import time
from collections import Counter
import hashlib


class Eser(object):
    def __init__(self):
        self.es = Elasticsearch([CONF.ES_CONN_STR], http_auth=(CONF.ES_USER, CONF.ES_PW))
        # self.es = Elasticsearch([CONF.ES_CONN_STR])

    def term(self, term_list):
        new_l = []
        for termd in term_list:
            data = {}
            data["term"] = termd
            new_l.append(data)
        return new_l

    def match(self, match_list):
        new_l = []
        for matchd in match_list:
            data = {}
            data["match"] = matchd
            new_l.append(data)
        return new_l

    def range(self, range_list):
        new_l = []
        for ranged in range_list:
            data = {}
            data["range"] = ranged
            new_l.append(data)
        return new_l


    def filter_body(self, req_data, page, limit):
        """
        计算data的MD5 并到redis查询是否有该 MD5
        存在 返回redis数据
        不存在 es查询 并将结果存储redis 返回数据
        """
        if req_data != {}:
            query_data = {
                "query":{"bool": {}},
                "size":limit,
                "from":page*limit,
                "aggs": {
                    "src_domain": {"terms": {"field": "Used_by_ES_src.source_endpoint_domain"}},
                    "src_ip": {"terms": {"field": "Used_by_ES_src.source_endpoint_ip"}},
                    "src_load": {"terms": {"field": "Used_by_ES_src.source_load_md5"}},
                    "dst_domain": {"terms": {"field": "Used_by_ES_dst.purpose_endpoint_domain"}},
                    "dst_ip": {"terms": {"field": "Used_by_ES_dst.purpose_endpoint_ip"}},
                    "dst_load": {"terms": {"field": "Used_by_ES_dst.purpose_load_md5"}}
                }
            }
            req_data = json.loads(req_data)
            data = req_data.get("data", {})
            must_l = data.get("must", [])
            should_l = data.get("should", [])
            filter_l = data.get("filter",[])
            wildcard = data.get("wildcard", {})
            if filter_l:
                query_data["query"]["bool"]["filter"] = self.range(filter_l)
            if must_l:
                query_data["query"]["bool"]["must"] = self.match(must_l)
            if should_l:
                query_data["query"]["bool"]["should"] = self.term(should_l)
            if wildcard != {}:
                query_data["query"]["wildcard"] = wildcard
            query_sql = json.dumps(query_data)
            ts_index = req_data.get("ts", [])
            type_index = req_data.get("types", [])
            index = [y+x for y in type_index for x in ts_index]
            return index, query_sql
        else:
            ts_index = req_data.get("ts", [])
            type_index = req_data.get("types", [])
            index = [y+x for y in type_index for x in ts_index]
            query_data = {"query":{"match_all":{}}}
            query_sql = json.dumps(query_data)
            return index, query_sql

    def search_body(self, req_data, page, limit):
        """
        计算data的MD5 并到redis查询是否有该 MD5
        存在 返回redis数据
        不存在 es查询 并将结果存储redis 返回数据
        """
        if req_data != {}:
            query_data = {
                "query":{"bool": {}},
                "size":limit,
                "from":page*limit
            }
            req_data = json.loads(req_data)
            data = req_data.get("data", {})
            must_l = data.get("must", [])
            should_l = data.get("should", [])
            filter_l = data.get("filter",[])
            wildcard = data.get("wildcard", {})
            if filter_l:
                query_data["query"]["bool"]["filter"] = self.range(filter_l)
            if must_l:
                query_data["query"]["bool"]["must"] = self.match(must_l)
            if should_l:
                query_data["query"]["bool"]["should"] = self.term(should_l)
            if wildcard != {}:
                query_data["query"]["wildcard"] = wildcard
            query_sql = json.dumps(query_data)
            ts_index = req_data.get("ts", [])
            type_index = req_data.get("types", [])
            index = [y+x for y in type_index for x in ts_index]
            return index, query_sql
        else:
            ts_index = req_data.get("ts", [])
            type_index = req_data.get("types", [])
            index = [y+x for y in type_index for x in ts_index]
            query_data = {"query":{"match_all":{}}}
            query_sql = json.dumps(query_data)
            return index, query_sql

    def search_es(self, index, body, limit):
        """
        查询es数据
        """
        indexs = set(index)
        num = 0
        es_l = []
        data = {}
        src_domian = []
        src_ip = []
        src_load = []
        dst_domain = []
        dst_ip = []
        dst_load = []
        for index in indexs:
            print(index, body)
            result = self.es.search(index=index, body=body)
            aggs = result.get("aggregations", {})
            if aggs != {}:
                src_domian += aggs.get("src_domain").get("buckets",[])
                src_ip += aggs.get("src_ip").get("buckets",[])
                src_load += aggs.get("src_load").get("buckets",[])
                dst_domain += aggs.get("dst_domain").get("buckets",[])
                dst_ip += aggs.get("dst_ip").get("buckets",[])
                dst_load += aggs.get("dst_load").get("buckets",[])
            data = result.get("hits")
            num += data.pop("total")
            es_l += data.pop("hits")
        data["src_domain"] = self.null_filter(src_domian)
        data["src_ip"] = self.null_filter(src_ip)
        data["src_load"] = self.null_filter(src_load)
        data["dst_domain"] = self.null_filter(dst_domain)
        data["dst_ip"] = self.null_filter(dst_ip)
        data["dst_load"] = self.null_filter(dst_load)
        data["total"] = num
        data["data"] = es_l[:limit]
        print(body)
        for es in es_l:
            sponsor_time = es["_source"]["threat_info"]["sponsor_time"]
            if es.get("_source").get("type").startswith('PTD', 0, 3):
                es["_source"]["threat_info"]["sponsor_time"] = sponsor_time
            elif es.get("_source").get("type").startswith('IEP', 0, 3):
                es["_source"]["threat_info"]["sponsor_time"] = \
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(sponsor_time)))
        return data


    def table_body(self, req_data):
        req_data = json.loads(req_data)
        if req_data != {}:
            query_data = {
                "query":{"bool": {}},
                "aggs": {},
                "size": CONF.REDIS_LIMIT,
                "from": 0
            }
            arg = req_data.pop("arg")
            md5 = hashlib.md5(json.dumps(req_data).encode("utf-8")).hexdigest()
            if arg["filters"]["ip"] == [] or arg["filters"]["domain"] == [] or arg["filters"]["payloads"] == []:
                data = req_data.get("data", {})
                must_l = data.get("must", [])
                should_l = data.get("should", [])
                filter_l = data.get("filter",[])
                wildcard = data.get("wildcard", {})
                if filter_l:
                    query_data["query"]["bool"]["filter"] = self.range(filter_l)
                if must_l:
                    query_data["query"]["bool"]["must"] = self.match(must_l)
                if should_l:
                    query_data["query"]["bool"]["should"] = self.term(should_l)
                if wildcard != {}:
                    query_data["query"]["wildcard"] = wildcard
                query_sql = json.dumps(query_data)
                ts_index = req_data.get("ts", [])
                type_index = req_data.get("types", [])
                index = [y+x for y in type_index for x in ts_index]
                return index, query_sql, arg, md5
            else:
                ips = arg["filters"].get("ip", [])
                domains = arg["filters"].get("domain", [])
                loads = arg["filters"].get("payloads", [])
                ip_l, domain_l, load_l = [], [], []
                for ip in ips:
                    src, dst = {}, {}
                    src["Used_by_ES_src.source_endpoint_ip"] = ip
                    ip_l.append(src)
                    dst["Used_by_ES_dst.purpose_endpoint_ip"] = ip
                    ip_l.append(dst)
                    query_data["aggs"]["src_ip"] = {"terms": {"field": "Used_by_ES_src.source_endpoint_ip"}}
                    query_data["aggs"]["dst_ip"] = {"terms": {"field": "Used_by_ES_dst.purpose_endpoint_ip"}}
                if ip_l:
                    query_data["query"]["bool"]["should"] = self.term(ip_l)
                for domain in domains:
                    src, dst = {}, {}
                    src["Used_by_ES_src.source_endpoint_domain"] = domain
                    domain_l.append(src)
                    dst["Used_by_ES_dst.purpose_endpoint_domain"] = domain
                    domain_l.append(dst)
                    query_data["aggs"]["src_domain"] = {"terms": {"field": "Used_by_ES_src.source_endpoint_domain"}}
                    query_data["aggs"]["dst_domain"] = {"terms": {"field": "Used_by_ES_dst.purpose_endpoint_domain"}}
                if domain_l:
                    query_data["query"]["bool"]["should"] = self.term(domain_l)
                for load in loads:
                    src, dst = {}, {}
                    src["Used_by_ES_src.source_load_md5"] = load
                    load_l.append(src)
                    dst["Used_by_ES_dst.purpose_load_md5"] = load
                    load_l.append(dst)
                    query_data["aggs"]["src_load"] = {"terms": {"field": "Used_by_ES_src.source_load_md5"}}
                    query_data["aggs"]["dst_load"] = {"terms": {"field": "Used_by_ES_dst.purpose_load_md5"}}
                if load_l:
                    query_data["query"]["bool"]["should"] = self.term(load_l)
                query_sql = json.dumps(query_data)
                ts_index = req_data.get("ts", [])
                type_index = req_data.get("types", [])
                index = [y+x for y in type_index for x in ts_index]
                return index, query_sql, arg, md5

    def table_es(self, index, body, page, limit):
        """
        查询es数据
        """
        indexs = set(index)
        num = 0
        es_l = []
        data = {}
        src_domian = []
        src_ip = []
        src_load = []
        dst_domain = []
        dst_ip = []
        dst_load = []
        for index in indexs:
            result = self.es.search(index=index, body=body)
            aggs = result.get("aggregations", {})
            if aggs != {}:
                if aggs.get("src_domain", {}) != {}:
                    src_domian += aggs.get("src_domain").get("buckets",[])
                elif aggs.get("src_ip", {}) != {}:
                    src_ip += aggs.get("src_ip").get("buckets",[])
                elif aggs.get("src_load", {}) != {}:
                    src_load += aggs.get("src_load").get("buckets",[])
                elif aggs.get("dst_domain", {}) != {}:
                    dst_domain += aggs.get("dst_domain").get("buckets",[])
                elif aggs.get("dst_ip", {}) != {}:
                    dst_ip += aggs.get("dst_ip").get("buckets",[])
                elif aggs.get("dst_load", {}) != {}:
                    dst_load += aggs.get("dst_load").get("buckets",[])
            data = result.get("hits")
            num += data.pop("total")
            es_l += data.pop("hits")
        data["src_domain"] = self.null_filter(src_domian)
        data["src_ip"] = self.null_filter(src_ip)
        data["src_load"] = self.null_filter(src_load)
        data["dst_domain"] = self.null_filter(dst_domain)
        data["dst_ip"] = self.null_filter(dst_ip)
        data["dst_load"] = self.null_filter(dst_load)
        data["total"] = num
        data["data"] = es_l[:CONF.REDIS_LIMIT]
        for es in es_l:
            sponsor_time = es["_source"]["threat_info"]["sponsor_time"]
            if es.get("_source").get("type").startswith('PTD', 0, 3):
                es["_source"]["threat_info"]["sponsor_time"] = sponsor_time
            elif es.get("_source").get("type").startswith('IEP', 0, 3):
                es["_source"]["threat_info"]["sponsor_time"] = \
                    time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(sponsor_time)))
        return data


    def null_filter(self, infos):
        new_l = []
        for info in infos:
            if info.get("key") != "":
                new_l.append(info)
            else:
                continue
        return new_l

    def show_data(self, es_data):
        res = []
        for item in es_data.get("data", {}):
            tmp_dict = {
                "logid": item.get("_id"), "category": item.get("_type"),
                "behavior_waring": item.get("_source").get("threat_info").get("event_type").get("first_type"),
                "behavior_waring_type": "疑似",
                "start_time": item.get("_source").get("threat_info").get("sponsor_time"),
                "attack_source": item.get("_source").get("Used_by_ES_src").get("source_endpoint_domain", "") + ","
                                 + item.get("_source").get("Used_by_ES_src").get("source_endpoint_ip", ""),
                "attack_source_type": "疑似",
                "victim": item["_source"]["Used_by_ES_dst"]["purpose_endpoint_ip"],
                "victim_type": "疑似失陷", "show_flag": True,
                # TODO 左侧列表的返回值中的载荷对应如下的哪个字段？
                "target_load": (item["_source"]["Used_by_ES_dst"]["purpose_load_filename"],),
                "target_load_md5": item["_source"]["Used_by_ES_dst"]["purpose_load_md5"],
                "target_load_type": "疑似",
                "soure_load": item["_source"]["Used_by_ES_src"]["source_load_filename"],
                "soure_load_md5": item["_source"]["Used_by_ES_src"]["source_load_md5"], "e_load_type": "疑似",
                "detec_source_id": item.get("_source").get("threat_info")["extend_details"]["detector_info"][0][
                    "detect_pro_id"]
            }
            res.append(tmp_dict)
        return res, es_data["total"]


if __name__ == "__main__":
    es = Eser(CONF.ES_CONN_STR, CONF.user_info)
    es.make_body(CONF.user_info)
