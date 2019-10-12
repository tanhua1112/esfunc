import copy
import json
import logging
import os
import re
import itertools

import redis
import p.config as CONF


class RedisLog:

    def __init__(self, es_data, flag):
        self.raw = es_data
        # print(f"es src data = {self.raw}")
        # 为了处理多用户情况，因此需要分别的设置前缀区分
        # redis数据库连接
        self.redis_handle = redis.Redis(host=CONF.REDIS_IP, port=CONF.REDIS_PORT,
                                        db=CONF.REDIS_DB,password=CONF.REDIS_PW)

        # 存储es查询条件后的前端所需要的结果
        self.init_res = self.parse_es(es_data)
        # 下面三个集合中的元素类型都要是str，强调这一点是因为从redis操作集合返回的集合中的元素类型都是`bytes`
        self.all_log_ids = set(self.init_res.keys())
        self.false_log_ids = copy.deepcopy(self.all_log_ids)
        self.first = False

        if flag:
            # 第一次`es`查询结果做缓存
            # 往`false`集合插入元素
            self.false_log_ids = self.false_log_ids - self._get_log_ids("true")
            self._insert_all_log_ids("false", self.false_log_ids)
            self.true_log_ids = set()
            self.first = True
        else:
            # 只要是es的查询不变，那么就需要去redis取出所有`false`集合，去修正
            # 需要去修正正确的数量
            self.false_log_ids = self.false_log_ids & self._get_log_ids("false")

            self.true_log_ids = self.all_log_ids - self.false_log_ids
        if not self.true_log_ids:
            self.true_log_ids = self._get_log_ids("true")
        # 插入数据
        self.insert_all_redis(self.init_res)

    @staticmethod
    def parse_es(es_data):
        """
        解析查询过后的es，只要前端要的字段，然后作为hash放入redis，作为缓存
        :param es_data: 查询过后的es数据
        :return: 一个字典，其中的每个item是一个字典，字典的value如下，key为logid
        {
          "logid": item0["_id"],
          "category": item0["_type"],  # PTD/IEP
          "behavior_waring": threat_info["event_type"]["first_type"],
          "behavior_waring_type": "疑似", # 等有了再改
          "start_time": threat_info["sponsor_time"],
          "attack_source": item0["_source"]["Used_by_ES_src"]["source_domain"] + "," + item0["_source"]
          ["Used_by_ES_src"]["source_ip"],
          "attack_source_type": "疑似",# 等有了再改
          "victim": item0["_source"]["Used_by_ES_dst"]["purpose_ip"],
          "victim_type": "疑似失陷",# 等有了再改
          "show_flag": True,
          "target_load":item0["_source"]["Used_by_ES_dst"]["purpose_load_filename"],
          "target_load_md5": item0["_source"]["Used_by_ES_dst"]["purpose_load_md5"],
          "target_load_type": "疑似",# 等有了再改
          "soure_load": item0["_source"]["Used_by_ES_src"]["source_load_filename"],
          "soure_load_md5": item0["_source"]["Used_by_ES_src"]["source_load_md5"],
          "e_load_type": "疑似",# 等有了再改
          "detec_source_id": threat_info["extend_details"]["detector_info"][0]["detect_pro_id"] # 检测源的uuid
        }
        """
        res = {}  # 最终的结果
        if not es_data:
            es_data = {}
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
                    "detect_pro_id"],
                "domains": [item.get("_source").get("Used_by_ES_src").get("source_endpoint_domain"),
                            item.get("_source").get("Used_by_ES_dst").get("purpose_endpoint_domain")],
                "ips": [item.get("_source").get("Used_by_ES_src").get("source_endpoint_ip"),
                        item.get("_source").get("Used_by_ES_dst").get("purpose_endpoint_ip")],
                "payloads": [item.get("_source").get("Used_by_ES_src").get("source_load_md5"),
                             item.get("_source").get("Used_by_ES_dst").get("purpose_load_md5")],
                "flag": False  # 后面的四个字段都是为了方便自用，flag字段按照前端的输入做出相应的修改，依据这个字段单独分页
            }
            # 经过标准化过后，数据类型应该有保证，就用`[]`方便一些
            res[tmp_dict.get("logid")] = tmp_dict
        return res

    def insert_all_redis(self, es_data):
        """
        :param es_data:self.init_res
        把从kafka的数据全部插进redis中，之前想的是key就是log_id,数据类型存hash
        但是这样的话处理逻辑就全部到python这端了，因此打算优化key，把value序列化之后作为字符串存进
        redis，也不知道哪个的性能更优.
        redis中的key姑且打算是把log_id,ip,domain和MD5拼接起来
        具体就是
        :return:
        """
        tasks = {}
        for log_id, data in es_data.items():
            # key就是log_id
            redis_value = json.dumps(data)
            tasks[log_id] = redis_value
        # msetnx如果key已经存在则不做修改，如果不存在才插入
        self.redis_handle.mset(tasks)
        # 默认只存储10分钟
        for log_id in es_data:
            self.redis_handle.expire(log_id, 600)

    def _get_log_ids(self, flag):
        """
        返回指定集合的所有log_id
        :param flag: 字符串 true or false
        :return: 一个集合
        """
        # 因为返回的是bytes，需要转换为str
        try:
            return {i.decode() for i in self.redis_handle.smembers(flag)}
        except AttributeError as e:
            return {}
        except Exception as e:
            return {}

    def _insert_all_log_ids(self, flag, log_ids):
        """
        把所给的log_ids插入到redis中的存放所有标志位为`flag`的集合中
        集合名只能是false和true
        :param log_ids: 一个可迭代对象
        :return:
        """
        if log_ids:
            # 不考虑多用户情况，因此不设置超时
            # 因为假如A用户对log_01做了修改，那么B用户应该也要察觉到修改
            self.redis_handle.sadd(flag, *log_ids)

    def _trans(self, data):
        """
        依据data中的数据，转换相对应id的标志位
        :param data: {
            logid: [],
            "setState":true
        }
        :return:没返回值，成功或失败问题都不大
        """
        log_ids = data.get("logid")
        # 判断这些log_id该去哪个集合, 初始默认都应该在`false`集合中
        # 如果set_state = "true"则从`false`集合转向`true`集合
        # 如果set_state = "false"则从`true`集合转向`false`集合
        set_state = "true" if data.get("setState") else "false"

        for log_id in log_ids:
            # 在redis中完成两个集合元素的迁徙
            self._trans_logs_states(log_id, set_state)

            # 再把self.init_res中的每一项的`flag`字段设置为 相应的数据
            try:
                flag_value = data.get("setState")
                self.init_res.get(log_id)["flag"] = flag_value
            except KeyError as e:
                continue
        # 相应的变更内部状态
        if set_state == "true":
            # 把他们`false`除名
            self.false_log_ids = self.false_log_ids - set(log_ids)
            # 把他们加到`true`
            self.true_log_ids.update(set(log_ids))
        else:  # "false" :  "true" == > "false"
            # 把他们从`true`除名
            self.true_log_ids = self.true_log_ids - set(log_ids)
            # 把他们加到`false`
            self.false_log_ids.update(set(log_ids))

    # 依据前端的输入，把redis中相应的集合数据做变更
    def _trans_logs_states(self, log_id, expected_value):
        """
        把标志位转换，即把一个log_id从false集合移动到true集合，反之也亦然
        :param log_id: log_id
        :param expected_value: 该log_id期望得到的值，如果当前log_id在`false`集合中,那么expected_value应该为`True`
        :return:
        """
        # 利用expected_value的值，去判断集合名字
        src_set_name = "false" if expected_value =="true" else "true"
        self.redis_handle.smove(src_set_name, expected_value, log_id)

    def _filter(self, query_dict, src_dict):
        """
        确定redis中的key的过程在这里完成，不采用之前的scan方法
        :param query_dict:过滤的条件
        {
            "ip":[],
            "domain":[],
            "payloads":[]
        }
        :param src_dict:就是self.init_res
        :return:
        """
        # 就是去init_res中找到相对应的log_id
        # 内部或，外部与
        ips = set()
        domains = set()
        payloads = set()
        # 解决如果三个key不同时存在的情况
        keys = query_dict.keys()
        # 最后的结果
        res = set()
        for log_id, res_dict in src_dict.items():
            if "ip" in keys:
                for ip in query_dict.get("ip"):  # 查找ip对应的key
                    if ip in res_dict.get("ips"):
                        ips.add(log_id)
            if "domain" in keys:
                for domain in query_dict.get("domain"):  # 查找ip对应的key
                    if domain in res_dict.get("domains"):
                        domains.add(log_id)
            if "payloads" in keys:
                for payload in query_dict.get("payloads"):  # 查找ip对应的key
                    if payload in res_dict.get("payloads"):
                        payloads.add(log_id)
        if not ips and not domains and not payloads:
            return set()
        for i in [ips, domains, payloads]:
            if not i:
                continue
            if i:
                if not res:
                    res = i
                    continue
                if res:
                    res = res.intersection(i)
        return res

    @staticmethod
    def _match(keyword, src_dict):
        """
        去redis中的domains,ips和payloads字段下利用search去找keyword!
        NOTE:估计会很慢.O(N^2) orz....
        :param keyword:作为pattern
        :return: [] Or ids
        """
        ids = set()
        for log_id, res_dict in src_dict.items():
            all_match_items = itertools.chain(res_dict.get("ips"), res_dict.get("domains"), res_dict.get("payloads"))
            for item in all_match_items:
                if re.search(keyword, item):
                    ids.add(log_id)
                    break
        return ids

    def handle_redis_value(self, log_ids):
        """
        利用mget命令查询结果，然后处理(反序列化)之后返回
        :param log_ids:
        :return:
        """
        if not log_ids:
            return []
        try:
            tmp_list = self.redis_handle.mget(list(log_ids))
            # 有短路机制，即使tmp_list= []也不会有问题
            if tmp_list and tmp_list[0] is not None:
                return [json.loads(i) for i in tmp_list if i is not None]

            else:
                return []
        except Exception as e:
            return []

    @staticmethod
    def paginate(all_res, pagination):
        """
        把中间那一坨分页返回去
        >>> c = [1,2,3,4]
        >>> c[1:4]
        [2, 3, 4]
        >>> c[1:55]
        [2, 3, 4]
        所以我就不需要判断越界的问题了
        :param all_res:待分页的内容，是一个列表
        :param pagination:{"currentPage":1, "pageSize":10}
        :return:
        """
        if not all_res:
            return []
        # 假如是第一页,那么current_page=1
        current_page = pagination.get("currentPage")
        page_size = pagination.get("pageSize")
        return all_res[(current_page - 1) * page_size: current_page * page_size]

    # 中间数据的接口
    def do(self, front_input):
        """
        对外提供的接口，按照front_input中的内容返回不同的结果
        :param front_input: 前端的输入
        :return:
        """
        if not self.raw:
            return []
        flag = "true" if front_input.get("flag") in ["true", True] else "false"
        filters = front_input.get("filters")  # 过滤中间的输出
        filter_flag = False  # 默认不过滤
        data = {
            "logid": front_input.get("logid"),
            "setState": front_input.get("toFlag")
        }
        # 完成标志位的变更
        if not self.first:
            self._trans(data)

        for i in filters.values():
            if i:
                filter_flag = True
                break
            else:
                filter_flag = False
        search = front_input.get("search")  # 模糊查询的条件
        pagination = front_input.get("pagination")  # 分页信息，有currentPage和pageSize字段

        # 去redis查出相应的log_ids的集合，返回值事一个列表，其中的每个元素的类型是`str`而不是`byte`
        # 后续的查询和过滤都是拿出对应的log_ids和他取交集
        all_flag_ids = self._get_log_ids(flag)
        if flag == "true":
            all_flag_ids = all_flag_ids & self.true_log_ids
            all_flag_ids = all_flag_ids - self.false_log_ids
        else:
            all_flag_ids = all_flag_ids & self.false_log_ids
            all_flag_ids = all_flag_ids - self.true_log_ids


        if not all_flag_ids:
            return [], 0
        if not filter_flag and not search:
            tmp_res = self.handle_redis_value(all_flag_ids)
            return self.paginate(tmp_res, pagination), len(tmp_res)
        if filter_flag or search:
            # 两者有其一或者都有
            # 这里应该有更优美的if else写法
            if filter_flag and not search:
                log_ids = self._filter(filters, self.init_res)
                # log_id要加上`flag`的匹配
                log_ids = log_ids.intersection(all_flag_ids)
                res = self.handle_redis_value(log_ids)
                return self.paginate(res, pagination), len(res)
            elif search and not filter_flag:
                log_ids = self._match(search, self.init_res)
                log_ids = log_ids.intersection(all_flag_ids)
                res = self.handle_redis_value(log_ids)
                return self.paginate(res, pagination), len(res)
            else:
                # 既要过滤,也要匹配
                log_ids_filter = self._filter(filters, self.init_res)
                log_ids_match = self._match(search, self.init_res)
                log_ids = log_ids_filter.intersection(log_ids_match).intersection(all_flag_ids)
                res = self.handle_redis_value(log_ids)
                return self.paginate(res, pagination), len(res)

    # 返回原始日志数据的接口
    @property
    def all_true_log(self):
        """
        返回`true`集合中的原始日志，因为我们可以保证自己的true_set与redis‘中数据是同步的
        因此遍历自己的true_set就可以
        """
        res = []
        redis_all_true_log_ids = self._get_log_ids("true")
        my_all_true_ids = self.true_log_ids & redis_all_true_log_ids
        es_data_dict = self.raw.get("data",  {})
        for i in my_all_true_ids:
            for one_es_log in es_data_dict:
                if i == one_es_log.get("_id"):
                    res.append(one_es_log)
        return res


