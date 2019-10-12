import psycopg2.extras
import psycopg2 as pg
import p.config as CONF
import json
import collections
import time
from confluent_kafka import Producer

class Kafkaer(object):
    def __init__(self, kafka_batch_len=1024 * 1024 * 10, send_len=2000):
        self.send_len = send_len
        self.kafka_conf_str = CONF.KAFKA_CONN_STR
        self.kafka_batch_len = kafka_batch_len

    def init_producer(self):
        try:
            producer = Producer({"bootstrap.servers": self.kafka_conf_str,
                                 "message.max.bytes": self.kafka_batch_len})
        except Exception as e:
            raise Exception(e)
        return producer

    def to_kafka(self, producer, ds, force=False):
        for data in ds:
            producer.produce(CONF.TOPIC, json.dumps(data))
            producer.flush()

class DBer(object):
    def __init__(self):
        try:
            self.conn = pg.connect(host=CONF.DB_HOSTNAME,
                            port=CONF.DB_PORT,
                            user=CONF.DB_USER,
                            password=CONF.DB_PASSWORD,
                            dbname=CONF.DB_NAME)
            self.cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        except Exception as ex:
            print("fuck")
            raise Exception(str(ex))

    def search_id(self, logid):
        """
        事件ID查询,
        返回告警编号
        """
        self.cur.execute('''select * from h_threat_alarm_event where original_log_list like '%{0:s}%';'''.format(logid))
        tdbs = self.cur.fetchall()
        tdata = [id.get("alarm_id") for id in tdbs]
        self.cur.execute('''select * from h_abnormal_alarm_event where original_log_list like '%{0:s}%';'''.format(logid))
        adbs = self.cur.fetchall()
        adata = [id.get("alarm_id") for id in adbs]
        total = []
        for value in (tdata+adata):
            data = {}
            if value.startswith("T"):
                data["type"] = "1"
                data["id"] = value
            elif value.startswith("V"):
                data["type"] = "2"
                data["id"] = value
            elif value.startswith("A"):
                data["type"] = "3"
                data["id"] = value
            total.append(data)
        db={}
        db["status"] = "success"
        db["data"] = total
        return json.dumps(db)


    def update(self, req):
        req_data = json.loads(req)
        keys = req_data.pop("keys")
        data = req_data.get("data", {})
        label = data["threat_info"]["purpose_endpoint"]["label"]
        label.append("人工告警")
        return json.dumps(req_data)