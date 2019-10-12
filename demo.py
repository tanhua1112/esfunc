from flask import Flask, escape, request
from eser import Eser
from dber import DBer, Kafkaer
# from rediser import RedisLog
from rediser import RedisLog
import p.config as CONF
import json
import asyncio

app = Flask(__name__)


@app.route("/es/filter/<int:page>/<int:limit>", methods=["GET", "POST"])
def data_filter(page, limit):
    """左侧聚合列表 高级搜索、日志
    """
    es = Eser()
    if request.method == "POST":
        req = request.data.decode("utf-8")
        index, data = es.filter_body(req, page, limit)
        print(index)
        esdata = es.search_es(index, data, limit)
    elif request.method == "GET":
        index, data = es.filter_body({}, page, limit)
        esdata = es.search_es(index, data, limit)
    return esdata

@app.route("/es/search/<int:page>/<int:limit>", methods=["GET", "POST"])
def data_search(page, limit):
    """日志查询 右侧内容
    """
    es = Eser()
    if request.method == "POST":
        req = request.data.decode("utf-8")
        index, data = es.search_body(req, page, limit)
        esdata = es.search_es(index, data, limit)
    elif request.method == "GET":
        req = request.data.decode("utf-8")
        index, data = es.search_body(req, page, limit)
        esdata = es.search_es(index, data, limit)
    return esdata

curent_md5 = None
curent_redis = None
current_ip = None
@app.route("/es/table/<int:page>/<int:limit>", methods=["GET", "POST"])
def data_table(page, limit):
    global curent_md5
    global curent_redis
    global current_ip
    es = Eser()
    if request.method == "POST":
        req = request.data.decode("utf-8")
        req_data = json.loads(req)

        index, data, arg, md5 = es.table_body(req)
        if curent_md5 is None or curent_md5 != md5:
            curent_md5 = md5
            esdata = es.table_es(index, data, page, limit)
            rdser = RedisLog(esdata, True)
            datas = rdser.do(arg)
            curent_redis = rdser
            return json.dumps({"data":datas[0], "total":datas[1]})
        else:
            esdata = es.table_es(index, data, page, limit)
            rdser = RedisLog(esdata, False)
            datas = rdser.do(arg)
            curent_redis = rdser
            return json.dumps({"data":datas[0], "total":datas[1]})

@app.route("/es/true", methods=["GET", "POST"])
def true():
    try:
        return {"data":curent_redis.all_true_log}
    except Exception as e:
        return {"data":[]}

@app.route("/es/alert/<id>", methods=["GET", "POST"])
def searchdb(id):
    """人工手动告警 高级查询
    """
    dber = DBer()
    ids = dber.search_id(id)
    return ids

@app.route("/es/alert/update", methods=["GET", "POST"])
def updatedb():
    """人工手动告警 高级查询 焦
    """
    dber = DBer()
    kfk = Kafkaer()
    if request.method == "POST":
        req = request.data.decode("utf-8")
        print(req)
        data = dber.update(req)
        producer = kfk.init_producer()
        kfk.to_kafka(producer, [data])
    return "update success"

@app.route("/aaa", methods=["GET", "POST"])
def func():
    return "aaaaaaa"

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(app.run(host="0.0.0.0", port=8888, debug=True))
    # app.run(host="0.0.0.0", port=8000, debug=True)
