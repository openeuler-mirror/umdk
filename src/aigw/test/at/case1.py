import sys
import threading
import time
import json
import requests
from flask import Flask, Response


# 注册URL
register_url = "http://127.0.0.1:8888/aigw/v1/register-instance"
# 调度URL
get_suggestion_url = "http://127.0.0.1:8888/aigw/v1/openai/get-suggestion"
# 注销URL
unregister_url = "http://127.0.0.1:8888/aigw/v1/unregister-instance"
# 实例1注册信息
ins1_info = {
    "name": "instance01",
    "model": "DeepSeek-R1-Distill-Qwen-7B",
    "instanceIp": "127.0.0.1",
    "port": "5001",
    "role": "mixed"
}
# 实例1注册信息
ins2_info = {
    "name": "instance02",
    "model": "DeepSeek-R1-Distill-Qwen-7B",
    "instanceIp": "127.0.0.1",
    "port": "5002",
    "role": "mixed"
}
# 推理请求
req = {
    "model": "DeepSeek-R1-Distill-Qwen-7B",
    "uuid": "",
    "messages": [{
        "role": "user",
        "content": "你是谁"
        },
        {
            "role": "assistant",
            "content": "您好，我是AI"
        },
        {
            "role": "user",
            "content": "你为何这么聪明"
        }],
    # 以下是无用参数，测试用
    "stream": False,
    "temperature": 0,
    "presence_penalty": 0,
    "frequency_penalty": 0,
    "top_p": 1
}
# 实例2注销信息
del_ins2_info = {
    "name": "instance02",
    "model": "DeepSeek-R1-Distill-Qwen-7B",
    "instanceIp": "127.0.0.1",
    "port": "5002",
}


# 创建第一个SSE服务端
app1 = Flask(__name__)


@app1.route('/subscribe-event')
def sse1():
    def event_stream():
        while True:

            # 创建一个 SSE 事件对象
            data = {
                "totalKvBlocks": 802,
                "freeKvBlocks": 802,
                "avgWaitingTime": 0,
                "timeToFirstToken": 0,
                "queueLength": 0,
                "timeBetweenTokens": 0
            }

            info = {
                "eventType": "metric_event",
                "data": data
            }

            # 构造 SSE 格式的消息。每个消息以\n结尾
            yield f"{json.dumps(info)}\n"
            time.sleep(2000)
    return Response(event_stream(), mimetype="text/event-stream")


def run_app1():
    app1.run(port=5001, threaded=True)


# 创建第二个SSE服务端
app2 = Flask(__name__)


@app2.route('/subscribe-event')
def sse2():
    def event_stream():
        while True:
            # 创建一个 SSE 事件对象
            data = {
                "totalKvBlocks": 800,
                "freeKvBlocks": 800,
                "avgWaitingTime": 0,
                "timeToFirstToken": 0,
                "queueLength": 0,
                "timeBetweenTokens": 0
            }

            info = {
                "eventType": "metric_event",
                "data": data
            }

            # 构造 SSE 格式的消息。每个消息以\n结尾
            yield f"{json.dumps(info)}\n"
            time.sleep(20000)

    return Response(event_stream(), mimetype="text/event-stream")


def run_app2():
    app2.run(port=5002, threaded=True)


if __name__ == '__main__':
    # 启动第一个SSE服务端线程
    t1 = threading.Thread(target=run_app1, daemon=True)
    t1.start()

    # 启动第二个SSE服务端线程
    t2 = threading.Thread(target=run_app2, daemon=True)
    t2.start()

    print("*** 实例已在端口5001和5002启动 ***")
    # 等待服务端启动
    time.sleep(1)

    # 设置请求头为 JSON 格式
    headers = {
        "Content-Type": "application/json"
    }

    # 注册实例1
    json_data = json.dumps(ins1_info)
    response = requests.post(register_url, data=json_data, headers=headers)
    if response.status_code != 200:
        print("[fail]实例1注册失败，预期成功")
        sys.exit(1)
    else:
        print("[success]实例1注册成功，预期成功")
    # 注册实例2
    json_data = json.dumps(ins2_info)
    response = requests.post(register_url, data=json_data, headers=headers)
    if response.status_code != 200:
        print("[fail]实例2注册失败，预期成功")
        sys.exit(1)
    else:
        print("[success]实例2注册成功，预期成功")
    # 重复注册
    response = requests.post(register_url, data=json_data, headers=headers)
    if response.status_code != 200:
        print("[success]实例2重复注册失败，预期失败")
    else:
        print("[fail]实例2重复注册成功，预期失败")
        sys.exit(1)
    # 请求调度，默认capacity，两次都调度给5001
    for i in range(2):
        uuid = f"req_{i}"
        req["uuid"] = uuid
        json_data = json.dumps(req)
        response = requests.post(get_suggestion_url, data=json_data, headers=headers)
        if response.json() == {'targetPrefill': '127.0.0.1:5001', 'targetDecode': ''}:
            print(f"[success]{uuid}调度结果：", response.json())
        else:
            print(f"[fail]{uuid}预期5001，实际调度结果：", response.json())
            sys.exit(1)
        time.sleep(1)
    # 注销实例2
    json_data = json.dumps(del_ins2_info)
    response = requests.post(unregister_url, data=json_data, headers=headers)
    if response.status_code != 200:
        print("[fail]实例2注销失败，预期成功")
        sys.exit(1)
    else:
        print("[success]实例2注销成功，预期成功")
    time.sleep(1)


