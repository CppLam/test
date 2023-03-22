import logging
import os
import time
import multiprocessing
import datetime
import requests
import gzip
import re
import concurrent.futures
import dns.resolver
import redis
import json

# version 1.0
# 更新模块（新的更新模块添加至此处，同时在 update_data函数的更新出添加对应更新模块的更新调用，插件更新并标准化后的数据存放至/data/*data目录下，*代表对应插件名）
import updateAlien
# 初始化日志设置
logging.basicConfig(filename='update.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

# 异常处理装饰器
def handle_exception(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f'Error occurred in {func.__name__}: {e}')
    return wrapper

# 更新白名单类
class WhitelistUpdater(multiprocessing.Process):
    def __init__(self, whitelist, lock):
        super().__init__()
        self.whitelist = whitelist
        self.lock = lock
        self.running = True
    def run(self):
        logging.info('Loading updating whitelist module')
        try:
            while self.running:
                # 每月15号更新白名单
                today = datetime.datetime.now()
                if today.day != 15:
                    time.sleep(24*60*60)
                    continue
                # 白名单更新
                new_whitelist = self.update_whitelist()
                if not new_whitelist:
                    time.sleep(60)
                    continue
                # 更新完成后替换旧白名单
                with self.lock:
                    self.whitelist.clear()
                    self.whitelist.update(new_whitelist)
                logging.info('Finish updating whitelist')
        except Exception as e:
            logging.error(f'Error occurred while run updating whitelist: {e}')

    def update_whitelist(self):
        logging.info('Updating whitelist begin')
        # 白名单更新
        try:
            current_dir = os.getcwd()
            datapath = os.path.join(current_dir, 'data')
            whitelist_ip_file = os.path.join(datapath, 'whitelist.ip')
            whitelist_domain_file = os.path.join(datapath, 'whitelist.domain')
            # 更新下载谷歌top域名列表
            topfile = self.updateChromeTop()
            # 将列表结果格式化为domain格式存放至 whitelist.domain
            self.generateDomainFile(topfile)
            # 进行全量DNS请求，存放dns结果至 whitelist.domain.dns
            self.updateDNS(whitelist_domain_file)
            # 根据dns结果获取ip白名单 whitelist.ip
            self.setwhiteiplist()
            white = {}
            # 获取更新后的白名单
            if os.path.exists(whitelist_ip_file):
                with open(whitelist_ip_file, 'r') as f:
                    whitelist_ip = set(f.read().splitlines())
            else:
                whitelist_ip = set()
            if os.path.exists(whitelist_domain_file):
                with open(whitelist_domain_file, 'r') as f:
                    whitelist_domain = set(f.read().splitlines())
            else:
                whitelist_domain = set()
            new_whitelist = {'ip': whitelist_ip,
                         'domain': whitelist_domain}
            return new_whitelist


        except Exception as e:
            logging.error(f'Error occurred while update_whitelist: {e}')
            return False

    def setwhiteiplist(self):
        current_dir = os.getcwd()
        datapath = os.path.join(current_dir, 'data')
        domaindns = os.path.join(datapath, 'whitelist.domain.dns')
        whiteiplist = os.path.join(datapath, 'whitelist.ip')
        with open(domaindns, 'r') as f:
            ip_count = {}
            white_count = {}
            data = f.readlines()
            for line in data:
                ip = line.split('|')[1].strip()
                if ip:
                    if ip in ip_count:
                        ip_count[ip] += 1
                    else:
                        ip_count[ip] = 1
            count = 0
            with open(whiteiplist, 'w') as fd:
                for one in ip_count:
                    if ip_count[one] >= 10:
                        print(str(one), file=fd)
                        count += 1
                        white_count[one] = ip_count[one]
                print(str(count))
                return white_count

    def updateDNS(self, filename):
        with open(filename, 'r') as f:
            domains = f.read().splitlines()
            dnslog = filename + '.dns'
            cache = []

            with open(dnslog, 'w') as fd, concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.resolve_domain, domain) for domain in domains]
                for future in concurrent.futures.as_completed(futures):
                    results = future.result()
                    for result in results:
                        if result[1] is not None:
                            record = f"{result[0]}|{result[1]}"
                            print(record, file=fd)
                        else:
                            cache.append(result[0])

                for domain in cache:
                    try:
                        results = self.resolve_domain(domain)
                        for result in results:
                            if result[1] is not None:
                                record = f"{result[0]}|{result[1]}"
                                print(record, file=fd)
                    except:
                        print(f"{domain} query failed")
                        continue

    def resolve_domain(self, domain):
        try:
            resolver = dns.resolver.Resolver(configure=False)
            # resolver.nameservers = ['223.5.5.5', '223.6.6.6', '119.29.29.29', '119.28.28.28', '1.2.4.8', '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4','208.67.222.222', '208.67.220.220','9.9.9.9', '149.112.112.112','8.26.56.26', '8.20.247.20','209.244.0.3', '209.244.0.4','84.200.69.80', '84.200.70.40',
            #                      '199.85.126.10', '199.85.127.10', '77.88.8.8', '77.88.8.1','91.239.100.100', '89.233.43.71',]
            resolver.nameservers = [
                '185.228.168.168', '185.228.169.168',  # CleanBrowsing
                '195.46.39.39', '195.46.39.40',  # SafeDNS
                '77.109.148.136', '77.109.148.137',  # DNSFilter
                '8.8.8.8', '8.8.4.4',  # Google Public DNS
                '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
                '208.67.222.222', '208.67.220.220',  # OpenDNS
                '9.9.9.9', '149.112.112.112',  # Quad9
                '8.26.56.26', '8.20.247.20',  # Comodo Secure DNS
                '209.244.0.3', '209.244.0.4',  # Level3 DNS
                '84.200.69.80', '84.200.70.40',  # DNS.WATCH
                '199.85.126.10', '199.85.127.10',  # Norton ConnectSafe
                '77.88.8.8', '77.88.8.1',  # Yandex.DNS
                '91.239.100.100', '89.233.43.71',  # UncensoredDNS
                '94.140.14.14', '94.140.15.15',  # Censurfridns
                '37.235.1.174', '37.235.1.177',  # FreeDNS
                '84.200.14.242', '84.200.70.243',  # Freifunk DNS
                '208.76.50.50', '208.76.51.51',  # Alternate DNSa
                '216.146.35.35', '216.146.36.36',  # Dyn
                '74.82.42.42',  # Hurricane Electric
                '80.80.80.80', '80.80.81.81',  # Freenom World
                '223.5.5.5', '223.6.6.6', '119.29.29.29', '119.28.28.28', '1.2.4.8', '185.121.177.177',
                '169.239.202.202', '94.232.174.194'
            ]
            answers = resolver.resolve(domain, 'A')
            return [(domain, str(answer)) for answer in answers]
        except dns.resolver.NXDOMAIN:
            print(f"{domain} does not exist")
            return [(domain, None)]
        except dns.resolver.NoAnswer:
            print(f"{domain} has no A record")
            return [(domain, None)]
        except:
            print(f"{domain} query failed")
            time.sleep(1)
            return [(domain, None)]

    def updateChromeTop(self):
        url = 'https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz'
        filename = os.path.basename(url)
        current_dir = os.getcwd()
        datapath = os.path.join(current_dir, 'data')
        local_path = os.path.join(datapath, filename)
        if not os.path.exists(datapath):
            os.mkdir(datapath)
        # Download the file
        response = requests.get(url)
        # Save the gzipped file
        with open(local_path, "wb") as f:
            f.write(response.content)
        # Unzip the file
        with gzip.open(local_path, "rb") as f_in:
            with open(os.path.splitext(local_path)[0], "wb") as f_out:
                f_out.write(f_in.read())
        return os.path.splitext(local_path)[0]

    def generateDomainFile(self, filename):
        current_dir = os.getcwd()
        datapath = os.path.join(current_dir, 'data')
        outname = 'whitelist.domain'
        local_path = os.path.join(datapath, outname)
        # Create the 'data' directory if it doesn't exist
        if not os.path.exists(datapath):
            os.mkdir(datapath)
        with open(filename, "r") as f:
            all = f.readlines()
            doms = []
            with open(local_path, 'w') as fout:
                for one in all:
                    dom = self.process_url(one)
                    if dom:
                        doms.append(dom)
                fout.writelines(doms)

    def process_url(self, url):
        # 匹配 URL 的各个部分
        pattern = r"^([a-z]+:\/\/)?([\w.-]+)(,\d+)?$"
        match = re.match(pattern, url)

        if match:
            # 使用 group 方法获取匹配到的内容
            protocol = match.group(1)
            domain = match.group(2)
            number = match.group(3)

            return domain + '\n'
        else:
            # 匹配失败，返回原始 URL
            return False

# 初始化白名单更新模块
@handle_exception
def init_whitelist():
    # 加载白名单
    logging.info('Start init whitelist')
    current_dir = os.getcwd()
    datapath = os.path.join(current_dir, 'data')
    whitelist_ip_file = os.path.join(datapath, 'whitelist.ip')
    whitelist_domain_file = os.path.join(datapath, 'whitelist.domain')
    if os.path.exists(whitelist_ip_file):
        with open(whitelist_ip_file, 'r') as f:
            whitelist_ip = set(f.read().splitlines())
    else:
        whitelist_ip = set()
    if os.path.exists(whitelist_domain_file):
        with open(whitelist_domain_file, 'r') as f:
            whitelist_domain = set(f.read().splitlines())
    else:
        whitelist_domain = set()
    # 更新白名单线程
    whitelist = {'ip': whitelist_ip,
                 'domain': whitelist_domain}
    logging.info('Finish init whitelist')
    return whitelist


# 数据更新模块
@handle_exception
def update_data():
    # 数据更新
    logging.info('Start updating data')
    time.sleep(1)
    # 调用更新插件的更新模块，有新的添加至此处
    r = updateAlien.update()
    if r:
        logging.info(f'Finish updating data')
    else:
        logging.info(f'Updating data fail')
    return r

# 数据过滤模块
@handle_exception
def filter_data(data, whitelist):
    # 数据过滤
    types = ['ipv4', 'domain', 'url', 'filehash-sha256', 'hostname', 'filehash-sha1', 'filehash-md5', 'email']
    newdata =[]
    for one in data:
        itype = one['type']
        if itype not in types:
            continue
        if itype == 'ipv4' and one['value'] not in whitelist['ip']:
            newdata.append(one)
        elif itype == 'domain' and one['value'] not in whitelist['domain']:
            newdata.append(one)
        elif itype == 'hostname' and one['value'] not in whitelist['domain']:
            newdata.append(one)
        else:
            newdata.append(one)
    return newdata

#数据碰撞模块
@handle_exception
def xcrash(client, data):
    data_to_set = {}
    for datum in data:
        types = ['ipv4', 'domain', 'hostname', 'filehash-md5', 'email']
        if datum['type'] not in types:
            continue
        key = datum['value']
        value = {
            'type': datum['type'],
            'reputation': datum['reputation'],
            'from': 'alien'
        }
        data_to_set[key] = json.dumps(value, ensure_ascii=False)
    if data_to_set:
        chunk_size = 1000
        chunks = [list(data_to_set.items())[i:i + chunk_size] for i in range(0, len(data_to_set), chunk_size)]
        for chunk in chunks:
            chunk_data = {k: v for k, v in chunk}
            client.mset(chunk_data)
            #client.expire(chunk_data.keys(), 24 * 3600)
            for key in chunk_data.keys():
                client.expire(key,24 * 3600)
        logging.info('upload crash data %d'% len(data_to_set))

# 数据上传模块
@handle_exception
def filter_upload_data(whitelist):
    # redis 初始化
    host = '11.11.1.11'
    port = 9111
    auth = '111111111111'
    # key = 'opencti'
    logging.info('Start uploading data')
    redis_client = redis.StrictRedis(host=host, port=port, password=auth)

    # 数据上传

    chunk_size = 1000
    current_dir = os.getcwd()
    # 遍历各插件更新标准数据，过滤后上传
    datapath = os.path.join(current_dir, 'data')
    for files, dirs, root in os.walk(datapath):
        for dir in dirs:
            scandir = os.path.join(datapath, dir)
            stand_files = [f for f in os.listdir(scandir) if f.endswith('.stand')]
            for i, upfile in enumerate(stand_files):
                key = f'opencti'
                pipeline = redis_client.pipeline()
                with open(os.path.join(scandir, upfile), 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    data = filter_data(data, whitelist)
                    for j in range(0, len(data), chunk_size):
                        chunk = data[j:j + chunk_size]
                        for value in chunk:
                            try:
                                query = json.dumps(value, ensure_ascii=False)
                                pipeline.rpush(key, query)
                            except Exception as e:
                                print(e)
                        pipeline.execute()
                        time.sleep(1)
                    # 上传碰撞
                    xcrash(redis_client, data)
                    logging.info('upload data %d'% len(data))

                os.remove(os.path.join(scandir, upfile))
    time.sleep(1)
    logging.info('Finish uploading data')

if __name__ == '__main__':
    #filter_upload_data('a')

    # 白名单更新
    manager = multiprocessing.Manager()
    whitelist = manager.dict()
    #wlist = whitelist.copy()
    org_whitelist = init_whitelist()
    whitelist.update(org_whitelist)
    new_whitelist = org_whitelist.copy()
    lock = multiprocessing.Lock()
    whitelist_updater = WhitelistUpdater(whitelist, lock)
    whitelist_updater.start()

    # 情报数据更新过滤上传
    while True:
        try:
            today = datetime.datetime.now()
            if today.hour != 18:
                time.sleep(60 * 60)
                continue
            # 更新数据
            r = update_data()
            if not r:
                time.sleep(60*60)
                continue
            with lock:
                new_whitelist = whitelist.copy()
            # 过滤上传数据
            filter_upload_data(new_whitelist)

            # 休眠一小时
            time.sleep(60 * 60)
        except Exception as e:
            logging.error(f'Error occurred in main thread: {e}')
