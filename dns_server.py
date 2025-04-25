import struct
import socket
import pickle
import time

TYPES = {
    1: 'A',
    2: 'NS',
    6: 'SOA',
    28: 'AAAA'
}
R_TYPES = {
    'A': 1,
    'NS': 2,
    'SOA': 6,
    'AAAA': 28
}


def url_to_bytes(url):
    chunks = url.split('.')
    count_bytes = 0
    result = b''
    for chunk in chunks:
        count_symbol = len(chunk)
        result += int.to_bytes(count_symbol, 1, 'big')
        count_bytes += 1
        for symbol in chunk:
            result += bytes(symbol, 'utf-8')
            count_bytes += 1
    return result, count_bytes


def get_info(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(data, ('212.193.163.7', 53))
    sock.settimeout(2)
    try:
        receive = sock.recvfrom(1024)[0]
        return receive, True
    except socket.timeout:
        print('Server unreachable')
        return b'', False
    finally:
        sock.close()


class DnsParse:
    def __init__(self, data):
        self.data = data
        self.transaction_id = data[:2]
        self.flags = data[2:4]
        self.questions = int.from_bytes(data[4:6], 'big')
        self.answer_rrs = int.from_bytes(data[6:8], 'big')
        self.authority_rrs = int.from_bytes(data[8:10], 'big')
        self.additional_rrs = int.from_bytes(data[10:12], 'big')

        point, query = read_query(data)
        self.query = query

        self.answers = []
        self.auth = []
        self.add = []

        point = self._read_section(point, self.answer_rrs, self.answers)
        point = self._read_section(point, self.authority_rrs, self.auth)
        self._read_section(point, self.additional_rrs, self.add)

    def _read_section(self, point, count, section_list):
        for _ in range(count):
            index, answer = self.read_answer(point, self.data)
            section_list.append(answer)
            cache.append(answer.name, answer, answer.type, self.flags)
            point = index
        return point

    @staticmethod
    def read_answer(point, data):
        offset = point
        count_readed, site_name = read_name_2(offset, data)

        type_offset = count_readed
        class_offset = count_readed + 2
        ttl_offset = count_readed + 4
        data_len_offset = count_readed + 8
        data_content_offset = count_readed + 10

        type_code = int.from_bytes(data[type_offset:type_offset + 2], byteorder='big')
        class_int = int.from_bytes(data[class_offset:class_offset + 2], byteorder='big')
        ttl = int.from_bytes(data[ttl_offset:ttl_offset + 4], byteorder='big')
        data_len = int.from_bytes(data[data_len_offset:data_len_offset + 2], byteorder='big')

        if TYPES.get(type_code) == 'A':
            sec_name = socket.inet_ntoa(data[data_content_offset:data_content_offset + data_len])
        elif TYPES.get(type_code) == 'AAAA':
            sec_name = socket.inet_ntop(socket.AF_INET6, data[data_content_offset:data_content_offset + data_len])
        else:
            _, sec_name = read_name_2(data_content_offset, data)

        answer = Answer(site_name, TYPES.get(type_code, f'UNKNOWN({type_code})'), class_int, ttl, sec_name)
        return data_content_offset + data_len, answer

    def complete_to_full_packet(self, query):
        answers_bytes = b''
        auth_bytes = b''
        count_answer_rrs = 0
        count_auth_rrs = 0
        count_addt_rrs = struct.pack('!h', 0)
        flags = b'\x85\x80'

        if self.query.name in cache.cache and self.query.type in cache.cache[self.query.name]:
            count_answer_rrs = len(cache.cache[self.query.name][self.query.type])
            for answer in cache.cache[self.query.name][self.query.type]:
                answers_bytes += answer[0].in_bytes

        result = self.transaction_id + flags + b'\x00\x01'
        result += (struct.pack('!h', count_answer_rrs) + struct.pack('!h', count_auth_rrs)
                   + count_addt_rrs + query.in_bytes)
        result += answers_bytes
        result += auth_bytes
        return result

    def __str__(self):
        result = f"Transaction ID: {self.transaction_id.hex()}  Flags: {self.flags.hex()}  " \
                 f"Questions: {self.questions}  Answer RRs: {self.answer_rrs}  " \
                 f"Authority RRs: {self.authority_rrs}  Additional RRs: {self.additional_rrs}\n" \
                 f"Query: {self.query}\n"
        for answer in self.answers:
            result += f"Answer: {answer}\n"
        return result


def read_name_2(d_index, data):
    index = d_index
    site_name = ''
    count_bytes = data[index]
    while count_bytes != 0 and count_bytes < 0xC0:
        for i in range(count_bytes):
            site_name += chr(data[1 + index + i])
        index += count_bytes + 1
        count_bytes = data[index]
        if count_bytes != 0:
            site_name += '.'
    if count_bytes >= 0xC0:
        point_offset = int.from_bytes(data[index: index + 2], 'big') & 0x3FFF
        part_name, _ = read_name_2(point_offset, data)
        site_name += part_name
        index += 2
    return site_name.rstrip('.'), index


def read_query(data):
    index, site_name = read_name_2(12, data)

    type_offset = index
    class_offset = index + 2

    type_code = int.from_bytes(data[type_offset:type_offset + 2], 'big')
    class_int = int.from_bytes(data[class_offset:class_offset + 2], 'big')

    type_str = TYPES.get(type_code, f'UNKNOWN({type_code})')
    query = Query(site_name, type_str, class_int, data[12:class_offset + 2])
    return class_offset + 2, query


def run_server():
    port = 53
    ip = '127.0.0.1'
    timeout = 1

    print(f"Starting DNS proxy server on {ip}:{port}...")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((ip, port))
        sock.settimeout(timeout)

        while True:
            try:
                data, addr = sock.recvfrom(1024)
            except socket.timeout:
                continue

            print(f"\nReceived query from {addr}")

            try:
                _, query = read_query(data)
                if query in cache:
                    print("Serving from cache")
                    query_parsed = DnsParse(data)
                    data_to_send = query_parsed.complete_to_full_packet(query)
                else:
                    print("Forwarding to upstream DNS")
                    data_to_send, status = get_info(data)
                    if status:
                        DnsParse(data_to_send)

                sock.sendto(data_to_send, addr)
            except Exception as ex:
                print(f"Error processing query: {ex}")


class Cache:
    def __init__(self):
        self.cache = {}
        self.load_file()

    def write_file(self):
        with open('dns_cache.pickle', 'wb') as file:
            pickle.dump(self.cache, file)

    def load_file(self):
        try:
            with open('dns_cache.pickle', 'rb') as file:
                self.cache = pickle.load(file)
                print("Cache loaded successfully")
        except (FileNotFoundError, EOFError, pickle.PickleError) as ex:
            print(f'Could not load cache: {ex}')
            self.cache = {}

    def append(self, key, answer, answer_type, flags):
        if key not in self.cache:
            self.cache[key] = {}

        if answer_type not in self.cache[key]:
            self.cache[key][answer_type] = []

        self.cache[key][answer_type] = [
            (ans, exp, fl) for (ans, exp, fl) in self.cache[key][answer_type]
            if exp > time.time()
        ]

        self.cache[key][answer_type].append((answer, time.time() + answer.ttl, flags))

    def __contains__(self, item):
        if item.name not in self.cache:
            return False

        if item.type in self.cache[item.name]:
            self.cache[item.name][item.type] = [
                (ans, exp, fl) for (ans, exp, fl) in self.cache[item.name][item.type]
                if exp > time.time()
            ]
            return bool(self.cache[item.name][item.type])

        if 'SOA' in self.cache[item.name]:
            self.cache[item.name]['SOA'] = [
                (ans, exp, fl) for (ans, exp, fl) in self.cache[item.name]['SOA']
                if exp > time.time()
            ]
            return bool(self.cache[item.name]['SOA'])

        return False


class Answer:
    def __init__(self, name, type_answer, class_int, ttl, sec_name):
        self.name = name
        self.type = type_answer
        self.class_int = class_int
        self.ttl = ttl
        self.sec_name = sec_name
        self.in_bytes = self.generate_packet()

    def generate_packet(self):
        result, _ = url_to_bytes(self.name)
        result += int.to_bytes(R_TYPES.get(self.type, 0), 2, 'big')
        result += int.to_bytes(self.class_int, 2, 'big')
        result += int.to_bytes(self.ttl, 4, 'big')

        if self.type == 'NS':
            bytes_name, count_b = url_to_bytes(self.sec_name)
            result += int.to_bytes(count_b, 2, 'big') + bytes_name
        elif self.type == 'A':
            result += int.to_bytes(4, 2, 'big') + socket.inet_aton(self.sec_name)
        elif self.type == 'AAAA':
            result += int.to_bytes(16, 2, 'big') + socket.inet_pton(socket.AF_INET6, self.sec_name)
        else:
            result += int.to_bytes(0, 2, 'big')

        return result

    def __str__(self):
        return f"Name: {self.name}, Type: {self.type}, Class: {self.class_int}, " \
               f"TTL: {self.ttl}, Data: {self.sec_name}"


class Query:
    def __init__(self, name, t, inter, byte):
        self.name = name
        self.type = t
        self.class_int = inter
        self.in_bytes = byte

    def __str__(self):
        return f"Query: Name={self.name}, Type={self.type}, Class={self.class_int}"


if __name__ == '__main__':
    cache = Cache()
    try:
        run_server()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        cache.write_file()
        print("Cache saved. Goodbye!")
    except Exception as e:
        print(f"Fatal error: {e}")
        cache.write_file()
