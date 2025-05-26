import socket
import time
import pickle
from dnslib import DNSRecord, RCODE


class DNSCache:
    def __init__(self, cache_file="dns_cache.pickle"):
        self.cache = {}
        self.cache_file = cache_file

    def load(self):
        try:
            with open(self.cache_file, "rb") as f:
                cached_data = pickle.load(f)
                current_time = time.time()
                self.cache = {
                    k: v for k, v in cached_data.items()
                    if v[1] > current_time
                }
        except (FileNotFoundError, EOFError):
            self.cache = {}

    def save(self):
        with open(self.cache_file, "wb") as f:
            pickle.dump(self.cache, f)

    def add(self, record_type, record_name, records, ttl):
        expiry = time.time() + ttl
        self.cache[(record_type, record_name)] = (records, expiry)

    def get(self, record_type, record_name):
        cached = self.cache.get((record_type, record_name))
        if cached:
            records, expiry = cached
            if time.time() < expiry:
                return records
            del self.cache[(record_type, record_name)]
        return None


def _build_response(query, records):
    response = DNSRecord(header=query.header)
    response.add_question(query.q)
    response.rr.extend(records)
    return response.pack()


class DNSResolver:
    def __init__(self, upstream_server="8.8.8.8"):
        self.upstream_server = upstream_server
        self.cache = DNSCache()

    def process_query(self, query_data):
        try:
            query = DNSRecord.parse(query_data)
            qtype, qname = query.q.qtype, query.q.qname

            cached_records = self.cache.get(qtype, qname)
            if cached_records:
                return _build_response(query, cached_records)

            response = self._query_upstream(query_data)
            if response:
                response_record = DNSRecord.parse(response)
                if response_record.header.rcode == RCODE.NOERROR:
                    self._update_cache(response_record)
                return response

        except Exception as e:
            print(f"Ошибка обработки запроса: {e}")
        return None

    def _query_upstream(self, query_data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(5)
                s.sendto(query_data, (self.upstream_server, 53))
                return s.recv(512)
        except socket.timeout:
            print("Таймаут запроса к вышестоящему серверу")
            return None

    def _update_cache(self, response_record):
        for section in (response_record.rr, response_record.auth, response_record.ar):
            for record in section:
                records = self.cache.get(record.rtype, record.rname) or []
                records.append(record)
                self.cache.add(record.rtype, record.rname, records, record.ttl)


def run_server(host="127.0.0.1", port=53):
    resolver = DNSResolver()
    resolver.cache.load()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.bind((host, port))
        print(f"DNS сервер запущен на {host}:{port}")

        try:
            while True:
                try:
                    data, addr = server_socket.recvfrom(512)
                    if data.decode().strip().lower() == "exit":
                        break

                    response = resolver.process_query(data)
                    if response:
                        server_socket.sendto(response, addr)

                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"Ошибка обработки запроса: {e}")

        finally:
            resolver.cache.save()
            print("Сервер остановлен")


if __name__ == "__main__":
    run_server()
