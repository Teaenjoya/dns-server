import socket
import struct
import random


def resolve_multiply(qname):
    marker = '.multiply.'
    idx = qname.find(marker)
    if idx == -1:
        return None

    prefix = qname[:idx]
    numbers = prefix.split('.')
    if not numbers or not all(n.isdigit() for n in numbers):
        return None

    product = 1
    for n in numbers:
        product = (product * int(n)) % 256
    return f"127.0.0.{product}"


def make_flags(is_response=True, rd=True, ra=True, rcode=0):
    flags = 0
    if is_response:
        flags |= 0x8000
    if rd:
        flags |= 0x0100
    if ra:
        flags |= 0x0080
    flags |= (rcode & 0x000F)
    return flags


def read_name(data, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0: #11000000
            pointer = struct.unpack('!H', data[offset:offset + 2])[0]
            pointer = pointer & 0x3FFF
            if not jumped:
                original_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        offset += 1
        labels.append(data[offset:offset + length].decode('ascii', errors='ignore'))
        offset += length

    if jumped:
        offset = original_offset
    return '.'.join(labels), offset


def parse_query(data):
    id = struct.unpack('!H', data[:2])[0]
    bytes_offset = 12

    labels = []
    while data[bytes_offset] != 0:
        length = data[bytes_offset]
        bytes_offset += 1
        labels.append(data[bytes_offset:bytes_offset + length].decode('ascii'))
        bytes_offset += length
    bytes_offset += 1
    qname = '.'.join(labels)

    qtype, qclass = struct.unpack('!HH', data[bytes_offset:bytes_offset + 4])
    return id, qname, qtype, qclass, bytes_offset + 2 + 2


def parse_response(data):
    id, flags, qcount, anscount, nscount, arcount = struct.unpack('!HHHHHH', data[:12])
    offset = 12

    for _ in range(qcount):
        qname, offset = read_name(data, offset)
        offset += 2 + 2

    for _ in range(anscount):
        name, offset = read_name(data, offset)
        offset += 2 + 2 + 4 + 2
        rdlength = struct.unpack('!H', data[offset - 2:offset])[0]
        offset += rdlength

    ns_names = []
    for _ in range(nscount):
        name, offset = read_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 2:  # NS-запись
            ns_name, _ = read_name(data, offset - rdlength)
            ns_names.append(ns_name)

    ips = []
    for _ in range(arcount):
        name, offset = read_name(data, offset)

        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 2 + 2 + 4 + 2

        rdata = data[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1 and rdlength == 4:
            ip = '.'.join(map(str, rdata))
            ips.append(ip)

    return ips, ns_names


def send_query_to_server(server_ip, domain_name, qtype=1):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2)

    id = random.randint(0, 65535)
    header = struct.pack('!HHHHHH', id, 0x0100, 1, 0, 0, 0)

    qname_bytes = b''
    for label in domain_name.split('.'):
        qname_bytes += bytes([len(label)]) + label.encode('ascii')
    qname_bytes += b'\x00'

    question = qname_bytes + struct.pack('!HH', qtype, 1)
    packet = header + question

    try:
        client_socket.sendto(packet, (server_ip, 53))
        response_data = client_socket.recvfrom(512)[0]
        return response_data
    except socket.timeout:
        print(f"Таймаут при запросе к {server_ip}")
        return None
    finally:
        client_socket.close()


def resolve_domain(domain_name):
    current_servers = ["192.5.5.241"]
    parts = domain_name.split('.')

    for i in range(len(parts) - 1, -1, -1):
        zone_to_find = '.'.join(parts[i:])
        next_servers = []

        if i == 0:
            break  # <--- ВОТ ЭТО

        for server_ip in current_servers:
            response = send_query_to_server(server_ip, zone_to_find, qtype=2)
            if response:
                ips, ns_names = parse_response(response)
                if ips:
                    next_servers = ips
                    break
                elif ns_names:
                    for ns_name in ns_names:
                        ns_ip = resolve_domain(ns_name)
                        if ns_ip:
                            next_servers.append(ns_ip)
                    if next_servers:
                        break

        if not next_servers:
            return None
        current_servers = next_servers

    for server_ip in current_servers:
        response = send_query_to_server(server_ip, domain_name, qtype=1)
        if response:
            id, flags, qdcount, anscount, nscount, arcount = struct.unpack('!HHHHHH', response[:12])
            if anscount > 0:
                offset = 12
                offset = read_name(response, offset)[1]
                offset += 2 + 2

                name, offset = read_name(response, offset)
                rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset + 10])
                offset += 2 + 2 + 4 + 2
                rdata = response[offset:offset + rdlength]

                if rtype == 5:  # CNAME
                    cname = read_name(response, offset - rdlength)[0]
                    print(f"  CNAME: {cname}")
                    return resolve_domain(cname)

                if rtype == 1 and rdlength == 4:
                    ip = '.'.join(map(str, rdata))
                    return ip

    return None


def build_response(query_data, qname_offset, qtype, qclass, resolved_ip=None):
    id = struct.unpack('!H', query_data[:2])[0]
    question_section = query_data[12:qname_offset]

    if resolved_ip is None:
        flags = make_flags(is_response=True, rd=True, ra=True, rcode=3)  # NXDOMAIN
        header = struct.pack('!HHHHHH', id, flags, 1, 0, 0, 0)
        return header + question_section

    flags = make_flags(is_response=True, rd=True, ra=True, rcode=0)  # NOERROR
    header = struct.pack('!HHHHHH', id, flags, 1, 1, 0, 0)

    answer_name = b'\xc0\x0c'
    answer_type = struct.pack('!H', qtype)
    answer_class = struct.pack('!H', qclass)
    answer_ttl = struct.pack('!I', 60)
    answer_rdlength = struct.pack('!H', 4)
    answer_rdata = bytes(map(int, resolved_ip.split('.')))

    answer_section = answer_name + answer_type + answer_class + answer_ttl + answer_rdlength + answer_rdata
    return header + question_section + answer_section


server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('0.0.0.0', 53)
server_socket.bind(server_address)

while True:
    data, addr = server_socket.recvfrom(512)

    try:
        id, qname, qtype, qclass, q_end = parse_query(data)
        print(f"ЗАПРОС ID: {id}, QNAME: {qname}, QTYPE: {qtype}, QCLASS: {qclass}")

        resolved_ip = resolve_multiply(qname)
        if resolved_ip:
            print(f"Multiply: {qname} -> {resolved_ip}")
        else:
            resolved_ip = resolve_domain(qname)

        if resolved_ip:
            response = build_response(data, q_end, qtype, qclass, resolved_ip)
            print(f"Отправлен ответ: {resolved_ip}")
        else:
            response = build_response(data, q_end, qtype, qclass, None)
            print(f"Увы NXDOMAIN для {qname}")

        server_socket.sendto(response, addr)
    except Exception as e:
        print(f"Ошибка обработки запроса от {addr}: {e}")