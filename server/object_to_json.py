import sqlite3


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def get_agent():
    connection = sqlite3.connect("site.db")
    connection.row_factory = dict_factory
    cursor = connection.cursor()
    cursor.execute("select * from agents")
    results = cursor.fetchall()
    connection.close()
    return results


def get_ip():
    connection = sqlite3.connect("site.db")
    connection.row_factory = dict_factory
    cursor = connection.cursor()
    cursor.execute("select ip , hostname from agents")
    ip_list = cursor.fetchall()
    connection.close()
    return ip_list


# print(get_agent())

# print(get_ip())


def get_ip_host(ip):
    connection = sqlite3.connect("site.db")
    connection.row_factory = dict_factory
    cursor = connection.cursor()
    cursor.execute("select  hostname from agents where ip = '" + ip + "'")
    io_to_host = cursor.fetchall()
    connection.close()
    return io_to_host


# print(get_ip_host("10.71.65.203"))
