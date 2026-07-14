import reader

def extract_external_ips(data):
     return [row[1] for row in data if not (row[1][:3] == "10." or row[1][:8] == "192.168.")]

def rows_error_ports(data):
    return [row for row in data if row[3] == '22' or row[3] == '23' or row[3] == '3389']

def rows_big_bites(data):
    return[row for row in data if int(row[5]) > 5000]


def normal_large(data):
    return [(row ,'large' if int(row[5]) >= 5000 else 'normal') for row in data]



data = reader.read_csv_to_list("network_traffic.log")
print(normal_large(data))