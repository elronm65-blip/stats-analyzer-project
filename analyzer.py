import reader


def extract_external_ips(data):
     return [row[1] for row in data if not (row[1][:3] == "10." or row[1][:8] == "192.168.")]

def rows_error_ports(data):
    return [row for row in data if row[3] == '22' or row[3] == '23' or row[3] == '3389']

def rows_big_bites(data):
    return[row for row in data if int(row[5]) > 5000]


def normal_large(data):
    return [(row ,'large' if int(row[5]) >= 5000 else 'normal') for row in data]


def ip_count_inquiries(data):
    counts = {}
    for row in data:
        ip =row[1]
        counts[ip] = counts.get(ip, 0) + 1
    return counts

def protocol_port(data):
    return {row[3]: row[4] for row in data}


def analyze_logs(data):
    ip_errors = {}

    checks = {
        'EXTERNAL_IP': lambda row: not (row[1].startswith('10.') or row[1].startswith('192.168.')),

        'SENSITIVE_PORT': lambda row: int(row[3]) in [22, 23, 3389],
        'LARGE_PACKET': lambda row: int(row[4]) > 5000,
        'NIGHT_ACTIVITY': lambda row: 0 <= int(row[0][11:13]) < 6
    }

    for row in data:
        ip = row[1]

        if ip not in ip_errors:
            ip_errors[ip] = []


        for name, check_func in checks.items():
            if check_func(row):
                if name not in ip_errors[ip]:
                    ip_errors[ip].append(name)

    return ip_errors


def filter_suspicious_ips(all_errors_dict):
    
    filtered_errors = {ip: errors for ip, errors in all_errors_dict.items() if len(errors) >= 2}

    return filtered_errors





data = reader.read_csv_to_list("network_traffic.log")
print(  ip_All_errors(data))