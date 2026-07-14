import csv
def read_csv_to_list(file_path):
    data =[]
    with open(file_path, mode='r', encoding='utf-8') as file:
        return [row for row in csv.reader(file)]
