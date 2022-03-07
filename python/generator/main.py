def process_list(item_list):
    for item in range(1, item_list):
        process_item = {'item':item}
        yield process_item

process_list_item = process_list(10000)
for process_one in process_list_item:
    print(process_one)
