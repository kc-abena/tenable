import json
from datetime import datetime
import csv
import requests

ctr=0
# json_file_path = r""
output_file = "scan_list.csv"
url = ""
api_key = ""
headers = {
        'x-apikey': api_key,
        'Content-Type': 'application/json'
    }

start_time = input("Enter start time in dd/mmm/yyyy format:")
end_time = input("Enter end time in dd/mmm/yyyy format:")

def get_scan_list(startTime,endTime):
    payload = {"startTime":startTime,"endTime":endTime}
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.ok:
            return response.json()
        else:
            print("Get scan list failed")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

def convert_date_to_epoch(dateString):
    date_obj=datetime.strptime(date_string, '%d/%b/%Y')
    epoch_time = int(date.obj.timestamp())
    return epoch_time

def convert_epoch_to_date(epoch_time):
    date_obj= datetime.utcfromtimestamp(int(epoch_time))
    formatted_date= date_obj.strftime('%d/%b/%Y')
    return formatted_date

def send_to_report(scan_id,scan_name,startTime):
    payload = {"name":scan_name+"_"+startTime,"description":"all details","context":"","status":0,"createdTime":1714110286,"groups":[],"schedule":{"start":"TZID=Asia/Hong_Kong:20240502T173000","repeatRule":"FREQ=NOW;INTERVAL=1","type":"now","enabled":"true"},"type":"csv","definition":{"dataSource":{"queryID":"10372","querySourceID":scan_id,"querySourceView":"all","querySourceType":"individual","sortColumn":"pluginID","sortDirection":"desc"},"columns":[{"name":"pluginID"},{"name":"pluginName"},{"name":"familyID"},{"name":"severity"},{"name":"ip"},{"name":"protocol"},{"name":"port"},{"name":"exploitAvailable"},{"name":"repositoryID"},{"name":"macAddress"},{"name":"dnsName"},{"name":"netbiosName"},{"name":"pluginText"},{"name":"synopsis"},{"name":"description"},{"name":"solution"},{"name":"seeAlso"},{"name":"riskFactor"},{"name":"stigSeverity"},{"name":"vprScore"},{"name":"baseScore"},{"name":"cvssV3BaseScore"},{"name":"temporalScore"},{"name":"cvssV3TemporalScore"},{"name":"cvssVector"},{"name":"cvssV3Vector"},{"name":"cpe"},{"name":"cve"},{"name":"bid"},{"name":"xref"},{"name":"firstSeen"},{"name":"lastSeen"},{"name":"vulnPubDate"},{"name":"seolDate"},{"name":"patchPubDate"},{"name":"pluginPubDate"},{"name":"pluginModDate"},{"name":"exploitEase"},{"name":"exploitFrameworks"},{"name":"checkType"},{"name":"version"},{"name":"recastRiskRuleComment"},{"name":"acceptRiskRuleComment"},{"name":"uuid"},{"name":"hostUUID"}],"dataPoints":"2147483647"},"styleFamily":{"id":5,"name":"Plain, Letter","description":"Plain style, letter","context":"","status":null,"createdTime":null,"modifiedTime":null},"pubSites":[],"shareUsers":[],"emailUsers":[],"emailTargets":"","emailBCCTargets":"","emailTargetType":"1"}

    try:
        response = requests.post(url, headers=headers, json=payload, verify=False)
        if response.ok:
            print("Success")
        else:
            print("Failed")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")

get_scan_list(convert_date_to_epoch(start_time),convert_date_to_epoch(end_time))

with open(output_file,'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
    csv_writer.writerow(['No.','Owner', 'Scan Name','ID','Start Date'])

    with open(json_file_path, 'r') as json_file:
        data = json.load(json_file)
        for item in data['response']['usable']:
            ctr+=1
            csv_name = item['name']
            csv_owner = item['owner']['firstname'] + " " + item['owner']['lastname']
            csv_id = item['id']
            csv_starttime = convert_epoch_to_date(item['startTime'])
            # send_to_report(csv_id,csv_name,csv_starttime)
            csv_writer.writerow([ctr,csv_owner, csv_name,csv_id,csv_starttime])
