import json, csv, sys, os, requests, uuid, jwt, csv
import time as t
from datetime import datetime, timedelta, date

page_num = 1

start_date = datetime.now() - timedelta(days=30)

start_date_string = str (start_date) 
start_date_string.replace(" ", "T")
print(start_date_string)

final_date = start_date_string.replace(" ", "T") + "Z"

optics_status = []
optics_device_name = []
optics_detection_id = []
optics_detection_occourenceTime = []
optics_detection_receivedTime = []
optics_severity = []
optics_description = []

# This will save all directories to the current working directory (the one where the program is being ran from)
working_dir = sys.path[0] + "/"

timestr = t.strftime("%Y%m%d-%H%M%S")
# The output file name and where it will be saved
output_file = working_dir + "optic_report_{}.csv".format(timestr)

log_file = working_dir + "log.txt"

#error_codes = [200, 400, 401, 403, 404, 409, 500, 501]

def write_error_log(error):
  f = open(log_file, 'a')
  f.write(error + "\n")
  f.close()
  return error

def get_error_code(error_code):

  error_time = datetime.utcnow()

  if error_code == 200:
    print("[200] CONNECTION OK")
  elif error_code == 400:
    print("[400] BAD REQUEST, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] Error 400 - Bad Request. There was a problem with the structure of the request or the payload."
    write_error_log(error)
    t.sleep(5)
    sys.exit()
  elif error_code == 401:
    print("[401] UNAUTHORIZED, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] Error 401 - Unauthorized. The AppID, TenantID & Secret you entered were incorrect. Try entering them again, if the error persists generate new integration credentials."
    write_error_log(error)
    t.sleep(5)
    sys.exit()
  elif error_code == 403:
    print("[403] FORBIDDEN, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] Error 403 - Forbidden. Request has been successfully authenticated, but authorization to access the requested resource was not granted."
    write_error_log(error)
    t.sleep(5)
    sys.exit()
  elif error_code == 404:
    print("[404] NOT FOUND, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] Error 404 - Not Found. Well this is awkward :/ A request was made for a resource that does not exist. Common causes are either an improperly formed URL or an invalid API Key"
    write_error_log(error)
    t.sleep(5)
    sys.exit()
  elif error_code == 409:
    print("[409] CONFLICT, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] Error 409 - Conflict. A reqeust was made to create or update an aspect of the resource that conflicts with another. Reason - Tenant Name or User Email is already in use."
    write_error_log(error)
    t.sleep(5)
    sys.exit()
  elif error_code == 500:
    print("[500] INTERNAL SERVER ERROR, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] Error 500 - Internal Server Error. Unhandled error has occurred on the server. Contact Support for further support on this issue."
    write_error_log(error)
    t.sleep(5)
    sys.exit()
  elif error_code == 501:
    print("[501] NOT IMPLEMENTED, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] Error 501 - Bad Request. A request was made against a resource with an operation that has yet to be implemented. Such operations should be identified accordingly."
    write_error_log(error)
    t.sleep(5)
    sys.exit()
  else:
    print(error_code + " THIS IS AWKWARD, SEE LOG FILE")
    error = "[ " + str(error_time) + " ] " + error_code + " Other. Contact Support - This error code is not recognised."
    write_error_log(error)
    t.sleep(5)
    sys.exit

  return error_code

def gen_token():
    # 30 minutes from now
    timeout = 1800
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=timeout)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())

    jti_val = str(uuid.uuid4())
    # Each of the following three variables will need to be inserted by the client themselves.
    # This is the only data we will need the client to enter, this is because it is unique to each portal
    # However we may be able to collect this data through Catalyst, but this is still unknown.

    ## Tenant ID
    print("Please enter your Tenant ID ") #Ask the usedr to enter their Tenant ID
    while True:
      tid_input = input() #Store the users input
      if tid_input != "":
        tid_val = tid_input
        break
      print("Please enter a valid Tenant ID")

    # App ID
    print("Please enter your Application ID")
    while True:
      appID_input = input() #Store the users input
      if appID_input != "":
        app_id = appID_input
        break
      print("Please enter a valid Application ID")

    # Secret ID
    print("Please enter your Secret ID")
    while True:
      sid_input = input() #Store the users input
      if sid_input != "":
        app_secret = sid_input
        break
      print("Please enter a valid Secret ID")

    ## URL to request the token.
    AUTH_URL = "https://protectapi-euc1.cylance.com/auth/v2/token"

    ## Properties of the request
    claims = {
        "exp": epoch_timeout,
        "iat": epoch_time,
        "iss": "http://cylance.com",
        "sub": app_id,
        "tid": tid_val,
        "jti": jti_val
        # The following is optional and is being noted here as an example on how one can restrict
        #  the list of scopes being requested
        # "scp": "policy:create, policy:list, policy:read, policy:update"
    }
    ## Encode the secret ID with the claims.
    encoded = jwt.encode(claims, app_secret, algorithm='HS256').decode('utf-8')

    payload = {"auth_token": encoded}
    headers = {"Content-Type": "application/json; charset=utf-8"}

    resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
    error_code = resp.status_code

    get_error_code(error_code)

    ## Assigns the access token value from the JSON file to a python variable.
    access_token = json.loads(resp.text)['access_token']

    #print ("http_status_code: " + str(resp.status_code)) ## Prints the response code to confirm the request was successful
    #print (access_token)

    ## Return the value of "access_token" to be used elsewhere in the script.
    return access_token

## Global variable for the access token, assigns the returned value to a variable that can be used
## elsewhere in the script
token = gen_token()
print(token)

def get_total_pages(): # Send one result to get the total number of pages for the following statements
  total_devices = "https://protectapi-euc1.cylance.com/detections/v2?page=1&page_size=200&start={d}&status=New".format(d=final_date) # Page size must be kept consistant throughout the whole program.

  payload = {}
  headers = {
    'Accept': 'application/json',
    'Authorization': 'Bearer {}'.format(token) # Insert the token we have already generated in the above function
  }

  resp = requests.get(total_devices, headers=headers, data=payload) # Send the GET reqest to the specificed API call point

  device_total = resp.text # Convert the results into text
  parsed = json.loads(device_total)

  total_pages = parsed["total_pages"] #
  return total_pages

total_pages = get_total_pages()

## Function that appends the breach entry to a particular CSV file.
def add_to_csv(file_name, data_entry):
    with open(file_name, 'a', newline='') as f:
        wr = csv.writer(f, quoting=csv.QUOTE_ALL)
        wr.writerow(data_entry)


## Create the CSV file and add the headers for each of the domains that will be queried.
def create_csv_sheet():
    headers = ["Notes", "Action", "Action Details", "Link", "Device", "Detection ID", "Detection Type", "Detected On Name", "Received Time", "Severity", "Status"]
    ## set the csv file name and reference the file path
    ## working directory + output folder + company name folder + the current time + ".csv"
    csv_name = output_file
    ## add the headers to the csv
    add_to_csv(csv_name, headers)

def get_detections_optics():
  current_page = 1
  data = []
  while current_page <= total_pages:
    
    url = "https://protectapi-euc1.cylance.com/detections/v2?page={}&page_size=200&start={}&status=New".format(current_page, final_date)

    payload = {}
    headers = {
      'Accept': 'application/json',
      'Authorization': 'Bearer {}'.format(token)
    }

    opticsTrigger = requests.get(url, headers=headers, data=payload)

    results = opticsTrigger.text
    parsed = json.loads(results)

    page_items = parsed["page_items"]
    
  
    for item in page_items: #A loop that will display each MAC Addressed assigned to the device list.
      duplicate = False

      status = item["Status"] # Get the status of the detection

      deviceDetails = item["Device"] #Prase the json value 'device_name' 
      deviceName = deviceDetails["Name"]

      detectionID = item["Id"]
      detection_date = item["OccurrenceTime"]
      severity = item["Severity"]
      received_date = item["ReceivedTime"]
      detection_description = item["DetectionDescription"]

      link = '=HYPERLINK("https://protect-euc1.cylance.com/Optics#/detect/' + detectionID + '", "Link")'
      
      
      appendedValues = (deviceName, detection_description)
      if appendedValues in data:
            duplicate == True
            continue
      else:
            data.append(appendedValues)
            opticsData = ["", "", "", link, deviceName, detectionID, detection_description, detection_date, received_date, severity, status]
            add_to_csv(output_file, opticsData)

    current_page += 1
    print(current_page)

### This is where we are going to loop through the pages if we are required to do so ####
create_csv_sheet()

def main():
    ## logging loop - try to do this, if it can't log the exception.
    try:
        get_detections_optics()
    except Exception as e:
      err_msg = str(e)
      if "page_items" in err_msg:
        print("Complete")
      else:
        print(e)

main()
