import requests, base64
import os
from dotenv import load_dotenv 
load_dotenv()
base_url = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VT_API_KEY")

def encodeUrl(url):
   return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

#get data from VT API ------------------------------------------
def getData(url):
  vt_url = f"{base_url}/{url}"
  headers = {
      'x-apikey' : VT_API_KEY
  }
  response = requests.get(vt_url, headers=headers)
  if(response.status_code==200):
    return response.json()
  print("Error : Couldn't fetch data")
  return None

#check if a target is malicious ---------------------------------------------------
def isMalicious(target):
    url = encodeUrl(target)
    data = getData(f"urls/{url}")
    if(data==None):
       print("No data found.")
       return False
    return data["data"]["attributes"]["last_analysis_stats"]["malicious"]>0

def run_vt_scan(target):
    url = encodeUrl(target)
    data = getData(f"urls/{url}")
    if(data==None):
       print("No data found.")
       return
    newData =  {
        "total_votes" : data["data"]["attributes"]["total_votes"],
        "total_agents" : sum(val for val in data["data"]["attributes"]["last_analysis_stats"].values()),
        "last_analysis_date" : data["data"]["attributes"]["last_analysis_date"],
        "last_analysis_stats" : data["data"]["attributes"]["last_analysis_stats"],
        "malicious_outlinks" : 0,
        "reputation" : data["data"]["attributes"]["reputation"],
    }

    #checking if any redirects are malicious
    for link in set(data["data"]["attributes"]["outgoing_links"][:10]):
       if(isMalicious(link)):
          newData["malicious_outlinks"] += 1
    return newData



# import requests, base64
# import os
# from dotenv import load_dotenv 
# load_dotenv()
# base_url = "https://www.virustotal.com/api/v3"
# VT_API_KEY = os.getenv("VT_API_KEY")

# def encodeUrl(url):
#    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# def getData(url):
#   vt_url = f"{base_url}/{url}"
#   headers = {
#       'x-apikey' : VT_API_KEY
#   }
#   response = requests.get(vt_url, headers=headers)
#   if(response.status_code==200):
#     return response.json()
#   print("Error : Couldn't fetch data")
#   return None

# def isMalicious(target):
#     url = encodeUrl(target)
#     data = getData(f"urls/{url}")
#     if(data==None):
#        print("No data found.")
#        return False
#     return data["data"]["attributes"]["last_analysis_stats"]["malicious"]>0

# def run_vt_scan(target):
#     url = encodeUrl(target)
#     data = getData(f"urls/{url}")
#     if(data==None):
#        print("No data found.")
#        return
#     newData =  {
#         "total_votes" : data["data"]["attributes"]["total_votes"],
#         "total_agents" : sum(val for val in data["data"]["attributes"]["last_analysis_stats"].values()),
#         "last_analysis_date" : data["data"]["attributes"]["last_analysis_date"],
#         "last_analysis_stats" : data["data"]["attributes"]["last_analysis_stats"],
#         "malicious_outlinks" : 0,
#         "reputation" : data["data"]["attributes"]["reputation"],
#     }
#     for link in set(data["data"]["attributes"]["outgoing_links"][:10]):
#        if(isMalicious(link)):
#           newData["malicious_outlinks"] += 1
#     return newData

# print(run_vt_scan("scanme.nmap.org"))
