import json
import base64
import urllib
import httplib2
from xml.dom import minidom
import time

misperrors = {'error': 'Error'}
userConfig = {
               'splunk_es_server': {
                 'type': 'String',
                 'message': 'Hostname/FQDN of your Splunk ES server'
               },
               'splunk_es_server_port': {
                 'type': 'Integer',
                 'regex': '/^[0-9]{1,4}$/i',
                 'errorMessage': 'Expected a number in range [0-9]',
                 'message': 'Management port for your Splunk ES server (Default: 8089)'
               },
               'ip_intel': {
                 'type': 'Boolean',
                 'message': 'Import IP intel artifacts'
               },
               'file_intel': {
                 'type': 'Boolean',
                 'message': 'Import file intel artifacts'
               },
               'email_intel': {
                 'type': 'Boolean',
                 'message': 'Import email intel artifacts'
               },
               'process_intel': {
                 'type': 'Boolean',
                 'message': 'Import process intel artifacts'
               },
               'service_intel': {
                 'type': 'Boolean',
                 'message': 'Import service intel artifacts'
               }
             };

inputSource = []

moduleinfo = {'version': '0.1', 'author': 'Ryan LeViseur',
              'description': 'Runs search and imports threat intelligence artifacts from Splunk Enterprise Security.',
              'module-type': ['import']}

moduleconfig = [ 'splunk_es_server', 'splunk_es_server_port' ]

def handler(q=False):
  if q is False:
      return False
  request = json.loads(q)
  config = q.get("config", {})

  baseurl = "https://{0}:{1}".format(config.get("splunk_es_server", None),
                                     config.get("splunk_es_server_port", None))
  userName = 'admin'
  password = 'changeme'

  # limit results to 10 while testing
  searchQuery = '| `ip_intel` | head 10'

  # Auth with Splunk server to get a session key
  sessionKey = splunkLogin(userName, password, baseurl)

  # Execute the Splunk search
  searchId = splunkSearch(searchQuery, sessionKey, baseurl)

  # Wait for search to complete
  done = 0
  while done is not 1:
    done = getSplunkSearchStatus(searchId, sessionKey, baseurl)
    # take a quick nap so we don't hammer the Splunk server
    time.sleep(5)

  # Pull down search results from Splunk server  
  searchResults = getSplunkSearchResults(searchId, sessionKey, baseurl)

  # For now just return request to get basic skel of module working
  return request

def introspection():
  modulesetup = {}
  try:
      userConfig
      modulesetup['userConfig'] = userConfig
  except NameError:
      pass
  try:
      inputSource
      modulesetup['inputSource'] = inputSource
  except NameError:
      pass
  return modulesetup

def version():
  moduleinfo['config'] = moduleconfig
  return moduleinfo

def splunkLogin(user, password, baseurl)
  # Authenticate with server.
  # Disable SSL cert validation. Splunk certs are self-signed.
  serverContent = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + '/services/auth/login',
      'POST', headers={}, body=urllib.urlencode({'username':userName, 'password':password}))[1]

  return minidom.parseString(serverContent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue

def splunkSearch(searchQuery, sessionKey, baseurl)
  # Remove leading and trailing whitespace from the search
  searchQuery = searchQuery.strip()

  # If the query doesn't already start with the 'search' operator or another 
  # generating command (e.g. "| inputcsv"), then prepend "search " to it.
  if not (searchQuery.startswith('search') or searchQuery.startswith("|")):
      searchQuery = 'search ' + searchQuery

  # Execute the search. Returns the search job ID.
  searchJob = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + '/services/search/jobs','POST',
  headers={'Authorization': 'Splunk %s' % sessionKey},body=urllib.urlencode({'search': searchQuery}))[1]

  jobID = minidom.parseString(searchJob).getElementsByTagName('sid')[0].childNodes[0].nodeValue

  return jobID

def getSplunkSearchStatus(jobId, sessionKey, baseurl)
  # Check the status of the search job
  jobStatus = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + '/services/search/jobs/%s' % jobId,'GET',
  headers={'Authorization': 'Splunk %s' % sessionKey},)[1]

  jobInfo = minidom.parseString(jobStatus).getElementsByTagName('s:key')
  for element in jobInfo:
    if element.getAttribute('name') == "isDone":
      return element.childNodes[0].nodeValue

def getSplunkSearchResults(jobId, sessionKey, baseurl)
  # Pull down the results of the search
  results = httplib2.Http(disable_ssl_certificate_validation=True).request(baseurl + '/services/search/jobs/%s/results' % jobId,'GET',
  headers={'Authorization': 'Splunk %s' % sessionKey},)[1]

  return results