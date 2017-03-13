import json
import base64
import splunk-sdk

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

moduleconfig = []

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)
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