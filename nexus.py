#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

DOCUMENTATION = r'''
module: nexus
version: 0.1
options:
    username:
        description: 
            - Username to use when connecting to Nexus
        required: False
    password:
        description:
            - Authentication password
        required: False
    nexus_endpoint:
        description:
            - The URL where the Nexus Server is listening.
        required: True
    artifact_id:
        description:
            - The Artifact ID to pull from Nexus
        required: True
    operation:
        description:
            - Operation to perform: GET or PUT. Default is 'GET'
        required: False
    source:
        description:
            - Filename to upload to Nexus
        required: False
    target:
        description:
            - Target filename where to locally save the artifact. It *MUST* reference a filename.
        required: False
    artifact_format:
        description:
            - Format of the remote artifact that needs to be fetched. Default is 'WAR'
        required: False
description:
    - Interact with Sonatype Nexus: Upload, Download and Get info about artifacts.
'''

EXAMPLES = r'''
- name: Download Java Artifact
  nexus:
      username: test@redhat.com
      pass: redhat123
      nexus_endpoint: "https://nexus.domain.tld"
      artifact_id: "org.redhat:demo-app:1.1.0-SNAPSHOT"
      target: "/tmp/demoapp.jar"
'''

RETURN = r'''
message:
    description: Return message from module run
    type: str
    returned: always
    sample: "OK"
'''

from ansible.module_utils.basic import AnsibleModule
from hashlib import sha1, md5
import base64
import os,re,sys,errno
from urllib import request, error
from json import loads

class MalformedArgumentException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

class MissingArgumentException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

class InvalidOperationException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

class InvalidPathException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

class FetchError(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

class FileCorruptedException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

NEXUS_REST_PATH = "service/rest/v1/search/assets"
MODULE_OPERATIONS = ["GET", "PUT"]
SUPPORTED_FORMATS = ["WAR", "JAR"]

# Parsed options wrapper
class Wrapper():
    def __init__(self, hash_info):
        if not (hash_info.__class__ == dict):
            raise MalformedArgumentException("Parameter class is not Hash, got [%s]" % hash_info.__class__)

        self._wrap(hash_info)

    def _wrap(self, infos):
        for key in infos.keys():
            element = infos.get(key)
            if element.__class__ == dict:
                setattr(self, key, Wrapper(element))
            elif element.__class__ == list:
                setattr(self, key, [])
                embedded_list = getattr(self, key)
                for item in element:
                    embedded_list.append(Wrapper(item))
            else:
                setattr(self, key, element)

# Nexus Adapter
class NexusAdapter():
    def __init__(self, parameters):
        self.parm_hash = parameters
        self.base_url = "%s" % (self.parm_hash.nexus_url)
        self.base_search_url = "%s/%s?sort=version" % (self.base_url, NEXUS_REST_PATH)
        self.base_download_url = "%s/%s/download?sort=version" % (self.base_url, NEXUS_REST_PATH)
        self.md5computer = md5()
        self.sha1computer = sha1()
        self.HASH_BUFFER_SIZE = 64*1024

    def build_search_parameters(self):
        self.url_parameters = "&group=%s&name=%s&maven.extension=%s&maven.classifier" % (self.parm_hash.artifact.groupID,
                                                                                        self.parm_hash.artifact.ID,
                                                                                        self.parm_hash.artifact.format)

    def _compute_hashes(self, filename):
        with open(filename, 'rb') as descriptor:
            while True:
                chunk = descriptor.read(self.HASH_BUFFER_SIZE)
                if not chunk:
                    break
                self.md5computer.update(chunk)
                self.sha1computer.update(chunk)

        return ("{0}".format(self.md5computer.hexdigest()), "{0}".format(self.sha1computer.hexdigest()))

    def pull_artifact(self):
        url_to_get = "%s%s" % (self.base_search_url, self.url_parameters)

        auth_hash = base64.b64encode(bytes("%s:%s" % (self.parm_hash.username, self.parm_hash.password), 'ascii'))

        http_request_object = request.Request(url_to_get)
        http_request_object.add_header('Authorization', 'Basic %s' % auth_hash.decode())
        try: 
            self.search_results = request.urlopen(http_request_object)

            if self.search_results.code == 200:
                content = Wrapper(loads(self.search_results.read().decode()))

                if not len(content.items) > 0:
                    raise FetchError("Artifact Not Found") 

                downloadUrl = content.items[0].downloadUrl
                shaDigest = content.items[0].checksum.sha1
                md5Digest = content.items[0].checksum.md5

                # download artifact...
                download_request = request.Request(downloadUrl)
                download_request.add_header('Authorization', 'Basic %s' % auth_hash.decode())
                download_object = request.urlopen(download_request)
                download_info = download_object.info()

                out_file = self.parm_hash.deploy_dir
                with open(out_file, "wb") as descriptor:
                    file_size = int(download_info["Content-Length"])

                    downloaded_so_far = 0
                    tx_size = 8192
                    while True:
                        buffer = download_object.read(tx_size)
                        if not buffer:
                            # no more bytes in stream
                            break

                        downloaded_so_far += len(buffer)
                        descriptor.write(buffer)
                        status = r"%10d  [%3.2f%%]" % (downloaded_so_far, downloaded_so_far * 100. / file_size)
                        status = status + chr(8)*(len(status)+1)

                md5Hash, sha1Hash = self._compute_hashes(out_file)

                if not all([md5Digest == md5Hash, shaDigest == sha1Hash]):
                    raise FileCorruptedException("Hashes do not match for downloaded artifact")
                else:
                    return { "message": "Hashes match: download is OK" }

            else:
                raise FetchError("Got HTTP code %s" % self.search_results.code)
        except error.HTTPError as url_exception:
            raise FetchError(url_exception.__str__())

# module handler function
def nexus_module():
    # module options
    module_args = dict(
            username = dict(type='str', required=True),
            password = dict(type='str', required=True, no_log=True),
            target = dict(type='str', required=False, default=None),
            nexus_endpoint = dict(type='str', required=True),
            artifact_id = dict(type='str', required=True),
            operation = dict(type='str', required=False, default="GET"),
            source = dict(type='str', required=False, default=None),
            artifact_format = dict(type='str', required=False, default="WAR")
        )

    # declare module
    nexus_module_instance = AnsibleModule(argument_spec=module_args)

    # populate options from task
    username = nexus_module_instance.params.get('username')
    password = nexus_module_instance.params.get('password')
    nexus_endpoint = nexus_module_instance.params.get('nexus_endpoint')
    target = nexus_module_instance.params.get('target')
    artifact_id = nexus_module_instance.params.get('artifact_id')
    operation = nexus_module_instance.params.get('operation')
    source = nexus_module_instance.params.get('source')
    artifact_format = nexus_module_instance.params.get('artifact_format')

    # results dict
    res_args = dict(
        changed = False,
        message = "OK"
    )

    if not (artifact_format.upper() in SUPPORTED_FORMATS):
        nexus_module_instance.fail_json(msg=str(MalformedArgumentException("Unsupported Artifact format: got [%s]", artifact_format)), **res_args)

    if not (operation in MODULE_OPERATIONS):
        nexus_module_instance.fail_json(msg=str(InvalidOperationException("Unsupported module operation requested. [%s]", operation)), **res_args)

    parameter_hash = {
        "username": username,
        "password": password,
        "nexus_url": nexus_endpoint
    }

    # get artifact metadata from module parameters
    artifact_tokens = artifact_id.split(":")
    artifact = {
            "groupID": artifact_tokens[0],
            "ID": artifact_tokens[1],
            "version": artifact_tokens[2],
            "format": artifact_format
        }

    if (operation == "GET"):
        # File already exists
        if os.path.isfile(target):
            nexus_module_instance.params['path'] = target
            file_args = nexus_module_instance.load_file_common_arguments(nexus_module_instance.params)
            file_args['path'] = target
            changed = nexus_module_instance.set_fs_attributes_if_different(file_args, False)

            # something changed...
            if changed:
                nexus_module_instance.exit_json(message="file already exists but file attributes changed", target=target, changed=changed)
            nexus_module_instance.exit_json(message="file already exists", target=target, changed=changed)
        else:
            # create directory structure
            target_dir = os.path.dirname(target)
            try:
                os.makedirs(target_dir)
            except OSError as makedir_exception:
                if makedir_exception.errno == errno.EEXIST and os.path.isdir(target_dir):
                    pass
                else:
                    nexus_module_instance.fail_json(msg=str(makedir_exception), **res_args)

        parameter_hash['artifact'] = artifact
        parameter_hash['deploy_dir'] = target

        # Create an instance of NexusAdapter class
        nexus_adapter = NexusAdapter(Wrapper(parameter_hash))

        # get the artifact
        try:
            nexus_adapter.build_search_parameters()
            nexus_adapter.pull_artifact()
            res_args['changed'] = True
        except FetchError as fe:
            nexus_module_instance.fail_json(msg=str(fe), **res_args)
        except FileCorruptedException as fce:
            nexus_module_instance.fail_json(msg=str(fce), **res_args)
    else:
        pass

    # terminale module run
    nexus_module_instance.exit_json(**res_args)

# main method
def main():
    nexus_module()

# MAIN
if __name__=="__main__" :
    main()


