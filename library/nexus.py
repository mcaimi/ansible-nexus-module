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
    repository:
        description:
            - The name of the repository on Nexus where to scope all API operations
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
      repository: "maven-snapshots"
      target: "/tmp/demoapp.jar"

- name: Upload an artifact to Nexus
      username: test@redhat.com
      pass: redhat123
      nexus_endpoint: "https://nexus.domain.tld"
      artifact_id: "org.redhat:demo-app:1.1.0-RELEASE"
      repository: "maven-releases"
      operation: "PUT"
      artifact_format: "JAR"
      source: "/repo/artifact.jar"
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
import requests
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

class AlreadyExistsException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(self, *args, **kwargs)

NEXUS_DOWNLOAD_PATH = "service/rest/v1/search/assets"
NEXUS_UPLOAD_PATH = "service/rest/v1/components"
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
        self.md5computer = md5()
        self.sha1computer = sha1()
        self.HASH_BUFFER_SIZE = 64*1024

    def _compute_hashes(self, filename):
        with open(filename, 'rb') as descriptor:
            while True:
                chunk = descriptor.read(self.HASH_BUFFER_SIZE)
                if not chunk:
                    break
                self.md5computer.update(chunk)
                self.sha1computer.update(chunk)

        return ("{0}".format(self.md5computer.hexdigest()), "{0}".format(self.sha1computer.hexdigest()))

    def push_artifact(self):
        # requred api parameters
        parameters = {
            "repository": self.parm_hash.repository
        }

        # build upload endpoint
        upload_endpoint = "/".join([self.base_url, NEXUS_UPLOAD_PATH])

        # upload artifact
        try:
            with open(self.parm_hash.source, 'rb') as fd:
                files = {
                    'maven2.groupId': (None, self.parm_hash.artifact.groupID),
                    'maven2.artifactId': (None, self.parm_hash.artifact.ID),
                    'maven2.version': (None, self.parm_hash.artifact.version),
                    'maven2.asset1': (self.parm_hash.artifact.ID, fd),
                    'maven2.asset1.extension': (None, self.parm_hash.artifact.format),
                }
                self.upload_response = requests.post(url=upload_endpoint,
                                        files=files,
                                        params=parameters,
                                        auth=(self.parm_hash.username, self.parm_hash.password))

            # handle errors
            if (self.upload_response.status_code == 403):
                raise PermissionError("Insufficient Permissions for Artifact Upload.")
            elif (self.upload_response.status_code == 422):
                raise MalformedArgumentException("Parameter 'repository' is mandatory")
        except Exception as e:
            raise Exception(e.__str__())

        return { 'message': "Artifact %s uploaded, status_code %d" % (self.parm_hash.source, self.upload_response.status_code) }

    def pull_artifact(self):
        self.base_search_url = "/".join([self.base_url, NEXUS_DOWNLOAD_PATH])

        # search parameters
        search_params = {
            'sort': 'version',
            'repository': self.parm_hash.repository,
            'group': self.parm_hash.artifact.groupID,
            'name': self.parm_hash.artifact.ID,
            'version': self.parm_hash.artifact.version,
            'maven.extension': self.parm_hash.artifact.format,
            'maven.classifier': None
        }

        try:
            self.search_results = requests.get(url=self.base_search_url,
                                            auth=(self.parm_hash.username, self.parm_hash.password),
                                            params=search_params)

            if self.search_results.status_code == 200:
                content = Wrapper(loads(self.search_results.text))

                if not len(content.items) > 0:
                    raise FetchError("Artifact Not Found")

                downloadUrl = content.items[0].downloadUrl
                shaDigest = content.items[0].checksum.sha1
                md5Digest = content.items[0].checksum.md5

                # download artifact...
                download_request = requests.get(downloadUrl, auth=(self.parm_hash.username, self.parm_hash.password))

                out_file = self.parm_hash.deploy_dir
                with open(out_file, "wb") as descriptor:
                    file_size = int(download_request.headers.get("Content-Length"))

                    downloaded_so_far = 0
                    tx_size = 8192
                    for chunk in download_request.iter_content(chunk_size=tx_size):
                        downloaded_so_far += len(chunk)
                        descriptor.write(chunk)

                md5Hash, sha1Hash = self._compute_hashes(out_file)

                if not all([md5Digest == md5Hash, shaDigest == sha1Hash]):
                    raise FileCorruptedException("Hashes do not match for downloaded artifact")
                if not downloaded_so_far == file_size:
                    raise FileCorruptedException("Downloaded file size does not match content-length")
                else:
                    return { "message": "Hashes match: download is OK" }

            else:
                raise FetchError("Got HTTP code %s" % self.search_results.code)
        except Exception as url_exception:
            raise FetchError(url_exception.__str__())

# module handler function
def nexus_module():
    # module options
    module_args = dict(
            username = dict(type='str', required=True),
            password = dict(type='str', required=True, no_log=True),
            target = dict(type='str', required=False, default=None),
            repository = dict(type='str', required=True),
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
    repository = nexus_module_instance.params.get('repository')
    artifact_id = nexus_module_instance.params.get('artifact_id')
    operation = nexus_module_instance.params.get('operation')
    source = nexus_module_instance.params.get('source')
    artifact_format = nexus_module_instance.params.get('artifact_format')

    # results dict
    res_args = dict(
        changed = False,
        message = "Undefined"
    )

    if not (artifact_format.upper() in SUPPORTED_FORMATS):
        nexus_module_instance.fail_json(msg=str(MalformedArgumentException("Unsupported Artifact format: got [%s]", artifact_format)), **res_args)

    if not (operation in MODULE_OPERATIONS):
        nexus_module_instance.fail_json(msg=str(InvalidOperationException("Unsupported module operation requested. [%s]", operation)), **res_args)

    parameter_hash = {
        "username": username,
        "password": password,
        "repository": repository,
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
                    res_args['message'] = "KO"
                    nexus_module_instance.fail_json(msg=str(makedir_exception), **res_args)

        parameter_hash['artifact'] = artifact
        parameter_hash['deploy_dir'] = target

        # Create an instance of NexusAdapter class
        nexus_adapter = NexusAdapter(Wrapper(parameter_hash))

        # get the artifact
        try:
            res_args['message'] = nexus_adapter.pull_artifact().get('message')
            res_args['changed'] = True
        except FetchError as fe:
            res_args['message'] = "KO"
            nexus_module_instance.fail_json(msg=str(fe), **res_args)
        except FileCorruptedException as fce:
            res_args['message'] = "KO"
            nexus_module_instance.fail_json(msg=str(fce), **res_args)
    elif (operation == "PUT"):
        # check whether source file exists
        if not os.path.isfile(source):
            nexus_module_instance.fail_json(msg="Source file %s does not exist" % source, **res_args)

        parameter_hash['source'] = source
        parameter_hash['artifact'] = artifact

        try:
            nexus_adapter = NexusAdapter(Wrapper(parameter_hash))
            res_args['message'] = nexus_adapter.push_artifact().get('message')
            res_args['changed'] = True
        except PermissionError as pe:
            res_args['message'] = "PermissionError"
            nexus_module_instance.fail_json(msg=str(pe), **res_args)
        except MalformedArgumentException as me:
            res_args['message'] = "Malformed Input: missing required parameter"
            nexus_module_instance.fail_json(msg=str(me), **res_args)
        except Exception as e:
            res_args['message'] = "KO"
            nexus_module_instance.fail_json(msg=str(e), **res_args)
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


