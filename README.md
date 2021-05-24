# Ansible Module to interact with Sonatype Nexus

An extremely simple implementation of Nexus3 upload/download APIs for Ansible.
Requires:

 * python-requests
 * python3
 * ansible 3+

## Artifact Upload Example

```yaml
    - name: Upload an artifact to nexus
      nexus:
        nexus_endpoint: "http://nexus.apps.kubernetes.local"
        username: "jenkins-nexus"
        password: "jenkins"
        artifact_id: "org.redhat:new-application-artifact:1.0.0-RELEASE"
        artifact_format: "jar"
        source: "/tmp/artifact.jar"
        operation: "PUT"
        repository: "maven-releases"
```

## Artifact Download Example

```yaml
    - name: Download an  artifact from Nexus repo
      nexus:
        nexus_endpoint: "http://nexus.apps.kubernetes.local"
        username: "jenkins-nexus"
        password: "jenkins"
        artifact_id: "org.redhat:openshift-demo-application-quarkus-runner:1.1.1-SNAPSHOT.12"
        artifact_format: "jar"
        target: "/tmp/artifact.jar"
        repository: "maven-snapshots"
```

## TODO

 * Better error handling
 * Better Nexus API usage

