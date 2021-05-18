.PHONY: test

test:
	../ansible/hacking/test-module -m ./nexus  -a "nexus_endpoint=http://nexus.apps.kubernetes.local username=jenkins-nexus password=jenkins artifact_id=org.redhat:openshift-demo-application-quarkus-runner:1.1.0-SNAPSHOT artifact_format=jar target=/tmp/artifact.jar"
