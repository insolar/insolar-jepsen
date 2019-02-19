#!/usr/bin/env python3

template = """
kind: Service
apiVersion: v1
metadata:
  name: jepsen-1
spec:
  type: NodePort
  ports:
    - port: 22
      nodePort: 32001
  selector:
    name: jepsen-1
---
apiVersion: v1
kind: Pod
metadata:
  name: jepsen-1
  labels:
    name: jepsen-1
spec:
  containers:
    - name: jepsen-1
      image: ubuntu-ssh:latest
      imagePullPolicy: Never
      securityContext:
        privileged: true
      ports:
        - containerPort: 22
---
"""

for i in range(0, 5):
    node_name = "jepsen-"+str(i+1)
    descr = template.replace("jepsen-1", node_name)
    print(descr)
