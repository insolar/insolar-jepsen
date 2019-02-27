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
    app: insolar-jepsen
spec:
  containers:
    - name: jepsen-1
      image: insolar-jepsen:latest
      imagePullPolicy: Never
      securityContext:
        capabilities:
          add:
            - NET_ADMIN
#        privileged: true
      ports:
        - containerPort: 22
#    nodeSelector:
#      jepsen: "true"
---
"""

for i in range(0, 5+1): # 5 nodes + pulsar
    node_name = "jepsen-"+str(i+1)
    port = str(32001 + i)
    descr = template.replace("jepsen-1", node_name)
    descr = descr.replace("32001", port)
    print(descr)
