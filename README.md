# Cloud Security Principles
**with focus on securing enterprise kubernetes deployments**
References/Sources aggregated will be listed at the bottom of this document.

## Cloud Agnostic Bits
**Common attack vectors, best practices, and relevant documentation**

#### *Secure the system/OS you run on your clusters.*
  * https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/pdf/security_guide/Red_Hat_Enterprise_Linux-6-Security_Guide-en-US.pdf

#### *Private Topology*
If your nodes use private IP's, the cluster should live in a private subnet/VPC.

#### *Firewall Ports*
  * Don't expose ports to the network that don't need to be exposed.
  * Every exposed port is a possible attack vector.
  * **IF** you can define a listen IP/interface to bind a service to (127.0.0.1/lo), do that. **ELSE** firewall the port.
```
   PORT   |    PROCESS     |  DESC
4149/tcp  | kubelet        | Default cAdvisor port used to query container metrics.
10250/tcp | kubelet        | API which allows full node access.
10255/tcp | kubelet        | Unauth read-only port that allows access to node state.
10256/tcp | kube-proxy     | Health check server for kube proxy.
9099/tcp  | calico-felix   | Health check server for Calico.
6443/tcp  | kube-apiserver | Kubernetes API port.
```
Note: Health check ports are not generally attack vectors. However, the network provider could be DoS'ed through an exposed health check port, which would affect a whole cluster.

#### *Bastion Host*
Do not provide a straight public ssh acces to any k8s node. Instead, use a bastion host (jump box)


#### **

#### **

#### **

## Sources:
https://github.com/freach/kubernetes-security-best-practice
https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-1/
https://www.youtube.com/watch?v=vTgQLzeBfRU
https://www.youtube.com/watch?v=ohTq0no0ZVU
https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/
https://www.coursera.org/learn/cloud-security-basics/home/welcome
