# Cloud Security Principles
**with focus on securing enterprise kubernetes deployments**
References/Sources aggregated will be listed at the bottom of this document.

## Cloud Agnostic Bits
**Common attack vectors, best practices, and relevant documentation**
As you will see below, the actionable items follow the principals of Role-Based Access Control (RBAC) and, in general, exposing as little as possible to the outside world. The intern probably should not have full cluster access, nor should the disgruntled ex-employee have an IAM role allowing them to stop EC2 instances and delete EBS volumes. Mitigate risk by minimizing the amount of information and power users can obtain. Document and monitor everything.

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
Do not provide a straight public ssh acces to any k8s node. Instead, use a bastion host (jump box) where you expose only on one specific host from which you ssh into all other hosts.
* How to: https://www.nadeau.tv/ssh-with-a-bastion-host/
* Record SSH sessions:  https://aws.amazon.com/blogs/security/how-to-record-ssh-sessions-established-through-a-bastion-host/
If anything ssh is exposed to the public, it will be under constant attack. Minimize risk by blocking ssh from the public internet and instead introducing a hardened jump box.

#### *K8s Security Scans*
Eliminate configuration flaws and vulnerabilities via services like `kube-bench`. This applies a k8s security benchmark against the master and control plane components. It sets specific guidelines that help you secure your cluster setup.
* NOTE: `kube-bench` is not a possibility on master nodes in managed clusters, like AKS, but it may still be used on workers.
* https://github.com/aquasecurity/kube-bench
* CIS Benchmarks downloaded locally and will be uploaded to Confluence for further research.

#### *API Settings*
Authorization mode and anonymous auth: Use RBAC! Some installers, like `kops` use `AlwaysAllow` auth mode for the cluster. This _would_ grant any authenticated user full cluster access. Bad!
* Use `--authorization-mode` on `kube-apiserver` processes to find out what auth mode you currently use. https://kubernetes.io/docs/admin/authorization/
* To enforce your authentication rules, make sure anonymous auth is **disabled** by setting `--anonymous-auth=false`.

Insecure Ports: an API port without any SSL/TLS, auth, authz, etc... protection. Disable any ports like this within `--insecure-port=0` (depracated after 1.10).
* If impossible to disable, firewall the port from public and internal access.

Profiling: Disable it. Set `--profiling=false`. Program and system info can be sniffed out via profiling, specifically vulnerable to DoS.

AdmissionController: Add some plugins to `--admission-control=...`!
* `AlwaysPullImages`: By default, pods can specify their own image pull policy. Essentially this forces credentials to be provided every time an image is being pulled/accessed. Otherwise, another pod _could_ access stored images to dig up confidential info.
* `DenyEscalatingExec`: If a pod is scheduled with `privileged:true`,`hostPID: true`, or `hostIPC: true` a #hackerman could escalate privileges through attaching to a privileged pod or executing a command in it. This plugin denies attach and exec for those pods.
* `PodSecurityPolicy`: If not set, Pod Security Policies **are NOT** enforced and pods violating those policies will still be scheduled. Make sure you have Security Policies already in place before setting this, otherwise pods will fail to be scheduled.

Kubelet Settings: by default, the kubelet offers a command API used by the kube-apiserver. Using this, one may execute commands on a specific node. To secure, firewall port `10250/TCP` (listed above also), and set `--authorization-mode=Webhook` and `anonymous-auth=false`.

#### **

#### **

#### **

## Sources:
* https://github.com/freach/kubernetes-security-best-practice
* https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-1/
* https://www.youtube.com/watch?v=vTgQLzeBfRU
* https://www.youtube.com/watch?v=ohTq0no0ZVU
* https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/
* https://www.coursera.org/learn/cloud-security-basics/home/welcome
