# Falcoadapter
Using this code we can create policy report by [CRD definition]{https://github.com/kubernetes-sigs/wg-policy-prototypes/blob/master/policy-report/README.md}
for Falco events using falcosidekick to give us the Falco JSON output.

The code is initial work on building a policy adapter for falcosidekick. 

To test this code follow the steps 
1. Create cluster using kind (Configuration: [kind-config.yaml]{https://gist.github.com/anushkamittal20/0e21b237b6ff98773675edf4e58be96a})
```
 kind create cluster --config=kind-config.yaml
 ```
2. Add required charts
 ```
helm repo add falcosecurity https://falcosecurity.github.io/charts
```
3. Update
```
helm repo update 
```
4. Install falco and enable falcosidekick and falcosidekick-ui
```
 helm install falco falcosecurity/falco --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=true
 ```
5. Check if all pods are running
```
kubectl get all
```
6. Port forward falco sidekick to 2801 and falco sidekick to 2802
```
 kubectl port-forward svc/falco-falcosidekick 2801
 kubectl port-forward svc/falco-falcosidekick-ui 2802
```
Now clone the repository and create policy reports by creating crd using the command
```
kubectl create -f kubernetes/crd/v1alpha2/wgpolicyk8s.io_policyreports.yaml
```
and then run the program
`go run main.go`
and to check the created policy report
```
kubectl get policyreports -o yaml > res.yaml
```

 





