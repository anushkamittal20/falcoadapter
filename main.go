package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"

	policyreport "github.com/anushkamittal20/falcoadapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	client "github.com/anushkamittal20/falcoadapter/pkg/generated/v1alpha2/clientset/versioned"
	"github.com/falcosecurity/falcosidekick/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v2"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Alerts struct {
	Alert []types.FalcoPayload `json:"events,omitempty"`
}

func main() {
	// resp, err := http.Get("http://localhost:2802/events")
	// // Error checking of the http.Get() request
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// // Resource leak if response body isn't closed
	// defer resp.Body.Close()
	// bodyBytes, err := ioutil.ReadAll(resp.Body)
	// // Error checking of the ioutil.ReadAll() request
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// bodyString := string(bodyBytes)
	// // Print Statements
	// controls, err := convert(bodyString)
	// if err != nil {
	// 	os.Exit(-1)
	// }
	// report := &policyreport.PolicyReport{}
	// for _, al := range controls.Alert {
	// 	fmt.Printf("Alert: \n Rule- %v\nPriority- %v\nTime- %v\nOutput- %v \n\n Output fields %v\n\n\n", al.Rule, al.Priority, al.Time, al.Output, al.OutputFields)
	// 	r := newResult(al)
	// 	report.Results = append(report.Results, r)
	// 	// if al.Priority == "" {
	// 	// }
	// 	//fmt.Printf(r.Rule)
	// }
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err)
	}
	clientset, err := client.NewForConfig(config)
	if err != nil {
		panic(err)
	}
	ats := clientset.Wgpolicyk8sV1alpha2().PolicyReports("default")
	deployment := &policyreport.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "sample-policy-report",
		},
	}
	// Create Deployment
	fmt.Println("Creating policy-report...")
	result, err := ats.Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created policy-report %q.\n", result.GetObjectMeta().GetName())
}

// func convert(jsonString string) (*Alerts, error) {
// 	jsonDataReader := strings.NewReader(jsonString)
// 	decoder := json.NewDecoder(jsonDataReader)
// 	var controls Alerts
// 	if err := decoder.Decode(&controls); err != nil {
// 		return nil, err
// 	}
// 	return &controls, nil
// }
// func newResult(FalcoPayload types.FalcoPayload) *policyreport.PolicyReportResult {
// 	return &policyreport.PolicyReportResult{
// 		Policy: FalcoPayload.Rule,
// 		//Rule:        group.Text,
// 		Severity:    policyreport.PolicyResultSeverity(FalcoPayload.Priority),
// 		Result:      "fail",
// 		Description: FalcoPayload.Output,
// 	}
// }
