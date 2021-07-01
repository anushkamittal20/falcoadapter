package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	//"time"

	"github.com/anushkamittal20/falcoadapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	policyreport "github.com/anushkamittal20/falcoadapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	client "github.com/anushkamittal20/falcoadapter/pkg/generated/v1alpha2/clientset/versioned"
	"github.com/falcosecurity/falcosidekick/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

type Alerts struct {
	Alert []types.FalcoPayload `json:"events,omitempty"`
}

func main() {
	//Getting output via falco sidekick webui/events
	resp, err := http.Get("http://localhost:2802/events")
	// Error checking of the http.Get() request
	if err != nil {
		log.Fatal(err)
	}
	// Resource leak if response body isn't closed
	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	// Error checking of the ioutil.ReadAll() request
	if err != nil {
		log.Fatal(err)
	}
	bodyString := string(bodyBytes)
	// Print Statements
	controls, err := convert(bodyString)
	if err != nil {
		os.Exit(-1)
	}

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
	report := &policyreport.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: "dummy-preport1",
		},
		Summary: v1alpha2.PolicyReportSummary{

			Fail: len(controls.Alert),
		},
	}
	for _, al := range controls.Alert {
		//Simply printing the output
		//fmt.Printf("Alert: \n Rule- %v\nPriority- %v\nTime- %v\nOutput- %v \n\n Output fields %v\n\n\n", al.Rule, al.Priority, al.Time, al.Output, al.OutputFields)

		r := newResult(al)
		report.Results = append(report.Results, r)

	}
	//fmt.Printf("\n\n\n %q,%q,%q,%q", report.Results[0].Policy, report.Results[1].Severity, report.Results[2].Result, report.Results[3].Description)
	// Create Policy report
	fmt.Println("Creating policy-report...")
	result, err := ats.Create(context.TODO(), report, metav1.CreateOptions{})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created policy-report %q.\n", result.GetObjectMeta().GetName())

}

func convert(jsonString string) (*Alerts, error) {
	jsonDataReader := strings.NewReader(jsonString)
	decoder := json.NewDecoder(jsonDataReader)
	var controls Alerts
	if err := decoder.Decode(&controls); err != nil {
		return nil, err
	}
	return &controls, nil
}

//basic mapping done
func newResult(FalcoPayload types.FalcoPayload) *policyreport.PolicyReportResult {

	var pri string
	if FalcoPayload.Priority > 4 {
		pri = "high"
	} else if FalcoPayload.Priority < 3 {
		pri = "low"
	} else {
		pri = "medium"
	}
	var m = make(map[string]string)
	for index, element := range FalcoPayload.OutputFields {
		m[index] = fmt.Sprintf("%v", element)
	}
	return &policyreport.PolicyReportResult{

		Policy: FalcoPayload.Rule,
		Scored: false,
		//Timestamp: metav1.Timestamp(time.Now()) ,
		Severity:    v1alpha2.PolicyResultSeverity(pri),
		Result:      "fail",
		Description: FalcoPayload.Output,
		Properties:  m,
	}
}
