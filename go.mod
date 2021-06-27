module github.com/anushkamittal20/falcoadapter

go 1.16

require (
	github.com/falcosecurity/falcosidekick v0.0.0-20210623203859-bd7f5fef3650
	k8s.io/api v0.20.5
	k8s.io/apimachinery v0.20.5
	k8s.io/client-go v11.0.0+incompatible
	sigs.k8s.io/controller-runtime v0.8.3
)

replace k8s.io/client-go => k8s.io/client-go v0.20.5

replace k8s.io/api => k8s.io/api v0.20.5
