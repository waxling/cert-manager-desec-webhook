package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/nrdcg/desec"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"os"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}
	cmd.RunWebhookServer(GroupName,
		&desecDNSProviderSolver{},
	)
}

type desecDNSProviderSolver struct {
	client *kubernetes.Clientset
}

type desecDNSProviderConfig struct {
	APIKeySecretRef v1.SecretKeySelector `json:"apiKeySecretRef"`
}

func (c *desecDNSProviderSolver) Name() string {
	return "desec"
}

func (c *desecDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(1).Infof("preset record '%s'", ch.ResolvedFQDN)
	cfg, err := loadConfig(ch.Config)

	klog.V(5).Info("retrieving secret")
	apiToken, err := c.getSecretKey(cfg.APIKeySecretRef, ch.ResourceNamespace)
	klog.V(5).Info("creating desec client")
	api := c.getClient(apiToken)

	klog.V(1).Infof("retrieving domain %s", util.UnFqdn(ch.ResolvedZone))

	domain, subName, err := c.getRecordInfo(api, ch)
	if err != nil {
		return err
	}

	recordSet := new(desec.RRSet)
	recordSet.Domain = domain.Name
	recordSet.SubName = subName
	recordSet.Records = append(recordSet.Records, "\""+ch.Key+"\"")
	recordSet.Type = "TXT"
	recordSet.TTL = 3600

	klog.V(5).Info(recordSet)

	record, err := api.Records.Create(context.Background(), *recordSet)
	if err != nil {
		klog.Fatal(err)
		return err
	}

	klog.V(5).Infof("Record %s", record)
	return nil
}

func (c *desecDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(1).Infof("cleanup record '%s'", ch.ResolvedFQDN)
	cfg, err := loadConfig(ch.Config)

	apiToken, err := c.getSecretKey(cfg.APIKeySecretRef, ch.ResourceNamespace)
	api := c.getClient(apiToken)

	domain, subName, err := c.getRecordInfo(api, ch)
	if err != nil {
		return err
	}

	recError := api.Records.Delete(context.Background(), domain.Name, subName, "TXT")
	if recError != nil {
		return recError
	}
	klog.V(1).Infof("Record %s in zone %s deleted", subName, domain.Name)
	return nil
}

func (c *desecDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

func loadConfig(cfgJSON *extapi.JSON) (desecDNSProviderConfig, error) {
	cfg := desecDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (c *desecDNSProviderSolver) getDomain(client desec.Client, subname string) (*desec.Domain, error) {
	domains, err := client.Domains.GetAll(context.Background())
	if err != nil {
		panic(err)
	}

	for _, v := range domains {
		if strings.HasSuffix(subname, v.Name) {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("domain not found")
}

func (c *desecDNSProviderSolver) getRecordInfo(api desec.Client, ch *v1alpha1.ChallengeRequest) (*desec.Domain, string, error) {
	klog.V(5).Infof("%s record", ch.ResolvedFQDN)
	// Remove trailing dots from zone and fqdn
	zone := util.UnFqdn(ch.ResolvedZone)
	fqdn := util.UnFqdn(ch.ResolvedFQDN)

	domain, err := c.getDomain(api, zone)
	if err != nil {
		return nil, "", err
	}

	// Get the subdomain portion of fqdn
	subName := fqdn[:len(fqdn)-len(domain.Name)-1]

	return domain, subName, nil
}

func (c *desecDNSProviderSolver) getClient(apiToken string) desec.Client {
	return *desec.New(apiToken, desec.NewDefaultClientOptions())
}

// getSecretKey fetch a secret key based on a selector and a namespace
func (c *desecDNSProviderSolver) getSecretKey(secret v1.SecretKeySelector, namespace string) (string, error) {
	klog.V(5).Infof("retrieving key `%s` in secret `%s/%s`", secret.Key, namespace, secret.Name)

	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("secret `%s/%s` not found", namespace, secret.Name)
	}

	data, ok := sec.Data[secret.Key]
	if !ok {
		return "", fmt.Errorf("key `%q` not found in secret `%s/%s`", secret.Key, namespace, secret.Name)
	}

	return string(data), nil
}