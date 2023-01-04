package inwx

import (
	"fmt"
	"time"

	"github.com/kolo/xmlrpc"
	"github.com/mitchellh/mapstructure"
	"github.com/pquerna/otp/totp"
)

type client struct {
	rpcClient *xmlrpc.Client
}

type response struct {
	Code         int    `xmlrpc:"code"`
	Message      string `xmlrpc:"msg"`
	ReasonCode   string `xmlrpc:"reasonCode"`
	Reason       string `xmlrpc:"reason"`
	ResponseData any    `xmlrpc:"resData"`
}

type errorResponse struct {
	Code       int    `xmlrpc:"code"`
	Message    string `xmlrpc:"msg"`
	ReasonCode string `xmlrpc:"reasonCode"`
	Reason     string `xmlrpc:"reason"`
}

type nameserverInfoRequest struct {
	Domain   string `xmlrpc:"domain,omitempty"`
	Name     string `xmlrpc:"name,omitempty"`
	Type     string `xmlrpc:"type,omitempty"`
	Content  string `xmlrpc:"content,omitempty"`
	TTL      int    `xmlrpc:"ttl,omitempty"`
	Priority int    `xmlrpc:"prio,omitempty"`
}

type nameserverInfoResponse struct {
	RoID    int                `mapstructure:"roId"`
	Domain  string             `mapstructure:"domain"`
	Type    string             `mapstructure:"type"`
	Count   int                `mapstructure:"count"`
	Records []nameserverRecord `mapstructure:"record"`
}

type nameserverCreateRecordRequest struct {
	Domain   string `xmlrpc:"domain"`
	Name     string `xmlrpc:"name"`
	Type     string `xmlrpc:"type"`
	Content  string `xmlrpc:"content"`
	TTL      int    `xmlrpc:"ttl"`
	Priority int    `xmlrpc:"prio"`
}

type nameserverCreateRecordResponse struct {
	ID int `mapstructure:"id"`
}

type nameserverUpdateRecordRequest struct {
	ID       int    `xmlrpc:"id"`
	Name     string `xmlrpc:"name"`
	Type     string `xmlrpc:"type"`
	Content  string `xmlrpc:"content"`
	TTL      int    `xmlrpc:"ttl"`
	Priority int    `xmlrpc:"prio"`
}

type nameserverDeleteRecordRequest struct {
	ID int `mapstructure:"id"`
}

type nameserverRecord struct {
	ID       int    `mapstructure:"id"`
	Name     string `mapstructure:"name"`
	Type     string `mapstructure:"type"`
	Content  string `mapstructure:"content"`
	TTL      int    `mapstructure:"ttl"`
	Priority int    `mapstructure:"prio"`
}

type nameserverCreateRequest struct {
	Domain string   `xmlrpc:"domain"`
	Type   string   `xmlrpc:"type"`
	NS     []string `xmlrpc:"ns"`
}

type nameserverDeleteRequest struct {
	Domain string `xmlrpc:"domain"`
}

type accountLoginRequest struct {
	User string `xmlrpc:"user"`
	Pass string `xmlrpc:"pass"`
}

type accountLoginResponse struct {
	TFA string `mapstructure:"tfa"`
}

type accountUnlockRequest struct {
	TAN string `xmlrpc:"tan"`
}

const endpointURL = "https://api.domrobot.com/xmlrpc/"

func newClient(endpointURL string) (*client, error) {
	rpcClient, err := xmlrpc.NewClient(endpointURL, nil)

	if err != nil {
		return nil, err
	}

	return &client{rpcClient}, nil
}

func (c *client) getRecords(domain string) ([]nameserverRecord, error) {
	response, err := c.call("nameserver.info", nameserverInfoRequest{
		Domain: domain,
	})

	if err != nil {
		return nil, err
	}

	data := nameserverInfoResponse{}
	err = mapstructure.Decode(response, &data)

	if err != nil {
		return nil, err
	}

	return data.Records, nil
}

func (c *client) findRecords(record nameserverRecord, domain string, matchContent bool) ([]nameserverRecord, error) {
	request := nameserverInfoRequest{
		Domain: domain,
		Type:   record.Type,
		Name:   record.Name,
	}

	if matchContent {
		request.Content = record.Content
	}

	response, err := c.call("nameserver.info", request)

	if err != nil {
		return nil, err
	}

	data := nameserverInfoResponse{}
	err = mapstructure.Decode(response, &data)

	if err != nil {
		return nil, err
	}

	return data.Records, nil
}

func (c *client) createRecord(record nameserverRecord, domain string) (int, error) {
	response, err := c.call("nameserver.createRecord", nameserverCreateRecordRequest{
		Domain:   domain,
		Name:     record.Name,
		Type:     record.Type,
		Content:  record.Content,
		TTL:      record.TTL,
		Priority: record.Priority,
	})

	if err != nil {
		return 0, err
	}

	data := nameserverCreateRecordResponse{}
	err = mapstructure.Decode(response, &data)

	if err != nil {
		return 0, err
	}

	return data.ID, nil
}

func (c *client) updateRecord(record nameserverRecord) error {
	if record.ID == 0 {
		return fmt.Errorf("record cannot be updated because the ID is not set")
	}

	_, err := c.call("nameserver.updateRecord", nameserverUpdateRecordRequest{
		ID:       record.ID,
		Name:     record.Name,
		Type:     record.Type,
		Content:  record.Content,
		TTL:      record.TTL,
		Priority: record.Priority,
	})

	return err
}

func (c *client) deleteRecord(record nameserverRecord) error {
	_, err := c.call("nameserver.deleteRecord", nameserverDeleteRecordRequest{
		ID: record.ID,
	})

	return err
}

func (c *client) createNameserver(domain string, _type string, nameservers []string) error {
	_, err := c.call("nameserver.create", nameserverCreateRequest{
		Domain: domain,
		Type:   _type,
		NS:     nameservers,
	})

	return err
}

func (c *client) deleteNameserver(domain string) error {
	_, err := c.call("nameserver.delete", nameserverDeleteRequest{
		Domain: domain,
	})

	return err
}

func (c *client) login(username string, password string, sharedSecret string) error {
	response, err := c.call("account.login", accountLoginRequest{
		User: username,
		Pass: password,
	})

	if err != nil {
		return err
	}

	data := accountLoginResponse{}
	err = mapstructure.Decode(response, &data)

	if err != nil {
		return err
	}

	if data.TFA == "GOOGLE-AUTH" {
		tan, err := totp.GenerateCode(sharedSecret, time.Now())

		if err != nil {
			return err
		}

		err = c.unlock(tan)

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *client) logout() error {
	_, err := c.call("account.logout", nil)

	return err
}

func (c *client) unlock(tan string) error {
	_, err := c.call("account.unlock", accountUnlockRequest{
		TAN: tan,
	})

	return err
}

func (c *client) call(method string, params any) (any, error) {
	var response response

	err := c.rpcClient.Call(method, params, &response)

	if err != nil {
		return nil, err
	}

	return response.ResponseData, checkResponse(response)
}

func (r *errorResponse) Error() string {
	if r.Reason != "" {
		return fmt.Sprintf("(%d) %s. Reason: (%s) %s", r.Code, r.Message, r.ReasonCode, r.Reason)
	}

	return fmt.Sprintf("(%d) %s", r.Code, r.Message)
}

func checkResponse(r response) error {
	if c := r.Code; c >= 1000 && c <= 1500 {
		return nil
	}

	return &errorResponse{
		Code:       r.Code,
		Message:    r.Message,
		Reason:     r.Reason,
		ReasonCode: r.ReasonCode,
	}
}
