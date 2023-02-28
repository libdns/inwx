package inwx

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

var (
	username    = os.Getenv("INWX_USERNAME")
	password    = os.Getenv("INWX_PASSWORD")
	zone        = os.Getenv("ZONE")
	testRecords = []libdns.Record{
		{
			Type:  "TXT",
			Name:  "test_1",
			Value: "test_value_1",
			TTL:   time.Duration(300 * time.Second),
		},
		{
			Type:  "TXT",
			Name:  "test_2",
			Value: "test_value_2",
			TTL:   time.Duration(300 * time.Second),
		},
		{
			Type:  "TXT",
			Name:  "test_3",
			Value: "test_value_3",
			TTL:   time.Duration(300 * time.Second),
		},
	}
)

func find[T any](elements []T, predicate func(T) bool) (T, bool) {
	for _, element := range elements {
		if predicate(element) {
			return element, true
		}
	}

	return *new(T), false
}

func contains[T any](elements []T, predicate func(T) bool) bool {
	_, ok := find(elements, predicate)

	return ok
}

func createTestNameserver(p *Provider) error {
	client, err := p.getClient(context.TODO())
	defer p.removeClient(context.TODO())

	if err != nil {
		return err
	}

	err = client.createNameserver(context.TODO(), getDomain(zone), "MASTER", []string{"ns.ote.inwx.de", "ns2.ote.inwx.de"})

	if err != nil {
		return err
	}

	_, err = p.AppendRecords(context.Background(), zone, testRecords)

	return err
}

func deleteTestNameserver(p *Provider) error {
	client, err := p.getClient(context.TODO())
	defer p.removeClient(context.TODO())

	if err != nil {
		return err
	}

	return client.deleteNameserver(context.TODO(), getDomain(zone))
}

func getProvider() *Provider {
	return &Provider{
		Username:    username,
		Password:    password,
		EndpointURL: "https://api.ote.domrobot.com/jsonrpc/",
	}
}

func TestProvider_GetRecords(t *testing.T) {
	p := getProvider()

	err := createTestNameserver(p)

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err = deleteTestNameserver(p)

		if err != nil {
			t.Fatal(err)
		}
	})

	records, err := p.GetRecords(context.Background(), zone)

	for _, testRecord := range testRecords {
		contains_ := contains(records, func(record libdns.Record) bool {
			return record.Type == testRecord.Type &&
				record.Name == testRecord.Name &&
				record.Value == testRecord.Value &&
				record.TTL == testRecord.TTL
		})

		if !contains_ {
			t.Fatalf("record %v not found on nameserver", testRecord)
		}
	}
}

func TestProvider_AppendRecords(t *testing.T) {
	p := getProvider()

	err := createTestNameserver(p)

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err = deleteTestNameserver(p)

		if err != nil {
			t.Fatal(err)
		}
	})

	newRecords := []libdns.Record{
		{
			Type:  "TXT",
			Name:  "test_4",
			Value: "test_value_4",
			TTL:   time.Duration(300 * time.Second),
		},
	}

	records, err := p.AppendRecords(context.Background(), zone, newRecords)

	if err != nil {
		t.Fatal(err)
	}

	for _, newRecord := range newRecords {
		contains_ := contains(records, func(record libdns.Record) bool {
			return record.Type == newRecord.Type &&
				record.Name == newRecord.Name &&
				record.Value == newRecord.Value &&
				record.TTL == newRecord.TTL
		})

		if !contains_ {
			t.Fatalf("result does not contain record %v", newRecord)
		}
	}

	records, err = p.GetRecords(context.Background(), zone)

	if err != nil {
		t.Fatal(err)
	}

	for _, newRecord := range newRecords {
		contains_ := contains(records, func(record libdns.Record) bool {
			return record.Type == newRecord.Type &&
				record.Name == newRecord.Name &&
				record.Value == newRecord.Value &&
				record.TTL == newRecord.TTL
		})

		if !contains_ {
			t.Fatalf("record %v does not exist on nameserver", newRecord)
		}
	}
}

func TestProvider_SetRecords(t *testing.T) {
	p := getProvider()

	err := createTestNameserver(p)

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err = deleteTestNameserver(p)

		if err != nil {
			t.Fatal(err)
		}
	})

	updatedRecords := []libdns.Record{
		{
			Type:  "TXT",
			Name:  "test_3",
			Value: "test_value_3_new",
			TTL:   time.Duration(300 * time.Second),
		},
		{
			Type:  "TXT",
			Name:  "test_4",
			Value: "test_value_4",
			TTL:   time.Duration(300 * time.Second),
		},
	}

	records, err := p.AppendRecords(context.Background(), zone, updatedRecords)

	if err != nil {
		t.Fatal(err)
	}

	for _, updatedRecord := range updatedRecords {
		contains_ := contains(records, func(record libdns.Record) bool {
			return record.Type == updatedRecord.Type &&
				record.Name == updatedRecord.Name &&
				record.Value == updatedRecord.Value &&
				record.TTL == updatedRecord.TTL
		})

		if !contains_ {
			t.Fatalf("result does not contain record %v", updatedRecord)
		}
	}

	records, err = p.GetRecords(context.Background(), zone)

	if err != nil {
		t.Fatal(err)
	}

	for _, updatedRecord := range updatedRecords {
		contains_ := contains(records, func(record libdns.Record) bool {
			return record.Type == updatedRecord.Type &&
				record.Name == updatedRecord.Name &&
				record.Value == updatedRecord.Value &&
				record.TTL == updatedRecord.TTL
		})

		if !contains_ {
			t.Fatalf("record %v does not exist on nameserver", updatedRecord)
		}
	}
}

func TestProvider_DeleteRecords(t *testing.T) {
	p := getProvider()

	err := createTestNameserver(p)

	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err = deleteTestNameserver(p)

		if err != nil {
			t.Fatal(err)
		}
	})

	deletedRecords := []libdns.Record{
		{
			Type:  "TXT",
			Name:  "test_3",
			Value: "test_value_3",
			TTL:   time.Duration(300 * time.Second),
		},
	}

	records, err := p.DeleteRecords(context.Background(), zone, deletedRecords)

	if err != nil {
		t.Fatal(err)
	}

	for _, deletedRecord := range deletedRecords {
		contains_ := contains(records, func(record libdns.Record) bool {
			return record.Type == deletedRecord.Type &&
				record.Name == deletedRecord.Name &&
				record.Value == deletedRecord.Value &&
				record.TTL == deletedRecord.TTL
		})

		if !contains_ {
			t.Fatalf("result does not contain record %v", deletedRecord)
		}
	}

	records, err = p.GetRecords(context.Background(), zone)

	if err != nil {
		t.Fatal(err)
	}

	for _, deletedRecord := range deletedRecords {
		contains_ := contains(records, func(record libdns.Record) bool {
			return record.Type == deletedRecord.Type &&
				record.Name == deletedRecord.Name &&
				record.Value == deletedRecord.Value &&
				record.TTL == deletedRecord.TTL
		})

		if contains_ {
			t.Fatalf("record %v is still present on nameserver", deletedRecord)
		}
	}
}
