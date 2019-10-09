//      http://www.apache.org/licenses/LICENSE-2.0

package mongodbadapter

import (
	"context"
	"errors"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
	"runtime"
	"time"

	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/persist"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// CasbinRule represents a rule in Casbin.
type CasbinRule struct {
	PType string
	V0    string
	V1    string
	V2    string
	V3    string
	V4    string
	V5    string
}

// adapter represents the MongoDB adapter for policy storage.
type adapter struct {
	database   string
	options    *options.ClientOptions
	session    *mongo.Client
	collection *mongo.Collection
	filtered   bool
}

// finalizer is the destructor for adapter.
func finalizer(a *adapter) {
	a.close()
}

// NewAdapter is the constructor for Adapter. If database name is not provided
// in the Mongo URL, 'casbin' will be used as database name.
func NewAdapter(url string) persist.Adapter {
	cs, err := connstring.Parse(url)
	if err != nil {
		panic(err)
	}
	options := options.Client().ApplyURI(url)

	return NewAdapterWithDialInfo(options, cs.Database)
}

// NewAdapterWithDialInfo is an alternative constructor for Adapter
// that does the same as NewAdapter, but uses options.ClientOptions instead of a Mongo URL
func NewAdapterWithDialInfo(dI *options.ClientOptions, Database string) persist.Adapter {
	a := &adapter{options: dI, database: Database}
	a.filtered = false

	// Open the DB, create it if not existed.
	a.open()

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
// Casbin will not automatically call LoadPolicy() for a filtered adapter.
func NewFilteredAdapter(url string) persist.FilteredAdapter {
	a := NewAdapter(url).(*adapter)
	a.filtered = true

	return a
}

func (a *adapter) open() {
	// FailFast will cause connection and query attempts to fail faster when
	// the server is unavailable, instead of retrying until the configured
	// timeout period. Note that an unavailable server may silently drop
	// packets instead of rejecting them, in which case it's impossible to
	// distinguish it from a slow server, so the timeout stays relevant.

	//a.dialInfo.FailFast = true
	if a.database == "" {
		a.database = "casbin"
	}

	session, err := mongo.NewClient(a.options)
	if err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = session.Connect(ctx)
	if err != nil {
		panic(err)
	}
	collection := session.Database(a.database).Collection("casbin_rule")

	a.session = session
	a.collection = collection

	//indexes := []string{"ptype", "v0", "v1", "v2", "v3", "v4", "v5"}
	//for _, k := range indexes {
	//	if err := a.collection.EnsureIndexKey(k); err != nil {
	//		panic(err)
	//	}
	//}
}

func (a *adapter) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	a.session.Disconnect(ctx)
}

func (a *adapter) dropTable() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := a.collection.Drop(ctx)
	if err != nil {
		if err.Error() != "ns not found" {
			return err
		}
	}
	return nil
}

func loadPolicyLine(line CasbinRule, model model.Model) {
	key := line.PType
	sec := key[:1]

	tokens := []string{}
	if line.V0 != "" {
		tokens = append(tokens, line.V0)
	} else {
		goto LineEnd
	}

	if line.V1 != "" {
		tokens = append(tokens, line.V1)
	} else {
		goto LineEnd
	}

	if line.V2 != "" {
		tokens = append(tokens, line.V2)
	} else {
		goto LineEnd
	}

	if line.V3 != "" {
		tokens = append(tokens, line.V3)
	} else {
		goto LineEnd
	}

	if line.V4 != "" {
		tokens = append(tokens, line.V4)
	} else {
		goto LineEnd
	}

	if line.V5 != "" {
		tokens = append(tokens, line.V5)
	} else {
		goto LineEnd
	}

LineEnd:
	model[sec][key].Policy = append(model[sec][key].Policy, tokens)
}

// LoadPolicy loads policy from database.
func (a *adapter) LoadPolicy(model model.Model) error {
	return a.LoadFilteredPolicy(model, nil)
}

// LoadFilteredPolicy loads matching policy lines from database. If not nil,
// the filter must be a valid MongoDB selector.
func (a *adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		a.filtered = false
	} else {
		a.filtered = true
	}
	iter, err := a.collection.Find(context.Background(), filter)
	if err != nil {
		panic(err)
	}
	for iter.Next(context.Background()) {
		line := CasbinRule{}
		loadPolicyLine(line, model)
	}

	return iter.Close(context.Background())
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *adapter) IsFiltered() bool {
	return a.filtered
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{
		PType: ptype,
	}

	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *adapter) SavePolicy(model model.Model) error {
	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}
	if err := a.dropTable(); err != nil {
		return err
	}

	var lines bson.A

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := savePolicyLine(ptype, rule)
			lines = append(lines, &line)
		}
	}
	_, err := a.collection.InsertMany(context.Background(), lines)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	_, err := a.collection.InsertOne(context.Background(), line)
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)
	if _, err := a.collection.DeleteOne(context.Background(), line); err != nil {
		switch err {
		case mongo.ErrNoDocuments:
			return nil
		default:
			return err
		}
	}
	return nil
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	selector := make(map[string]interface{})
	selector["ptype"] = ptype

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		if fieldValues[0-fieldIndex] != "" {
			selector["v0"] = fieldValues[0-fieldIndex]
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		if fieldValues[1-fieldIndex] != "" {
			selector["v1"] = fieldValues[1-fieldIndex]
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		if fieldValues[2-fieldIndex] != "" {
			selector["v2"] = fieldValues[2-fieldIndex]
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		if fieldValues[3-fieldIndex] != "" {
			selector["v3"] = fieldValues[3-fieldIndex]
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		if fieldValues[4-fieldIndex] != "" {
			selector["v4"] = fieldValues[4-fieldIndex]
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		if fieldValues[5-fieldIndex] != "" {
			selector["v5"] = fieldValues[5-fieldIndex]
		}
	}

	_, err := a.collection.DeleteMany(context.Background(), selector)
	return err
}
