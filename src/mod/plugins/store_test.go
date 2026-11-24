package plugins

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/foleyit/dunree/mod/database"
)

// The list format of the Zoraxy plugin store, served by a local test server (no // legacy-compat
// connection to any real store is made by the tests)
const listFormatIndex = `[{"IconPath":"","PluginIntroSpect":{"id":"com.example.demo","name":"Demo","author":"test","version_major":1},"DownloadURLs":{"linux_amd64":"https://downloads.invalid/demo_linux_amd64"}}]`

func listFormatServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(listFormatIndex)) }))
	t.Cleanup(srv.Close)
	return srv
}

func TestUpdateDownloadablePluginList(t *testing.T) {
	srv := listFormatServer(t)
	mockManager := &Manager{
		Options: &ManagerOptions{
			DownloadablePluginCache: []*DownloadablePlugin{},
			PluginStoreURLs:         []string{srv.URL + "/index2.json"},
			Database: &database.Database{
				Backend: &fakeBackend{},
			},
		},
	}

	err := mockManager.UpdateDownloadablePluginList()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(mockManager.Options.DownloadablePluginCache) == 0 {
		t.Fatalf("expected plugin cache to be updated, but it was empty")
	}

	if mockManager.Options.LastSuccPluginSyncTime == 0 {
		t.Fatalf("expected LastSuccPluginSyncTime to be updated, but it was not")
	}
}

func TestGetPluginListFromURL(t *testing.T) {
	srv := listFormatServer(t)
	mockManager := &Manager{
		Options: &ManagerOptions{
			DownloadablePluginCache: []*DownloadablePlugin{},
			PluginStoreURLs:         []string{},
		},
	}

	pluginList, err := mockManager.getPluginListFromURL(srv.URL + "/index2.json")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(pluginList) != 1 || pluginList[0].PluginIntroSpect.ID != "com.example.demo" || pluginList[0].Signature != SigUnsigned {
		t.Fatalf("expected the plugin of the list, got %+v", pluginList)
	}
}

type fakeBackend struct{}

func (f *fakeBackend) NewTable(tableName string) error {
	return nil
}

func (f *fakeBackend) TableExists(tableName string) bool {
	return false
}

func (f *fakeBackend) DropTable(tableName string) error {
	return nil
}

func (f *fakeBackend) Write(tableName string, key string, value any) error {
	return nil
}

func (f *fakeBackend) Read(tableName string, key string, assignee any) error {
	return nil
}

func (f *fakeBackend) KeyExists(tableName string, key string) bool {
	return false
}

func (f *fakeBackend) Delete(tableName string, key string) error {
	return nil
}

func (f *fakeBackend) ListTable(tableName string) ([][][]byte, error) {
	return [][][]byte{}, nil
}

func (f *fakeBackend) Close() {}
