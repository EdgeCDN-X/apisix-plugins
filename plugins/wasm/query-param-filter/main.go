package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	// Set the VM context to a new instance of the vmContext struct
	proxywasm.SetVMContext(&vmContext{})
}

// The vmContext struct represents the VM context
type vmContext struct {
	// Embed the DefaultVMContext type from the proxywasm/types package
	types.DefaultVMContext
}

// The NewPluginContext function is called when a new plugin context is created
func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	// Return a new instance of the pluginContext struct with the given contextID
	return &pluginContext{contextID: contextID}
}

// The pluginContext struct represents the plugin context
type pluginContext struct {
	// Embed the DefaultPluginContext type from the proxywasm/types package
	types.DefaultPluginContext
	conf      string
	contextID uint32
}

// The OnPluginStart function is called when the plugin is started
func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	// Get the plugin configuration data
	data, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		// Log a critical error if there's an error reading the configuration
		proxywasm.LogCriticalf("error reading plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	// Store the configuration data in the conf field
	ctx.conf = string(data)
	// Return a successful status
	return types.OnPluginStartStatusOK
}

// The OnPluginDone function is called when the plugin is done
func (ctx *pluginContext) OnPluginDone() bool {
	proxywasm.LogInfo("do clean up...")
	return true
}

// The NewHttpContext function is called when a new HTTP context is created
func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	// Return a new instance of the httpLifecycle struct with the given contextID and conf
	return &httpLifecycle{
		pluginCtxID: ctx.contextID,
		conf:        ctx.conf,
		contextID:   contextID,
	}
}

// The httpLifecycle struct represents the HTTP lifecycle
type httpLifecycle struct {
	// Embed the DefaultHttpContext type from the proxywasm/types package
	types.DefaultHttpContext
	pluginCtxID uint32
	contextID   uint32
	conf        string
}

// The OnHttpRequestHeaders function is called when HTTP request headers are received
func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Log a warning message with the plugin context ID, configuration, and HTTP context ID
	proxywasm.LogWarnf("run plugin ctx %d with conf %s in http ctx %d", ctx.pluginCtxID, ctx.conf, ctx.contextID)
	// Return an action to continue processing the request
	return types.ActionContinue
}
