package keyvault

// TemplateContext provides a getter to find a Client for the specified keyvault.
type TemplateContext interface {
	// GetClient returns a client for the specified keyvault. It will create
	// a new Client if necessary.  If kv is an empty string, it will return
	// the Client for the default keyvault as specified in the configuration.
	GetClient(kv string) (*Client, error)
}

type defaultTemplateContext struct {
	TemplateContext
	dflt string
}

// WrapContext provides a TemplateContext with the specified keyvault replacing the
// default.
func WrapContext(tc TemplateContext, dflt string) TemplateContext {
	return &defaultTemplateContext{
		TemplateContext: tc,
		dflt:            dflt,
	}
}

func (dtc *defaultTemplateContext) GetClient(kvname string) (*Client, error) {
	if kvname == "" {
		return dtc.TemplateContext.GetClient(dtc.dflt)
	} else {
		return dtc.TemplateContext.GetClient(kvname)
	}
}

// Returns a functions table for the specified TemplateContext.
func GetFuncs(tc TemplateContext) *Funcs {
	return &Funcs{TemplateContext: tc}
}
