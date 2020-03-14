package keyvault

type TemplateContext interface {
	GetClient(kv string) (*Client, error)
}

type defaultTemplateContext struct {
	TemplateContext
	dflt string
}

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

func GetFuncs(tc TemplateContext) *Funcs {
	return &Funcs{TemplateContext: tc}
}
