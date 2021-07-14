package authority

import (
	"fmt"
	"sync"
)

type Options struct {
	Issuer string
}

func (opts Options) Validate() error {
	if opts.Issuer == "" {
		return fmt.Errorf("Issuer is empty")
	}

	return nil
}

type handler struct {
	sync.RWMutex
	issuer string
}

func NewHandler(opts Options) (*handler, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	return &handler{
		issuer: opts.Issuer,
	}, nil
}

func (h *handler) GetIssuer() string {
	h.RLock()
	defer h.RUnlock()

	return h.issuer
}

func (h *handler) SetIssuer(newIssuer string) {
	h.Lock()
	defer h.Unlock()

	h.issuer = newIssuer
}
