package server

type HandlerOptions struct {
	Issuer string
}

type HandlerOption func(*HandlerOptions)

func WithIssuer(issuer string) HandlerOption {
	return func(opts *HandlerOptions) {
		opts.Issuer = issuer
	}
}
