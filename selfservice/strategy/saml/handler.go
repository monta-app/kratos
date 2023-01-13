package saml

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/samlsp"
	"github.com/julienschmidt/httprouter"

	"github.com/ory/herodot"
	"github.com/ory/kratos/continuity"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/selfservice/errorx"

	samlidp "github.com/crewjam/saml"

	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/decoderx"
	"github.com/ory/x/fetcher"
)

var ErrNoSession = errors.New("saml: session not present")

var samlMiddlewares = make(map[string]*samlsp.Middleware)

type ory_kratos_continuity struct{}

type (
	handlerDependencies interface {
		x.WriterProvider
		x.CSRFProvider
		session.ManagementProvider
		session.PersistenceProvider
		errorx.ManagementProvider
		config.Provider
	}
	HandlerProvider interface {
		LogoutHandler() *Handler
	}
	Handler struct {
		d  handlerDependencies
		dx *decoderx.HTTP
	}
)

type SessionData struct {
	SessionID string
}

func NewHandler(d handlerDependencies) *Handler {
	return &Handler{
		d:  d,
		dx: decoderx.NewHTTP(),
	}
}

func (h *Handler) RegisterPublicRoutes(router *x.RouterPublic) {
	h.d.CSRFHandler().IgnoreGlob(RouteBaseAcs + "/*")

	router.GET(RouteMetadata, h.serveMetadata)
	router.GET(RouteAuth, h.loginWithIdp)
}

// Handle /selfservice/methods/saml/metadata
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	config := h.d.Config()
	pid := ps.ByName("provider")

	if samlMiddlewares[pid] == nil {
		if err := instantiateMiddleware(r.Context(), *config, h.d.SelfServiceErrorManager(), pid); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	buf, _ := xml.MarshalIndent(samlMiddlewares[pid].ServiceProvider.Metadata(), "", "  ")
	w.Header().Set("Content-Type", "text/xml")
	w.Write(buf)
}

// swagger:route GET /self-service/methods/saml/auth v0alpha2 initializeSelfServiceSamlFlowForBrowsers
//
// Initialize Authentication Flow for SAML (Either the login or the register)
//
// If you already have a session, it will redirect you to the main page.
//
//	Schemes: http, https
//
//	Responses:
//	  200: selfServiceRegistrationFlow
//	  400: jsonError
//	  500: jsonError
func (h *Handler) loginWithIdp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// Middleware is a singleton so we have to verify that it exists
	config := h.d.Config()
	pid := ps.ByName("provider")

	if samlMiddlewares[pid] == nil {
		if err := instantiateMiddleware(r.Context(), *config, h.d.SelfServiceErrorManager(), pid); err != nil {
			h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// We have to get the SessionID from the cookie to inject it into the context to ensure continuity
	cookie, err := r.Cookie(continuity.CookieName)
	if err != nil {
		h.d.SelfServiceErrorManager().Forward(r.Context(), w, r, err)
		return
	}
	body, _ := ioutil.ReadAll(r.Body)
	r2 := r.Clone(context.WithValue(r.Context(), ory_kratos_continuity{}, cookie.Value))
	r2.Body = ioutil.NopCloser(bytes.NewReader(body))
	*r = *r2

	// Checks if the user already have an active session
	if e := new(session.ErrNoActiveSessionFound); errors.As(e, &e) {
		// No session exists yet, we start the auth flow and create the session
		samlMiddlewares[pid].HandleStartAuthFlow(w, r)
	} else {
		// A session already exist, we redirect to the main page
		http.Redirect(w, r, config.SelfServiceBrowserDefaultReturnTo(r.Context()).Path, http.StatusTemporaryRedirect)
	}
}

func DestroyMiddlewareIfExists(pid string) {
	if samlMiddlewares[pid] != nil {
		samlMiddlewares[pid] = nil
	}
}

// Instantiate the middleware SAML from the information in the configuration file
func instantiateMiddleware(ctx context.Context, config config.Config, errorManager *errorx.Manager, pid string) error {

	providerConfig, err := CreateSAMLProviderConfig(config, ctx, pid)
	if err != nil {
		return err
	}

	// Key pair to encrypt and sign SAML requests
	keyPair, err := tls.LoadX509KeyPair(strings.Replace(providerConfig.PublicCertPath, "file://", "", 1), strings.Replace(providerConfig.PrivateKeyPath, "file://", "", 1))
	if err != nil {
		return herodot.ErrNotFound.WithTrace(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return herodot.ErrNotFound.WithTrace(err)
	}

	var idpMetadata *samlidp.EntityDescriptor

	// We check if the metadata file is provided
	if providerConfig.IDPInformation["idp_metadata_url"] != "" {
		// The metadata file is provided
		metadataURL := providerConfig.IDPInformation["idp_metadata_url"]

		metadataBuffer, err := fetcher.NewFetcher().Fetch(metadataURL)
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		metadata, err := ioutil.ReadAll(metadataBuffer)
		if err != nil {
			return errors.WithStack(herodot.ErrInternalServerError.
				WithReason("Error reading IdP metadata").
				WithDebug(err.Error()).WithWrap(err))
		}

		idpMetadata, err = samlsp.ParseMetadata(metadata)
		if err != nil {
			return ErrInvalidSAMLMetadataError.WithTrace(err)
		}

	} else {
		// The metadata file is not provided
		// So were are creating a minimalist IDP metadata based on what is provided by the user on the config file
		entityIDURL, err := url.Parse(providerConfig.IDPInformation["idp_entity_id"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		// The IDP SSO URL
		IDPSSOURL, err := url.Parse(providerConfig.IDPInformation["idp_sso_url"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		// The IDP Logout URL
		IDPlogoutURL, err := url.Parse(providerConfig.IDPInformation["idp_logout_url"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		// The certificate of the IDP
		certificateBuffer, err := fetcher.NewFetcher().Fetch(providerConfig.IDPInformation["idp_certificate_path"])
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}

		certificate, err := ioutil.ReadAll(certificateBuffer)
		if err != nil {
			return errors.WithStack(herodot.ErrInternalServerError.
				WithReason("Error reading certificate").
				WithDebug(err.Error()).WithWrap(err))
		}

		// We parse it into a x509.Certificate object
		IDPCertificate, err := MustParseCertificate(certificate)
		if err != nil {
			return ErrInvalidCertificateError.WithTrace(err)
		}

		// Because the metadata file is not provided, we need to simulate an IDP to create artificial metadata from the data entered in the conf file
		tempIDP := samlidp.IdentityProvider{
			Key:         nil,
			Certificate: IDPCertificate,
			Logger:      nil,
			MetadataURL: *entityIDURL,
			SSOURL:      *IDPSSOURL,
			LogoutURL:   *IDPlogoutURL,
		}

		// Now we assign our reconstructed metadata to our SP
		idpMetadata = tempIDP.Metadata()
	}

	// The main URL
	rootURL, err := url.Parse(config.SelfServiceBrowserDefaultReturnTo(ctx).String())
	if err != nil {
		return herodot.ErrNotFound.WithTrace(err)
	}

	// Here we create a MiddleWare to transform Kratos into a Service Provider
	samlMiddleWare, err := samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
		SignRequest: true,
		// We have to replace the ContinuityCookie by using RelayState. We will pass the SessionID (uuid) of Kratos through RelayState
		RelayStateFunc: func(w http.ResponseWriter, r *http.Request) string {
			ctx := r.Context()
			cipheredCookie, ok := ctx.Value(ory_kratos_continuity{}).(string)
			if !ok {
				_, err := w.Write([]byte("No SessionID in current context"))
				if err != nil {
					errorManager.Forward(r.Context(), w, r, err)
				}
				return ""
			}
			return cipheredCookie
		},
	})
	if err != nil {
		return errors.WithStack(herodot.ErrInternalServerError.
			WithReason("Error creating middleware").
			WithDebug(err.Error()).WithWrap(err))
	}

	// It's better to use SHA256 than SHA1
	samlMiddleWare.ServiceProvider.SignatureMethod = dsig.RSASHA256SignatureMethod

	var publicUrlString = config.SelfPublicURL(ctx).String()

	// Sometimes there is an issue with double slash into the url so we prevent it
	// Crewjam library use default route for ACS and metadata but we want to overwrite them
	RouteSamlAcsWithSlash := strings.Replace(RouteAcs, ":provider", providerConfig.ID, 1)
	if publicUrlString[len(publicUrlString)-1] != '/' {

		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u

	} else if publicUrlString[len(publicUrlString)-1] == '/' {

		publicUrlString = publicUrlString[:len(publicUrlString)-1]
		u, err := url.Parse(publicUrlString + RouteSamlAcsWithSlash)
		if err != nil {
			return herodot.ErrNotFound.WithTrace(err)
		}
		samlMiddleWare.ServiceProvider.AcsURL = *u
	}

	// Crewjam library use default route for ACS and metadata but we want to overwrite them
	metadata, err := url.Parse(publicUrlString + RouteBaseMetadata + "/" + pid)
	if err != nil {
		return herodot.ErrNotFound.WithTrace(err)
	}
	samlMiddleWare.ServiceProvider.MetadataURL = *metadata

	// The EntityID in the AuthnRequest is the Metadata URL
	samlMiddleWare.ServiceProvider.EntityID = samlMiddleWare.ServiceProvider.MetadataURL.String()

	// The issuer format is unspecified
	samlMiddleWare.ServiceProvider.AuthnNameIDFormat = samlidp.UnspecifiedNameIDFormat

	samlMiddlewares[pid] = samlMiddleWare

	return nil
}

// Return the singleton MiddleWare
func GetMiddleware(ctx context.Context, config *config.Config, errorManager *errorx.Manager, pid string) (*samlsp.Middleware, error) {
	if samlMiddlewares[pid] == nil {
		if err := instantiateMiddleware(ctx, *config, errorManager, pid); err != nil {
			return nil, err
		}
	}
	return samlMiddlewares[pid], nil
}

func MustParseCertificate(pemStr []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		return nil, errors.Errorf("Cannot find the next PEM formatted block")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Create a SAMLProvider object from the config file
func CreateSAMLProviderConfig(config config.Config, ctx context.Context, pid string) (*Configuration, error) {
	c, err := GetProvidersConfigCollection(ctx, &config)
	if err != nil {
		return nil, err
	}

	providerConfig, err := c.ProviderConfig(pid)
	if err != nil {
		return nil, ErrInvalidSAMLConfiguration.WithTrace(err)
	}

	if providerConfig.IDPInformation == nil {
		return nil, ErrInvalidSAMLConfiguration.WithReasonf("Please include your Identity Provider information in the configuration file.").WithTrace(err)
	}

	/**
	* SAMLTODO errors
	 */
	// _, sso_exists := providerConfig.IDPInformation["idp_sso_url"]
	_, sso_exists := providerConfig.IDPInformation["idp_sso_url"]
	_, entity_id_exists := providerConfig.IDPInformation["idp_entity_id"]
	_, certificate_exists := providerConfig.IDPInformation["idp_certificate_path"]
	_, logout_url_exists := providerConfig.IDPInformation["idp_logout_url"]
	_, metadata_exists := providerConfig.IDPInformation["idp_metadata_url"]

	if (!metadata_exists && (!sso_exists || !entity_id_exists || !certificate_exists || !logout_url_exists)) || len(providerConfig.IDPInformation) > 4 {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Please check your IDP information in the configuration file").WithTrace(err)
	}

	if providerConfig.ID == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have an ID").WithTrace(err)
	}

	if providerConfig.Label == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a label").WithTrace(err)
	}

	if providerConfig.PrivateKeyPath == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a private key").WithTrace(err)
	}

	if providerConfig.PublicCertPath == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a public certificate").WithTrace(err)
	}

	if providerConfig.AttributesMap == nil || len(providerConfig.AttributesMap) == 0 {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have an attributes map").WithTrace(err)
	}

	if providerConfig.AttributesMap["id"] == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("You must have an ID field in your attribute_map").WithTrace(err)
	}

	if providerConfig.Mapper == "" {
		return nil, ErrInvalidSAMLConfiguration.WithReason("Provider must have a mapper url").WithTrace(err)
	}

	return providerConfig, nil
}
