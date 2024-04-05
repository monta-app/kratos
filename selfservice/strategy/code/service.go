// Copyright © 2022 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

//go:generate mockgen -destination=mocks/mock_service.go -package=mocks github.com/ory/kratos/selfservice/strategy/code Flow

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-retryablehttp"

	"github.com/ory/kratos/courier"
	templates "github.com/ory/kratos/courier/template/sms"
	"github.com/ory/kratos/driver/clock"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/x/httpx"
)

type Flow interface {
	GetID() uuid.UUID
	Valid() error
}

type AuthenticationService interface {
	SendCode(ctx context.Context, flow Flow, phone string, transientPayload json.RawMessage) error
	VerifyCode(ctx context.Context, flow Flow, code string, transientPayload json.RawMessage) (*Code, error)
	DoVerify(ctx context.Context, expectedCode *Code, code string) (*Code, error)
}

type dependencies interface {
	config.Provider
	clock.Provider
	CodePersistenceProvider
	courier.Provider
	courier.ConfigProvider
	HTTPClient(ctx context.Context, opts ...httpx.ResilientOptions) *retryablehttp.Client
	RandomCodeGeneratorProvider
	ExternalVerifierProvider
}

type authenticationServiceImpl struct {
	r dependencies
}

type AuthenticationServiceProvider interface {
	CodeAuthenticationService() AuthenticationService
}

func NewCodeAuthenticationService(r dependencies) AuthenticationService {
	return &authenticationServiceImpl{r}
}

// SendCode
// Sends a new code to the user in a message.
// Returns error if the code was already sent and is not expired yet.
func (s *authenticationServiceImpl) SendCode(
	ctx context.Context,
	flow Flow,
	identifier string,
	transientPayload json.RawMessage,
) error {
	if err := flow.Valid(); err != nil {
		return err
	}

	codeValue := ""
	useStandbySender := false
	sendSMS := true
	for _, n := range s.r.Config().SelfServiceCodeTestNumbers(ctx) {
		if n == identifier {
			codeValue = "0000"
			sendSMS = false
			break
		}
	}

	if sendSMS {
		if err := s.detectSpam(ctx, identifier); err != nil {
			return err
		}
		codeValue = s.r.RandomCodeGenerator().Generate(4)
		requestStandbyConfig := s.r.Config().CourierSMSStandbyRequestConfig(ctx)
		if requestStandbyConfig != nil && bytes.Compare(requestStandbyConfig, []byte("{}")) != 0 {
			var err error
			useStandbySender, err = s.shouldUseStandbySender(ctx, identifier)
			if err != nil {
				return err
			}
		}
	}

	if s.r.Config().SelfServiceCodeExternalSMSVerifyEnabled() {
		codeValue = "external"
	}

	if err := s.r.CodePersister().CreateCode(ctx, &Code{
		FlowId:     flow.GetID(),
		Identifier: identifier,
		Code:       codeValue,
		ExpiresAt:  s.r.Clock().Now().Add(s.r.Config().SelfServiceCodeLifespan()),
	}); err != nil {
		return err
	}

	message := templates.NewCodeMessage(
		s.r,
		&templates.CodeMessageModel{
			Code:             codeValue,
			To:               identifier,
			UseStandbySender: useStandbySender,
			TransientPayload: transientPayload,
		})

	if s.r.Config().SelfServiceCodeExternalSMSVerifyEnabled() {
		return s.r.ExternalVerifier().VerificationStart(ctx, message)
	} else {
		if sendSMS {
			cr, err := s.r.Courier(ctx)
			if err != nil {
				return err
			}
			if _, err := cr.QueueSMS(ctx, message); err != nil {
				return err
			}
		}
	}

	return nil
}

// VerifyCode
// Verifies code by looking up in db.
func (s *authenticationServiceImpl) VerifyCode(ctx context.Context, flow Flow, code string, transientPayload json.RawMessage) (*Code, error) {
	if err := flow.Valid(); err != nil {
		return nil, err
	}
	expectedCode, err := s.r.CodePersister().FindActiveCode(ctx, flow.GetID(), s.r.Clock().Now())
	if err != nil {
		return nil, err
	}
	if expectedCode == nil {
		return nil, NewInvalidCodeError()
	}
	if s.r.Config().SelfServiceCodeExternalSMSVerifyEnabled() && expectedCode.Code == "external" {
		message := templates.NewCodeMessage(s.r,
			&templates.CodeMessageModel{
				Code:             code,
				To:               expectedCode.Identifier,
				UseStandbySender: false,
				TransientPayload: transientPayload,
			})
		if err = s.r.ExternalVerifier().VerificationCheck(ctx, message); err != nil {
			return nil, err
		}
	} else {
		expectedCode, err = s.DoVerify(ctx, expectedCode, code)
		if err != nil {
			updateErr := s.r.CodePersister().UpdateCode(ctx, expectedCode)
			if updateErr != nil {
				return nil, updateErr
			}
			return expectedCode, err
		}
	}

	if err = s.r.CodePersister().DeleteCodes(ctx, expectedCode.Identifier); err != nil {
		return nil, err
	}
	return expectedCode, nil
}

func (s *authenticationServiceImpl) DoVerify(ctx context.Context, expectedCode *Code, code string) (*Code, error) {
	if expectedCode.Code != code {
		expectedCode.Attempts++
		return expectedCode, NewInvalidCodeError()
	} else if expectedCode.Attempts >= s.r.Config().SelfServiceCodeMaxAttempts() {
		return expectedCode, NewAttemptsExceededError()
	}
	return expectedCode, nil
}

func (s *authenticationServiceImpl) detectSpam(ctx context.Context, identifier string) error {
	if !s.r.Config().SelfServiceCodeSMSSpamProtectionEnabled() {
		return nil
	}

	count, err := s.r.CodePersister().CountByIdentifier(ctx, identifier,
		s.r.Clock().Now().AddDate(0, 0, -7))
	if err != nil {
		return err
	}
	if count > s.r.Config().SelfServiceCodeSMSSpamProtectionMaxSingleNumber() {
		return NewSMSSpamError()
	}

	count, err = s.r.CodePersister().CountByIdentifierLike(ctx, identifier[0:7]+"%",
		s.r.Clock().Now().AddDate(0, 0, -7))
	if err != nil {
		return err
	}
	if count > s.r.Config().SelfServiceCodeSMSSpamProtectionMaxNumbersRange() {
		return NewSMSSpamError()
	}

	return nil
}

func (s *authenticationServiceImpl) shouldUseStandbySender(ctx context.Context, identifier string) (bool, error) {
	count, err := s.r.CodePersister().CountByIdentifier(ctx, identifier,
		s.r.Clock().Now().AddDate(0, 0, -1))
	if err != nil {
		return false, err
	}

	return count > 0, nil
}
