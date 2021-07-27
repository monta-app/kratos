package courier

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/pkg/errors"

	"github.com/ory/herodot"

	"github.com/gofrs/uuid"

	"github.com/ory/kratos/request"
)

type sendSMSRequestBody struct {
	From string `json:"from"`
	To   string `json:"to"`
	Body string `json:"body"`
}

type smsClient struct {
	RequestConfig        json.RawMessage
	RequestStandbyConfig json.RawMessage

	GetTemplateType        func(t SMSTemplate) (TemplateType, error)
	NewTemplateFromMessage func(d Dependencies, msg Message) (SMSTemplate, error)
}

func newSMS(ctx context.Context, deps Dependencies) *smsClient {
	return &smsClient{
		RequestConfig:        deps.CourierConfig(ctx).CourierSMSRequestConfig(),
		RequestStandbyConfig: deps.CourierConfig(ctx).CourierSMSStandbyRequestConfig(),

		GetTemplateType:        SMSTemplateType,
		NewTemplateFromMessage: NewSMSTemplateFromMessage,
	}
}

func (c *courier) QueueSMS(ctx context.Context, t SMSTemplate) (uuid.UUID, error) {
	recipient, err := t.PhoneNumber()
	if err != nil {
		return uuid.Nil, err
	}

	templateType, err := c.smsClient.GetTemplateType(t)
	if err != nil {
		return uuid.Nil, err
	}

	templateData, err := json.Marshal(t)
	if err != nil {
		return uuid.Nil, err
	}

	message := &Message{
		Status:       MessageStatusQueued,
		Type:         MessageTypePhone,
		Recipient:    recipient,
		TemplateType: templateType,
		TemplateData: templateData,
	}
	if err := c.deps.CourierPersister().AddMessage(ctx, message); err != nil {
		return uuid.Nil, err
	}

	return message.ID, nil
}

func (c *courier) dispatchSMS(ctx context.Context, msg Message) error {
	if !c.deps.CourierConfig().CourierSMSEnabled(ctx) {
		return errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Courier tried to deliver an sms but courier.sms.enabled is set to false!"))
	}

	tmpl, err := c.smsClient.NewTemplateFromMessage(c.deps, msg)
	if err != nil {
		return err
	}

	body, err := tmpl.SMSBody(ctx)
	if err != nil {
		return err
	}

	requestConfig := c.smsClient.RequestConfig
	from := c.deps.CourierConfig(ctx).CourierSMSFrom()
	if smsStandby, ok := tmpl.(SMSStandbySender); ok {
		requestStandbyConfig := c.smsClient.RequestStandbyConfig
		if requestStandbyConfig != nil && bytes.Compare(requestStandbyConfig, []byte("{}")) != 0 {
			if smsStandby.UseStandbySender() {
				requestConfig = requestStandbyConfig
				from = c.deps.CourierConfig(ctx).CourierSMSStandbyFrom()
			}
		}
	}

	builder, err := request.NewBuilder(requestConfig, c.deps.HTTPClient(ctx), c.deps.Logger())
	if err != nil {
		return err
	}

	req, err := builder.BuildRequest(&sendSMSRequestBody{
		To:   msg.Recipient,
		From: from,
		Body: body,
	})
	if err != nil {
		return err
	}

	res, err := c.deps.HTTPClient(ctx).Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusCreated:
	case http.StatusAccepted:
	case http.StatusBadRequest:
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return NewMessageRejectedError(res.StatusCode, string(b))
	default:
		b, err := io.ReadAll(res.Body)
		if err != nil {
			return err
		}
		return errors.Errorf("Status: %s, body: %s", http.StatusText(res.StatusCode), string(b))
	}

	return nil
}
