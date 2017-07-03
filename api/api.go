package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ebittleman/cartio/authn"
	"github.com/ebittleman/cartio/authz"
)

type contextKey string

const (
	userKey contextKey = "user"
)

// AuthNegotiator returns an authn.Authenticator as per request parameters
type AuthNegotiator func(r *http.Request) (authn.Authenticator, authn.Credential, error)

// AuthenticatorNegotiationFactory parses a request to instantiate a
// contextual authenticator populated with its required parameters
func AuthenticatorNegotiationFactory(credStores []authn.CredStore) AuthNegotiator {
	defaultStore := 0
	return func(r *http.Request) (authn.Authenticator, authn.Credential, error) {
		user, password, ok := r.BasicAuth()
		if !ok {
			return nil, nil, http.ErrNotSupported
		}

		authenticator := authn.NewAuthenticator(credStores[defaultStore])
		return authenticator, authn.NewPlainTextCredential(user, password), nil
	}
}

// AuthenticationRequired wraps http requests with authentication step
func AuthenticationRequired(authNegotiator AuthNegotiator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authenticator, credential, err := authNegotiator(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ok, err := authenticator.Authenticate(credential)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !ok {
			http.Error(w, "Unauthorized - Authentication Failed", http.StatusUnauthorized)
			return
		}

		newR := r.WithContext(context.WithValue(
			r.Context(),
			userKey,
			credential.UserID(),
		))

		next.ServeHTTP(w, newR)
	})
}

// HasPermission protects an endpoint with some basic rbac
func HasPermission(rules authz.Rules, action string, subject string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := r.Context().Value(userKey).(authn.UserID)
		if !ok || user == nil {
			http.Error(w, "Unauthorized - Login Required", http.StatusUnauthorized)
			return
		}

		if !rules.IsAllowed(user.String(), action, subject) {
			http.Error(w, "Unauthorized - Permission Denied", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// HelloWorld simple http handler for testing out auth stuff
func HelloWorld(w http.ResponseWriter, r *http.Request) {
	var place interface{} = "World"

	user := r.Context().Value(userKey)
	if user != nil {
		place = user
	}

	fmt.Fprintf(w, "Hello %v", place)
}

// CommandHandler recieves command requests and routes them to the proper
// service
type CommandHandler struct {
	service CartService
}

func (c *CommandHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)

	req := new(APIRequest)
	err := decoder.Decode(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp := new(APIResponse)
	resp.Command = req.Command
	resp.RequestID = req.RequestID

	switch req.Command {
	case "add_items":
		resp.AddItems, err = c.service.AddItems(r.Context(), req.AddItems)
	case "update_items":
		resp.UpdateItems, err = c.service.UpdateItems(r.Context(), req.UpdateItems)
	case "remove_items":
		resp.RemoveItems, err = c.service.RemoveItems(r.Context(), req.RemoveItems)
	case "add_coupon_code":
		resp.AddCouponCode, err = c.service.AddCouponCode(r.Context(), req.AddCouponCode)
	case "remove_coupon_code":
		resp.RemoveCouponCode, err = c.service.RemoveCouponCode(r.Context(), req.RemoveCouponCode)
	case "set_special_instructions":
		resp.SetSpecialInstructions, err = c.service.SetSpecialInstructions(r.Context(), req.SetSpecialInstructions)
	case "calculate_shipping":
		resp.CalculateShipping, err = c.service.CalculateShipping(r.Context(), req.CalculateShipping)
	case "calculate_sales_tax":
		resp.CalculateSalesTax, err = c.service.CalculateSalesTax(r.Context(), req.CalculateSalesTax)
	case "set_shipping_address":
		resp.SetShippingAddress, err = c.service.SetShippingAddress(r.Context(), req.SetShippingAddress)
	case "set_billing_address":
		resp.SetBillingAddress, err = c.service.SetBillingAddress(r.Context(), req.SetBillingAddress)
	case "set_payment_method":
		resp.SetPaymentMethod, err = c.service.SetPaymentMethod(r.Context(), req.SetPaymentMethod)
	case "submit_order":
		resp.SubmitOrder, err = c.service.SubmitOrder(r.Context(), req.SubmitOrder)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	encoder := json.NewEncoder(w)
	err = encoder.Encode(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// APIRequest command endpoint request body
type APIRequest struct {
	Command   string `json:"command"`
	RequestID string `json:"request_id,omitempty"`

	AddItems               *AddItemsInput               `json:"add_items,omitempty"`
	UpdateItems            *UpdateItemsInput            `json:"update_items,omitempty"`
	RemoveItems            *RemoveItemsInput            `json:"remove_items,omitempty"`
	AddCouponCode          *AddCouponCodeInput          `json:"add_coupon_code,omitempty"`
	RemoveCouponCode       *RemoveCouponCodeInput       `json:"remove_coupon_code,omitempty"`
	SetSpecialInstructions *SetSpecialInstructionsInput `json:"set_special_instructions,omitempty"`
	CalculateShipping      *CalculateShippingInput      `json:"calculate_shipping,omitempty"`
	CalculateSalesTax      *CalculateSalesTaxInput      `json:"calculate_sales_tax,omitempty"`
	SetShippingAddress     *SetShippingAddressInput     `json:"set_shipping_address,omitempty"`
	SetBillingAddress      *SetBillingAddressInput      `json:"set_billing_address,omitempty"`
	SetPaymentMethod       *SetPaymentMethodInput       `json:"set_payment_method,omitempty"`
	SubmitOrder            *SubmitOrderInput            `json:"submit_order,omitempty"`
}

// APIResponse command endpoint response body
type APIResponse struct {
	Command   string `json:"command"`
	RequestID string `json:"request_id,omitempty"`

	AddItems               *AddItemsOutput               `json:"add_items,omitempty"`
	UpdateItems            *UpdateItemsOutput            `json:"update_items,omitempty"`
	RemoveItems            *RemoveItemsOutput            `json:"remove_items,omitempty"`
	AddCouponCode          *AddCouponCodeOutput          `json:"add_coupon_code,omitempty"`
	RemoveCouponCode       *RemoveCouponCodeOutput       `json:"remove_coupon_code,omitempty"`
	SetSpecialInstructions *SetSpecialInstructionsOutput `json:"set_special_instructions,omitempty"`
	CalculateShipping      *CalculateShippingOutput      `json:"calculate_shipping,omitempty"`
	CalculateSalesTax      *CalculateSalesTaxOutput      `json:"calculate_sales_tax,omitempty"`
	SetShippingAddress     *SetShippingAddressOutput     `json:"set_shipping_address,omitempty"`
	SetBillingAddress      *SetBillingAddressOutput      `json:"set_billing_address,omitempty"`
	SetPaymentMethod       *SetPaymentMethodOutput       `json:"set_payment_method,omitempty"`
	SubmitOrder            *SubmitOrderOutput            `json:"submit_order,omitempty"`
}

// CartService methods available for working with shopping carts
type CartService interface {
	AddItems(context.Context, *AddItemsInput) (*AddItemsOutput, error)
	UpdateItems(context.Context, *UpdateItemsInput) (*UpdateItemsOutput, error)
	RemoveItems(context.Context, *RemoveItemsInput) (*RemoveItemsOutput, error)
	AddCouponCode(context.Context, *AddCouponCodeInput) (*AddCouponCodeOutput, error)
	RemoveCouponCode(context.Context, *RemoveCouponCodeInput) (*RemoveCouponCodeOutput, error)
	SetSpecialInstructions(context.Context, *SetSpecialInstructionsInput) (*SetSpecialInstructionsOutput, error)
	CalculateShipping(context.Context, *CalculateShippingInput) (*CalculateShippingOutput, error)
	CalculateSalesTax(context.Context, *CalculateSalesTaxInput) (*CalculateSalesTaxOutput, error)
	SetShippingAddress(context.Context, *SetShippingAddressInput) (*SetShippingAddressOutput, error)
	SetBillingAddress(context.Context, *SetBillingAddressInput) (*SetBillingAddressOutput, error)
	SetPaymentMethod(context.Context, *SetPaymentMethodInput) (*SetPaymentMethodOutput, error)
	SubmitOrder(context.Context, *SubmitOrderInput) (*SubmitOrderOutput, error)
}

type AddItem struct {
	ID  string `json:"id"`
	Qty int    `json:"qty"`
}

type AddItemsInput struct {
	CartID string    `json:"cart_id"`
	Items  []AddItem `json:"items"`
}

type AddItemsOutput struct {
	CartID string `json:"cart_id"`
}

type UpdateItem struct {
	ID  string `json:"id"`
	Qty int    `json:"qty"`
}

type UpdateItemsInput struct {
	CartID string       `json:"cart_id"`
	Items  []UpdateItem `json:"items"`
}

type UpdateItemsOutput struct {
	CartID string `json:"cart_id"`
}

type RemoveItem struct {
	ID string `json:"id"`
}

type RemoveItemsInput struct {
	CartID string       `json:"cart_id"`
	Items  []RemoveItem `json:"items"`
}

type RemoveItemsOutput struct {
	CartID string `json:"cart_id"`
}

type AddCouponCodeInput struct {
	CartID string `json:"cart_id"`
	Code   string `json:"code"`
}

type AddCouponCodeOutput struct {
	CartID string `json:"cart_id"`
}

type RemoveCouponCodeInput struct {
	CartID string `json:"cart_id"`
	Code   string `json:"code"`
}

type RemoveCouponCodeOutput struct {
	CartID string `json:"cart_id"`
}

type SetSpecialInstructionsInput struct {
	CartID       string `json:"cart_id"`
	Instructions string `json:"instructions"`
}

type SetSpecialInstructionsOutput struct {
	CartID string `json:"cart_id"`
}

type CalculateShippingInput struct {
	CartID      string `json:"cart_id"`
	PostalCode  string `json:"postal_code"`
	CountryCode string `json:"country_code"`
}

type CalculateShippingOutput struct {
	CartID string `json:"cart_id"`
}

type CalculateSalesTaxInput struct {
	CartID      string `json:"cart_id"`
	PostalCode  string `json:"postal_code"`
	CountryCode string `json:"country_code"`
}

type CalculateSalesTaxOutput struct {
	CartID string `json:"cart_id"`
}

type SetShippingAddressInput struct {
	CartID      string `json:"cart_id"`
	ShipTo      string `json:"ship_to"`
	Addr1       string `json:"addr_1"`
	Addr2       string `json:"addr_2"`
	AptSuite    string `json:"apt_suite"`
	City        string `json:"city"`
	PostalCode  string `json:"postal_code"`
	CountryCode string `json:"country_code"`
}

type SetShippingAddressOutput struct {
	CartID string `json:"cart_id"`
}

type SetBillingAddressInput struct {
	CartID      string `json:"cart_id"`
	BillTo      string `json:"bill_to"`
	Addr1       string `json:"addr_1"`
	Addr2       string `json:"addr_2"`
	AptSuite    string `json:"apt_suite"`
	City        string `json:"city"`
	PostalCode  string `json:"postal_code"`
	CountryCode string `json:"country_code"`
}

type SetBillingAddressOutput struct {
	CartID string `json:"cart_id"`
}

type PayPal struct{}
type Stripe struct{}
type AccountBalance struct {
	RemainderWith string `json:"remainder_with"`
	PayPal        PayPal `json:"paypal"`
	Stripe        Stripe `json:"stripe"`
}

type SetPaymentMethodInput struct {
	CartID         string         `json:"cart_id"`
	Type           string         `json:"type"`
	PayPal         PayPal         `json:"paypal"`
	Stripe         Stripe         `json:"stripe"`
	AccountBalance AccountBalance `json:"account_balance"`
}

type SetPaymentMethodOutput struct {
	CartID string `json:"cart_id"`
}

type SubmitOrderInput struct {
	CartID       string `json:"cart_id"`
	AgreeToTerms bool   `json:"agree_to_terms"`
}

type SubmitOrderOutput struct {
	CartID string `json:"cart_id"`
}
