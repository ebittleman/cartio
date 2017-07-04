// cartio - A e-commerce api.
// Copyright (C) 2017 Eric Bittleman

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.

// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/ebittleman/cartio/authn"
	"github.com/ebittleman/cartio/authz"
	"github.com/ebittleman/cartio/domain/cart"
	"github.com/ebittleman/cartio/domain/cart/iface"
	"github.com/ebittleman/cartio/domain/product"
	"github.com/pborman/uuid"
)

type contextKey string

const (
	userKey    contextKey = "user"
	requestKey contextKey = "request"
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
	service iface.CartService
	rules   authz.Rules
}

func NewCommandHandler() http.Handler {
	service := cart.NewService(&MockProductService{}, &MockRepository{})
	return &CommandHandler{
		service: service,
		rules:   authz.NewRules("eric"),
	}
}

func (c *CommandHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	defer r.Body.Close()

	req := new(Request)
	err := decoder.Decode(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.RequestID == "" {
		req.RequestID = uuid.New()
	}

	resp := new(Response)
	resp.Command = req.Command
	resp.RequestID = req.RequestID

	ctx := context.WithValue(r.Context(), requestKey, req.RequestID)

	if ok, err := c.isAllowed(ctx, req); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if !ok {
		http.Error(w, "Unauthorized - Permission Denied", http.StatusUnauthorized)
		return
	}

	if err = c.execute(ctx, resp, req); err != nil {
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

func (c *CommandHandler) isAllowed(
	ctx context.Context,
	req *Request,
) (bool, error) {
	var subject string
	user := ctx.Value(userKey).(authn.UserID).String()

	switch req.Command {
	case "create_cart":
	case "add_items":
		subject = req.AddItems.CartID
	case "update_items":
		subject = req.UpdateItems.CartID
	case "remove_items":
		subject = req.RemoveItems.CartID
	case "add_coupon_code":
		subject = req.AddCouponCode.CartID
	case "remove_coupon_code":
		subject = req.RemoveCouponCode.CartID
	case "set_special_instructions":
		subject = req.SetSpecialInstructions.CartID
	case "calculate_shipping":
		subject = req.CalculateShipping.CartID
	case "calculate_sales_tax":
		subject = req.CalculateSalesTax.CartID
	case "set_shipping_address":
		subject = req.SetShippingAddress.CartID
	case "set_billing_address":
		subject = req.SetBillingAddress.CartID
	case "set_payment_method":
		subject = req.SetPaymentMethod.CartID
	case "submit_order":
		subject = req.SubmitOrder.CartID
	}

	return c.rules.IsAllowed(user, req.Command, subject), nil
}

func (c *CommandHandler) execute(ctx context.Context, resp *Response, req *Request) (err error) {
	user := ctx.Value(userKey).(authn.UserID).String()

	switch req.Command {
	case "create_cart":
		req.CreateCart.Owner = user
		resp.CreateCart, err = c.service.CreateCart(ctx, req.CreateCart)
	case "add_items":
		resp.AddItems, err = c.service.AddItems(ctx, req.AddItems)
	case "update_items":
		resp.UpdateItems, err = c.service.UpdateItems(ctx, req.UpdateItems)
	case "remove_items":
		resp.RemoveItems, err = c.service.RemoveItems(ctx, req.RemoveItems)
	case "add_coupon_code":
		resp.AddCouponCode, err = c.service.AddCouponCode(ctx, req.AddCouponCode)
	case "remove_coupon_code":
		resp.RemoveCouponCode, err = c.service.RemoveCouponCode(ctx, req.RemoveCouponCode)
	case "set_special_instructions":
		resp.SetSpecialInstructions, err = c.service.SetSpecialInstructions(ctx, req.SetSpecialInstructions)
	case "calculate_shipping":
		resp.CalculateShipping, err = c.service.CalculateShipping(ctx, req.CalculateShipping)
	case "calculate_sales_tax":
		resp.CalculateSalesTax, err = c.service.CalculateSalesTax(ctx, req.CalculateSalesTax)
	case "set_shipping_address":
		resp.SetShippingAddress, err = c.service.SetShippingAddress(ctx, req.SetShippingAddress)
	case "set_billing_address":
		resp.SetBillingAddress, err = c.service.SetBillingAddress(ctx, req.SetBillingAddress)
	case "set_payment_method":
		resp.SetPaymentMethod, err = c.service.SetPaymentMethod(ctx, req.SetPaymentMethod)
	case "submit_order":
		resp.SubmitOrder, err = c.service.SubmitOrder(ctx, req.SubmitOrder)
	}

	return
}

// Request command endpoint request body
type Request struct {
	Command   string `json:"command"`
	RequestID string `json:"request_id,omitempty"`

	CreateCart             *cart.CreateCartInput             `json:"create_cart,omitempty"`
	AddItems               *cart.AddItemsInput               `json:"add_items,omitempty"`
	UpdateItems            *cart.UpdateItemsInput            `json:"update_items,omitempty"`
	RemoveItems            *cart.RemoveItemsInput            `json:"remove_items,omitempty"`
	AddCouponCode          *cart.AddCouponCodeInput          `json:"add_coupon_code,omitempty"`
	RemoveCouponCode       *cart.RemoveCouponCodeInput       `json:"remove_coupon_code,omitempty"`
	SetSpecialInstructions *cart.SetSpecialInstructionsInput `json:"set_special_instructions,omitempty"`
	CalculateShipping      *cart.CalculateShippingInput      `json:"calculate_shipping,omitempty"`
	CalculateSalesTax      *cart.CalculateSalesTaxInput      `json:"calculate_sales_tax,omitempty"`
	SetShippingAddress     *cart.SetShippingAddressInput     `json:"set_shipping_address,omitempty"`
	SetBillingAddress      *cart.SetBillingAddressInput      `json:"set_billing_address,omitempty"`
	SetPaymentMethod       *cart.SetPaymentMethodInput       `json:"set_payment_method,omitempty"`
	SubmitOrder            *cart.SubmitOrderInput            `json:"submit_order,omitempty"`
}

// Response command endpoint response body
type Response struct {
	Command   string `json:"command"`
	RequestID string `json:"request_id,omitempty"`

	CreateCart             *cart.CreateCartOutput             `json:"create_cart,omitempty"`
	AddItems               *cart.AddItemsOutput               `json:"add_items,omitempty"`
	UpdateItems            *cart.UpdateItemsOutput            `json:"update_items,omitempty"`
	RemoveItems            *cart.RemoveItemsOutput            `json:"remove_items,omitempty"`
	AddCouponCode          *cart.AddCouponCodeOutput          `json:"add_coupon_code,omitempty"`
	RemoveCouponCode       *cart.RemoveCouponCodeOutput       `json:"remove_coupon_code,omitempty"`
	SetSpecialInstructions *cart.SetSpecialInstructionsOutput `json:"set_special_instructions,omitempty"`
	CalculateShipping      *cart.CalculateShippingOutput      `json:"calculate_shipping,omitempty"`
	CalculateSalesTax      *cart.CalculateSalesTaxOutput      `json:"calculate_sales_tax,omitempty"`
	SetShippingAddress     *cart.SetShippingAddressOutput     `json:"set_shipping_address,omitempty"`
	SetBillingAddress      *cart.SetBillingAddressOutput      `json:"set_billing_address,omitempty"`
	SetPaymentMethod       *cart.SetPaymentMethodOutput       `json:"set_payment_method,omitempty"`
	SubmitOrder            *cart.SubmitOrderOutput            `json:"submit_order,omitempty"`
}

type MockRepository struct {
	carts map[string]*cart.Cart
	sync.Mutex
}

func (m *MockRepository) init() {
	if m.carts != nil {
		return
	}

	m.carts = make(map[string]*cart.Cart)
}

func (m *MockRepository) GetCart(cartID string) (*cart.Cart, error) {
	m.Lock()
	defer m.Unlock()
	m.init()
	cart, ok := m.carts[cartID]
	if !ok {
		return nil, nil
	}

	return cart, nil
}

func (m *MockRepository) SaveCart(cart cart.Cart) error {
	m.Lock()
	defer m.Unlock()
	m.init()
	m.carts[cart.ID] = &cart
	return nil
}

type MockProductService struct{}

func (m *MockProductService) GetProduct(
	ctx context.Context,
	input *product.GetProductInput,
) (*product.GetProductOutput, error) {
	output, ok := products[input.ProductID]
	if !ok {
		return nil, errors.New("Product Not Found: " + input.ProductID)
	}

	return output, nil
}

var products = map[string]*product.GetProductOutput{
	"prod1": &product.GetProductOutput{
		Product: product.Product{
			ID:    "prod1",
			Name:  "Test Item",
			Price: 100,
		},
	},
}
