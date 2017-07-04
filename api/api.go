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

// NewCommandHandler creates a new http handler to serve cart api requests
func NewCommandHandler(rules authz.Rules) http.Handler {
	service := cart.NewService(&MockProductService{}, &MockRepository{})
	return &CommandHandler{
		service: service,
		rules:   rules,
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

	subject, err := c.resolveSubject(ctx, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if subject != nil {
		ctx = context.WithValue(r.Context(), cart.CartKey, subject)
	}

	if ok, err := c.isAllowed(ctx, req.Command); err != nil {
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

func (c *CommandHandler) resolveSubject(
	ctx context.Context,
	req *Request,
) (subject authz.Subject, err error) {
	var subjectID string

	switch req.Command {
	case "create_cart":
	case "add_items":
		subjectID = req.AddItems.CartID
	case "update_items":
		subjectID = req.UpdateItems.CartID
	case "remove_items":
		subjectID = req.RemoveItems.CartID
	case "add_coupon_code":
		subjectID = req.AddCouponCode.CartID
	case "remove_coupon_code":
		subjectID = req.RemoveCouponCode.CartID
	case "set_special_instructions":
		subjectID = req.SetSpecialInstructions.CartID
	case "calculate_shipping":
		subjectID = req.CalculateShipping.CartID
	case "calculate_sales_tax":
		subjectID = req.CalculateSalesTax.CartID
	case "set_shipping_address":
		subjectID = req.SetShippingAddress.CartID
	case "set_billing_address":
		subjectID = req.SetBillingAddress.CartID
	case "set_payment_method":
		subjectID = req.SetPaymentMethod.CartID
	case "submit_order":
		subjectID = req.SubmitOrder.CartID
	}

	if subjectID == "" {
		return
	}

	output, err := c.service.GetCart(ctx, &cart.GetCartInput{
		ID: subjectID,
	})

	if err != nil {
		return nil, err
	}

	return *output.Cart, nil

}

func (c *CommandHandler) isAllowed(
	ctx context.Context,
	action string,
) (bool, error) {
	var subject authz.Subject
	user := ctx.Value(userKey).(authn.UserID).String()
	if cart, ok := ctx.Value(cart.CartKey).(authz.Subject); ok {
		subject = cart
	}

	return c.rules.IsAllowed(user, action, subject), nil
}

func (c *CommandHandler) execute(
	ctx context.Context,
	resp *Response,
	req *Request,
) (err error) {
	user := ctx.Value(userKey).(authn.UserID).String()

	switch req.Command {
	case "create_cart":
		input := &cart.CreateCartInput{Owner: user}
		resp.CreateCart, err = c.service.CreateCart(ctx, input)
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

	// CreateCart             *cart.CreateCartInput             `json:"create_cart,omitempty"`
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

//
// ================================================
//
//		MOCK AREA BELOW, Just Some Placeholders
//      to get this thing running.
//
// ================================================
//

var carts = map[string]*cart.Cart{}

// MockRepository fake cart repository
type MockRepository struct {
	sync.RWMutex
}

// GetCart gets cart from global fixture
func (m *MockRepository) GetCart(cartID string) (*cart.Cart, error) {
	m.RLock()
	defer m.RUnlock()
	cart, ok := carts[cartID]
	if !ok {
		return nil, nil
	}

	return cart, nil
}

// SaveCart saves cart to global fixture
func (m *MockRepository) SaveCart(cart cart.Cart) error {
	m.Lock()
	defer m.Unlock()
	carts[cart.ID()] = &cart
	return nil
}

// MockProductService fake product service
type MockProductService struct{}

// GetProduct returns fake product
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
