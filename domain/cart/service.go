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

package cart

import (
	"context"

	"github.com/ebittleman/cartio/domain/product"
	"github.com/ebittleman/cartio/domain/product/iface"
)

type contextKey string

const (
	// CartKey context key for current cart being operated on
	CartKey contextKey = "cart"
)

// Service implements CartService
type Service struct {
	productService iface.ProductService
	repo           Repository
}

// NewService instantiates a new local CartService
func NewService(
	productService iface.ProductService,
	repo Repository,
) *Service {
	return &Service{
		productService: productService,
		repo:           repo,
	}
}

func (c *Service) resolveCart(
	ctx context.Context,
	id string,
) (cart Cart, err error) {

	if subject, ok := ctx.Value(CartKey).(Cart); ok {
		cart = subject
	} else {
		cart, err = c.repo.GetCart(id)
	}

	return
}

// GetCartInput parameters for calling GetCart
type GetCartInput struct {
	ID string
}

// GetCartOutput response data from calling GetCart
type GetCartOutput struct {
	Cart Cart
}

// GetCart retreives a Cart from the repository
func (c *Service) GetCart(ctx context.Context, input *GetCartInput) (*GetCartOutput, error) {
	cart, err := c.repo.GetCart(input.ID)
	if err != nil {
		return nil, err
	}

	if cart == nil || cart.ID() == "" {
		return nil, ErrCartNotFound
	}

	return &GetCartOutput{Cart: cart}, nil
}

// CreateCartInput parameters for calling CreateCart
type CreateCartInput struct {
	Owner string `json:"owner"`
}

// CreateCartOutput response data from calling CreateCart
type CreateCartOutput struct {
	CartID string `json:"cart_id"`
}

// CreateCart creates a new Cart and adds it to the repository
func (c *Service) CreateCart(
	ctx context.Context,
	input *CreateCartInput,
) (output *CreateCartOutput, err error) {
	cart, err := c.repo.NewCart(input.Owner)
	if err != nil {
		return nil, err
	}

	if err = c.repo.SaveCart(ctx, cart); err != nil {
		return nil, err
	}

	output = new(CreateCartOutput)
	output.CartID = cart.ID()

	return
}

// AddItem item to be added to a cart
type AddItem struct {
	ProductID string `json:"product_id"`
	Qty       int    `json:"qty"`
}

// AddItemsInput parameters for calling AddItems
type AddItemsInput struct {
	CartID string    `json:"cart_id"`
	Items  []AddItem `json:"items"`
}

// AddItemsOutput response data from calling AddItems
type AddItemsOutput struct {
	CartID string `json:"cart_id"`
}

// AddItems adds a list of items to a cart
func (c *Service) AddItems(
	ctx context.Context,
	input *AddItemsInput,
) (output *AddItemsOutput, err error) {
	var cart Cart
	if cart, err = c.resolveCart(ctx, input.CartID); err != nil {
		return nil, err
	}

	for _, addItem := range input.Items {
		productOutput, err := c.productService.GetProduct(
			ctx,
			&product.GetProductInput{
				ProductID: addItem.ProductID,
			},
		)

		if err != nil {
			return nil, err
		}

		cart = cart.AddItem(CartItem{
			Qty:       addItem.Qty,
			ProductID: productOutput.Product.ID,
			Name:      productOutput.Product.Name,
			Price:     productOutput.Product.Price,
		})
	}

	cart = cart.Calculate()
	if err = c.repo.SaveCart(ctx, cart); err != nil {
		return
	}

	output = new(AddItemsOutput)
	output.CartID = cart.ID()

	return output, nil
}

// UpdateItem item to be set in the a cart
type UpdateItem struct {
	ProductID string `json:"product_id"`
	Qty       int    `json:"qty"`
}

// UpdateItemsInput parameters for calling UpdateItems
type UpdateItemsInput struct {
	CartID string       `json:"cart_id"`
	Items  []UpdateItem `json:"items"`
}

// UpdateItemsOutput response data from calling UpdateItems
type UpdateItemsOutput struct {
	CartID string `json:"cart_id"`
}

// UpdateItems updates and overrides cart items
func (c *Service) UpdateItems(
	ctx context.Context,
	input *UpdateItemsInput,
) (output *UpdateItemsOutput, err error) {
	var cart Cart
	if cart, err = c.resolveCart(ctx, input.CartID); err != nil {
		return nil, err
	}

	for _, updateItem := range input.Items {
		productOutput, err := c.productService.GetProduct(
			ctx,
			&product.GetProductInput{
				ProductID: updateItem.ProductID,
			},
		)

		if err != nil {
			return nil, err
		}

		cart = cart.UpdateItem(CartItem{
			Qty:       updateItem.Qty,
			ProductID: productOutput.Product.ID,
			Name:      productOutput.Product.Name,
			Price:     productOutput.Product.Price,
		})
	}

	cart = cart.Calculate()
	if err = c.repo.SaveCart(ctx, cart); err != nil {
		return
	}

	output = new(UpdateItemsOutput)
	output.CartID = cart.ID()

	return output, nil
}

// RemoveItem item to be removed from the a cart
type RemoveItem struct {
	ProductID string `json:"product_id"`
}

// RemoveItemsInput parameters for calling RemoveItems
type RemoveItemsInput struct {
	CartID string       `json:"cart_id"`
	Items  []RemoveItem `json:"items"`
}

// RemoveItemsOutput response data from calling RemoveItems
type RemoveItemsOutput struct {
	CartID string `json:"cart_id"`
}

// RemoveItems removes items from a shopping cart.
func (c *Service) RemoveItems(
	ctx context.Context,
	input *RemoveItemsInput,
) (output *RemoveItemsOutput, err error) {
	var cart Cart
	if cart, err = c.resolveCart(ctx, input.CartID); err != nil {
		return nil, err
	}

	for _, removeItem := range input.Items {
		productOutput, err := c.productService.GetProduct(
			ctx,
			&product.GetProductInput{
				ProductID: removeItem.ProductID,
			},
		)

		if err != nil {
			return nil, err
		}

		cart = cart.RemoveItem(CartItem{
			ProductID: productOutput.Product.ID,
		})
	}

	cart = cart.Calculate()
	if err = c.repo.SaveCart(ctx, cart); err != nil {
		return
	}

	output = new(RemoveItemsOutput)
	output.CartID = cart.ID()

	return output, nil
}

type AddCouponCodeInput struct {
	CartID string `json:"cart_id"`
	Code   string `json:"code"`
}

type AddCouponCodeOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) AddCouponCode(context.Context, *AddCouponCodeInput) (*AddCouponCodeOutput, error) {
	return nil, nil
}

type RemoveCouponCodeInput struct {
	CartID string `json:"cart_id"`
	Code   string `json:"code"`
}

type RemoveCouponCodeOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) RemoveCouponCode(context.Context, *RemoveCouponCodeInput) (*RemoveCouponCodeOutput, error) {
	return nil, nil
}

type SetSpecialInstructionsInput struct {
	CartID       string `json:"cart_id"`
	Instructions string `json:"instructions"`
}

type SetSpecialInstructionsOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) SetSpecialInstructions(context.Context, *SetSpecialInstructionsInput) (*SetSpecialInstructionsOutput, error) {
	return nil, nil
}

type CalculateShippingInput struct {
	CartID      string `json:"cart_id"`
	PostalCode  string `json:"postal_code"`
	CountryCode string `json:"country_code"`
}

type CalculateShippingOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) CalculateShipping(context.Context, *CalculateShippingInput) (*CalculateShippingOutput, error) {
	return nil, nil
}

type CalculateSalesTaxInput struct {
	CartID      string `json:"cart_id"`
	PostalCode  string `json:"postal_code"`
	CountryCode string `json:"country_code"`
}

type CalculateSalesTaxOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) CalculateSalesTax(context.Context, *CalculateSalesTaxInput) (*CalculateSalesTaxOutput, error) {
	return nil, nil
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

func (c *Service) SetShippingAddress(context.Context, *SetShippingAddressInput) (*SetShippingAddressOutput, error) {
	return nil, nil
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

func (c *Service) SetBillingAddress(context.Context, *SetBillingAddressInput) (*SetBillingAddressOutput, error) {
	return nil, nil
}

type PayPalInput struct{}
type StripeInput struct{}
type AccountBalanceInput struct {
	RemainderWith string `json:"remainder_with"`
	PayPal        PayPal `json:"paypal"`
	Stripe        Stripe `json:"stripe"`
}

type SetPaymentMethodInput struct {
	CartID         string              `json:"cart_id"`
	Type           string              `json:"type"`
	PayPal         PayPalInput         `json:"paypal"`
	Stripe         StripeInput         `json:"stripe"`
	AccountBalance AccountBalanceInput `json:"account_balance"`
}

type SetPaymentMethodOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) SetPaymentMethod(context.Context, *SetPaymentMethodInput) (*SetPaymentMethodOutput, error) {
	return nil, nil
}

type SubmitOrderInput struct {
	CartID       string `json:"cart_id"`
	AgreeToTerms bool   `json:"agree_to_terms"`
	Timestamp    int    `json:"timestamp"`
}

type SubmitOrderOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) SubmitOrder(context.Context, *SubmitOrderInput) (*SubmitOrderOutput, error) {
	return nil, nil
}
