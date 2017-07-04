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
	"errors"

	"github.com/ebittleman/cartio/domain/product"
	"github.com/ebittleman/cartio/domain/product/iface"
	"github.com/pborman/uuid"
)

type Service struct {
	productService iface.ProductService
	repo           Repository
}

func NewService(
	productService iface.ProductService,
	repo Repository,
) *Service {
	return &Service{
		productService: productService,
		repo:           repo,
	}
}

type CreateCartInput struct {
	Owner string `json:"owner"`
}

type CreateCartOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) CreateCart(
	ctx context.Context,
	input *CreateCartInput,
) (output *CreateCartOutput, err error) {
	var cart Cart
	cart.Owner = input.Owner

	for {
		cart.ID = uuid.New()

		exists, err := c.repo.GetCart(cart.ID)
		if err != nil {
			return nil, err
		}

		if exists == nil {
			break
		}
	}

	if err = c.repo.SaveCart(cart); err != nil {
		return
	}

	output = new(CreateCartOutput)
	output.CartID = cart.ID

	return
}

type AddItem struct {
	ProductID string `json:"product_id"`
	Qty       int    `json:"qty"`
}

type AddItemsInput struct {
	CartID string    `json:"cart_id"`
	Items  []AddItem `json:"items"`
}

type AddItemsOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) AddItems(
	ctx context.Context,
	input *AddItemsInput,
) (output *AddItemsOutput, err error) {
	var foundCart *Cart

	foundCart, err = c.repo.GetCart(input.CartID)
	if err != nil {
		return
	}

	if foundCart == nil {
		return nil, errors.New("Cart Not Found: " + input.CartID)
	}

	cart := *foundCart
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

	if err = c.repo.SaveCart(cart); err != nil {
		return
	}

	output = new(AddItemsOutput)
	output.CartID = cart.ID

	return output, nil
}

type UpdateItem struct {
	ProductID string `json:"product_id"`
	Qty       int    `json:"qty"`
}

type UpdateItemsInput struct {
	CartID string       `json:"cart_id"`
	Items  []UpdateItem `json:"items"`
}

type UpdateItemsOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) UpdateItems(context.Context, *UpdateItemsInput) (*UpdateItemsOutput, error) {
	return nil, nil
}

type RemoveItem struct {
	ProductID string `json:"product_id"`
}

type RemoveItemsInput struct {
	CartID string       `json:"cart_id"`
	Items  []RemoveItem `json:"items"`
}

type RemoveItemsOutput struct {
	CartID string `json:"cart_id"`
}

func (c *Service) RemoveItems(context.Context, *RemoveItemsInput) (*RemoveItemsOutput, error) {
	return nil, nil
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
