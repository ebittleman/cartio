// cartio - An e-commerce API.
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

package iface

import (
	"context"

	"github.com/ebittleman/cartio/domain/cart"
)

// CartService methods available for working with shopping carts
type CartService interface {
	GetCart(context.Context, *cart.GetCartInput) (*cart.GetCartOutput, error)

	CreateCart(context.Context, *cart.CreateCartInput) (*cart.CreateCartOutput, error)
	AddItems(context.Context, *cart.AddItemsInput) (*cart.AddItemsOutput, error)
	UpdateItems(context.Context, *cart.UpdateItemsInput) (*cart.UpdateItemsOutput, error)
	RemoveItems(context.Context, *cart.RemoveItemsInput) (*cart.RemoveItemsOutput, error)
	AddCouponCode(context.Context, *cart.AddCouponCodeInput) (*cart.AddCouponCodeOutput, error)
	RemoveCouponCode(context.Context, *cart.RemoveCouponCodeInput) (*cart.RemoveCouponCodeOutput, error)
	SetSpecialInstructions(context.Context, *cart.SetSpecialInstructionsInput) (*cart.SetSpecialInstructionsOutput, error)
	CalculateShipping(context.Context, *cart.CalculateShippingInput) (*cart.CalculateShippingOutput, error)
	CalculateSalesTax(context.Context, *cart.CalculateSalesTaxInput) (*cart.CalculateSalesTaxOutput, error)
	SetShippingAddress(context.Context, *cart.SetShippingAddressInput) (*cart.SetShippingAddressOutput, error)
	SetBillingAddress(context.Context, *cart.SetBillingAddressInput) (*cart.SetBillingAddressOutput, error)
	SetPaymentMethod(context.Context, *cart.SetPaymentMethodInput) (*cart.SetPaymentMethodOutput, error)
	SubmitOrder(context.Context, *cart.SubmitOrderInput) (*cart.SubmitOrderOutput, error)
}
