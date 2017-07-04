package iface

import (
	"context"

	"github.com/ebittleman/cartio/domain/cart"
)

// CartService methods available for working with shopping carts
type CartService interface {
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
