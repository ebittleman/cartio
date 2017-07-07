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

package cart

import (
	"errors"

	"github.com/ebittleman/cartio/events"
)

var (
	// ErrCartNotFound returned when a cart cannot be resolved
	ErrCartNotFound = errors.New("cart Not Found")
	// ErrInvalidParameters returned when a command cannot be executed due to
	// invalid or missing parameters.
	ErrInvalidParameters = errors.New("Invalid or Missing Parameters")
)

// Address describes the location of a building
type Address struct {
	Name        string
	Addr1       string
	Addr2       string
	AptSuite    string
	City        string
	PostalCode  string
	CountryCode string
}

// PayPal data that can be used to capture payment from PayPal
type PayPal struct{}

// Stripe data that can be used to capture payment from Stripe
type Stripe struct{}

// AccountBalance data that can be used to capture payment from a users account
// balance then capture the remainder of an orders balance via the selected
// payment gateway
type AccountBalance struct {
	RemainderWith string
	PayPal        PayPal
	Stripe        Stripe
}

// PaymentMethod method for capturing payment
type PaymentMethod struct {
	Type           string
	PayPal         PayPal
	Stripe         Stripe
	AccountBalance AccountBalance
}

// CartItem a line item in a cart
type CartItem struct {
	Qty       int
	ProductID string
	Name      string
	Price     int
}

// Cart domain model interface for interacting with a shopping cart
type Cart interface {
	ID() string
	Owner() string
	Calculate() Cart
	AddItem(item CartItem) Cart
	UpdateItem(item CartItem) Cart
	RemoveItem(item CartItem) Cart
}

type cart struct {
	id    string
	owner string

	ShipTo        Address
	BillTo        Address
	PaymentMethod PaymentMethod

	Items []CartItem

	PostalCode  string
	CountryCode string

	Instructions string

	SubTotal int
	SalesTax int
	Shipping int
	Total    int
}

// NewCart instantiates a new simple cart
func NewCart(id string, owner string) cart {
	return cart{
		id:    id,
		owner: owner,
	}
}

func (c cart) ID() string {
	return c.id
}

func (c cart) Owner() string {
	return c.owner
}

func (c cart) Calculate() Cart {
	var (
		subTotal int
		total    int
	)

	for _, cursor := range c.Items {
		subTotal += (cursor.Qty * cursor.Price)
	}

	total = subTotal + c.SalesTax + c.Shipping

	c.SubTotal = subTotal
	c.Total = total

	return c
}

func (c cart) AddItem(item CartItem) Cart {
	for i, cursor := range c.Items {
		if cursor.ProductID == item.ProductID {
			c.Items[i].Qty += item.Qty
			c.Items[i].Price = item.Price

			return c
		}
	}

	c.Items = append(c.Items, item)

	return c
}

func (c cart) UpdateItem(item CartItem) Cart {
	for i, cursor := range c.Items {
		if cursor.ProductID == item.ProductID {
			c.Items[i] = item

			return c
		}
	}

	c.Items = append(c.Items, item)

	return c
}

func (c cart) RemoveItem(item CartItem) Cart {
	for i, cursor := range c.Items {
		if cursor.ProductID == item.ProductID {
			c.Items = append(c.Items[:i], c.Items[i+1:]...)
			return c
		}
	}

	return c
}

type observableCart struct {
	cart
	*events.Evented
}

// NewObservableCart a shopping cart that implements the events.Subject
// interface which emits events after interacting with the cart
func NewObservableCart(id string, owner string) Cart {
	cart := observableCart{
		cart: cart{
			id:    id,
			owner: owner,
		},
		Evented: &events.Evented{},
	}

	cart.Emit(events.Event{
		Name:     "new-cart",
		EntityID: id,
		Payload: struct {
			ID    string
			Owner string
		}{
			ID:    id,
			Owner: owner,
		},
	})

	return cart
}

func (o observableCart) AddItem(item CartItem) Cart {
	o.cart = o.cart.AddItem(item).(cart)
	o.Emit(events.Event{
		Name:     "item-added",
		EntityID: o.ID(),
		Payload: struct {
			CartItem
		}{
			CartItem: item,
		},
	})

	return o
}

func (o observableCart) UpdateItem(item CartItem) Cart {
	o.cart = o.cart.UpdateItem(item).(cart)
	o.Emit(events.Event{
		Name:     "item-updated",
		EntityID: o.ID(),
		Payload: struct {
			CartItem
		}{
			CartItem: item,
		},
	})

	return o
}

func (o observableCart) RemoveItem(item CartItem) Cart {
	o.cart = o.cart.RemoveItem(item).(cart)
	o.Emit(events.Event{
		Name:     "item-removed",
		EntityID: o.ID(),
		Payload: struct {
			ProductID string
		}{
			ProductID: item.ProductID,
		},
	})

	return o
}

func (o observableCart) Calculate() Cart {
	o.cart = o.cart.Calculate().(cart)

	o.Emit(events.Event{
		Name:     "calculated",
		EntityID: o.ID(),
		Payload: struct {
			SubTotal int
			SalesTax int
			Shipping int
			Total    int
		}{
			SubTotal: o.SubTotal,
			SalesTax: o.SalesTax,
			Shipping: o.Shipping,
			Total:    o.Total,
		},
	})

	return o
}
