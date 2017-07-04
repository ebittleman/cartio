package cart

type Address struct {
	Name        string
	Addr1       string
	Addr2       string
	AptSuite    string
	City        string
	PostalCode  string
	CountryCode string
}

type PayPal struct{}
type Stripe struct{}
type AccountBalance struct {
	RemainderWith string
	PayPal        PayPal
	Stripe        Stripe
}

type PaymentMethod struct {
	Type           string
	PayPal         PayPal
	Stripe         Stripe
	AccountBalance AccountBalance
}

type CartItem struct {
	Qty       int
	ProductID string
	Name      string
	Price     int
}

type Cart struct {
	ID    string
	Owner string

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

func (c Cart) Calculate() Cart {
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

func (c Cart) AddItem(item CartItem) Cart {
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

func (c Cart) UpdateItem(item CartItem) Cart {
	for i, cursor := range c.Items {
		if cursor.ProductID == item.ProductID {
			c.Items[i] = item

			return c
		}
	}

	c.Items = append(c.Items, item)

	return c
}

func (c Cart) RemoveItem(item CartItem) Cart {
	for i, cursor := range c.Items {
		if cursor.ProductID == item.ProductID {
			c.Items = append(c.Items[:i], c.Items[i+1:]...)
			return c
		}
	}

	return c
}
