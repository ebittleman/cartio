package cart

type Repository interface {
	GetCart(cartID string) (*Cart, error)
	SaveCart(cart Cart) error
}
